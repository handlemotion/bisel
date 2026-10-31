import Foundation

/// Where `AccountLinker` talks to the server. The live one is `SyncClient`; flow tests wrap it to drop requests or lie.
public protocol LinkTransport: Sendable {
    func start(server: URL, deviceName: String) async throws -> SyncClient.ConnectCode
    func poll(server: URL, deviceCode: String) async throws -> SyncClient.ConnectStatus
}

struct LiveLinkTransport: LinkTransport {
    func start(server: URL, deviceName: String) async throws -> SyncClient.ConnectCode {
        try await Vault.startConnect(server: server, deviceName: deviceName)
    }
    func poll(server: URL, deviceCode: String) async throws -> SyncClient.ConnectStatus {
        try await Vault.pollConnect(server: server, deviceCode: deviceCode)
    }
}

/// The browser sign-in flow that ties this Mac's box to a bisel account, as one state machine (see LINKING.md).
///
/// It covers three starting points, picked from the vault itself:
/// - `.newBox`: no vault on this Mac yet. The account approves, then this Mac creates the vault and its box through the account.
/// - `.linkLocalBox`: a local-only vault. The account approves, then the box is created on the server from the existing vault
///   and every local item is uploaded.
/// - `.claimServerBox`: a vault that already syncs with a box nobody owns (made with a token, or from before accounts). The
///   account approves and takes ownership of that box.
///
/// The UI only observes `state` / `updates()` and calls `start`, `cancel`, `retry`. Nothing secret is in a state except the
/// recovery phrase of a new box in `.linked`, which the UI must show once. The secret device code never leaves this actor,
/// is never logged and is dropped the moment it is spent.
public actor AccountLinker {
    /// The Bisel server (the app's `BiselEnvironment.defaultServer`). Opt-in: first run never links (`BoxSetup`, SETUP.md).
    public static let defaultServer = URL(string: "https://box.bisel.app")!

    public enum Mode: Sendable, Equatable { case newBox, linkLocalBox, claimServerBox }

    /// What to show while waiting for the person in the browser.
    public struct Pending: Sendable, Equatable {
        public let mode: Mode
        /// "ABCD-EFGH": show it, the page shows the same one ("does it match?").
        public let userCode: String
        /// `https://box.bisel.app/connect?code=ABCD-EFGH`: open this in the browser. Built here from the fixed server address,
        /// never taken from the server's answer.
        public let url: URL
        /// After this the code stops working (a countdown can be drawn from it).
        public let expiresAt: Date
        /// The last poll could not reach the server. Polling continues with back-off; clears itself when the server answers.
        public var isOffline: Bool
    }

    public struct Linked: Sendable, Equatable {
        public let mode: Mode
        public let boxID: String?
        /// Only for `.newBox`: the only copy. Show it once and make the person confirm it (`Vault.confirmRecovery`).
        public let recoveryPhrase: RecoveryPhrase?
        /// Local items that went up to the new box (`.linkLocalBox`).
        public let itemsUploaded: Int
        /// Local items the first sync could not upload (network went away). Normal syncing carries on with them.
        public let itemsStillPending: Int
    }

    public enum Failure: Error, Sendable, Equatable {
        /// The person pressed cancel on the page, or (for a claim) the account already owns another box. Nothing changed.
        case denied
        /// The server says the code ran out (10 minutes) or does not know it.
        case expired
        /// Nothing happened before this app's own deadline.
        case timedOut
        /// The account that approved already owns a box: a second Mac joins it by enrolment or the recovery phrase.
        case accountHasBox
        /// A claim, but the box already belongs to an account.
        case alreadyLinked
        /// The server no longer accepts the approved code (already used, or lapsed while registering).
        case codeRejected
        /// Touch ID was cancelled or failed. The approval is kept: `retry()` asks again.
        case biometryRefused
        /// A fingerprint changed and the device key is gone: enrol this Mac again.
        case biometryChanged
        /// The server could not be reached, or kept failing. `retry()` resumes with the same code while it is valid.
        case network
        case server(status: Int?)
        /// The server named a different box than this vault's. Nothing was written.
        case boxMismatch
        /// The vault cannot do this (for example a locked vault whose unlock failed, or an unusable local store).
        case vaultUnavailable

        /// `retry()` can continue without asking the person to start over.
        public var isRetryable: Bool { self == .biometryRefused || self == .network || isServer }
        private var isServer: Bool { if case .server = self { return true } else { return false } }
    }

    public enum State: Sendable, Equatable {
        case idle
        case requestingCode
        case waitingForApproval(Pending)
        /// Approved. Touch ID, then this Mac's device key is registered with the server. Not cancellable.
        case registering(Mode)
        /// Registered; local items are going up (`pending` of them when it began).
        case uploading(pending: Int)
        case linked(Linked)
        case failed(Failure)
        case cancelled

        public var isFinished: Bool {
            switch self {
            case .linked, .failed, .cancelled: return true
            default: return false
            }
        }
    }

    /// Pacing. The defaults are what the app uses; tests shorten them through the debug initialiser.
    public struct Timing: Sendable {
        /// Replaces the server's poll interval (tests only). Otherwise the server's, clamped to 1...10 seconds.
        public var intervalOverride: TimeInterval?
        public var maxBackoff: TimeInterval = 30
        /// Failed polls in a row before the wait gives up with `.network`.
        public var maxConsecutiveFailures = 6
        /// Seconds after which the wait ends with `.timedOut` whatever the server says. Default: the code's lifetime plus 5 s.
        public var hardTimeout: TimeInterval?
        public var sleep: @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) }
        public var now: @Sendable () -> Date = { Date() }
        public init() {}
    }

    private let vault: Vault
    private let server: URL
    private let transport: any LinkTransport
    private let timing: Timing

    public private(set) var state: State = .idle
    private var continuations: [UUID: AsyncStream<State>.Continuation] = [:]

    private struct Session {
        let mode: Mode
        let server: URL
        let deviceName: String
        let code: SyncClient.ConnectCode
        let interval: TimeInterval
        let expiresAt: Date
        let deadline: Date
        var approved: Bool
    }
    private var session: Session?
    private var deviceName = ""
    private var generation = 0
    private var task: Task<Void, Never>?

    public init(vault: Vault) {
        self.vault = vault
        server = Self.defaultServer
        transport = LiveLinkTransport()
        timing = Timing()
    }

    #if DEBUG || BISEL_SOFTWARE_KEYS
    /// Tests and debug runs only: another server, a faulty transport, fast timers. Not compiled into Release.
    public init(vault: Vault, server: URL, transport: (any LinkTransport)? = nil, timing: Timing = Timing()) {
        self.vault = vault
        self.server = server
        self.transport = transport ?? LiveLinkTransport()
        self.timing = timing
    }
    #endif

    // MARK: observing

    /// The current state first, then every change. Safe to call from several places.
    public func updates() -> AsyncStream<State> {
        let id = UUID()
        let (stream, continuation) = AsyncStream.makeStream(of: State.self)
        continuation.yield(state)
        continuations[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.removeObserver(id) } }
        return stream
    }

    private func removeObserver(_ id: UUID) { continuations[id] = nil }

    private func set(_ new: State) {
        guard new != state else { return }
        state = new
        for c in continuations.values { c.yield(new) }
    }

    /// Waits until the flow reaches `.linked`, `.failed` or `.cancelled` and returns that state.
    public func finished() async -> State {
        for await s in updates() where s.isFinished { return s }
        return state
    }

    // MARK: operations

    /// Begins the flow from `idle`, `failed` or `cancelled`. Ignored while a flow is running or after `linked`
    /// (use `reset()` to forget a finished flow).
    public func start(deviceName: String) {
        switch state {
        case .idle, .cancelled, .failed: break
        default: return
        }
        self.deviceName = deviceName
        begin()
    }

    /// Stops waiting. The code stays on the server until it times out, but nothing can redeem it without this Mac.
    /// Not possible once the approval is being redeemed (`registering`, `uploading`) or after `linked`.
    @discardableResult
    public func cancel() -> Bool {
        switch state {
        case .requestingCode, .waitingForApproval, .failed: break
        default: return false
        }
        generation += 1
        task?.cancel()
        session = nil
        set(.cancelled)
        return true
    }

    /// After `.failed(f)` with `f.isRetryable`: resumes polling the same code, or asks Touch ID again for an approved one.
    /// Any other failure starts a new request, as `start` would.
    public func retry() {
        guard case .failed(let failure) = state else { return }
        if failure.isRetryable, let session, session.deadline > timing.now() {
            generation += 1
            let g = generation
            task = Task { [session] in
                if session.approved { await self.register(session, g) } else { await self.poll(session, g) }
            }
            set(session.approved ? .registering(session.mode) : .waitingForApproval(pending(session, offline: false)))
        } else {
            session = nil
            begin()
        }
    }

    /// Back to `idle` after a finished flow (a `.linked` flow cannot be run again: the vault is linked).
    public func reset() {
        guard state.isFinished else { return }
        session = nil
        set(.idle)
    }

    private func begin() {
        generation += 1
        let g = generation
        session = nil
        set(.requestingCode)
        task = Task { await self.requestCode(g) }
    }

    private func current(_ g: Int) -> Bool { g == generation && !Task.isCancelled }

    // MARK: 1 - ask for a code

    private func requestCode(_ g: Int) async {
        let identity: LocalIdentity?
        do { identity = try await vault.identity() } catch { return fail(.vaultUnavailable, g) }
        let mode: Mode = identity == nil ? .newBox : (identity?.serverURL == nil ? .linkLocalBox : .claimServerBox)
        let server = identity?.serverURL ?? self.server
        let name = identity?.deviceName ?? deviceName
        do {
            // The vault key is needed to register (local box) or to sign the claim, and a locked vault would fail late: unlock
            // now, so a refused Touch ID ends things before a code exists.
            if mode != .newBox, !(await vault.isUnlocked) { try await vault.unlock(reason: "Link this box to your account") }
            guard current(g) else { return }
            let code: SyncClient.ConnectCode
            if mode == .claimServerBox { code = try await vault.claimBox() }
            else { code = try await transport.start(server: server, deviceName: name) }
            guard current(g) else { return }
            guard Self.isUserCode(code.userCode), Self.verificationURL(server: server, userCode: code.userCode) != nil else {
                return fail(.server(status: nil), g)
            }
            let now = timing.now()
            let lifetime = min(TimeInterval(max(code.expiresIn, 1)), 900)
            let interval = timing.intervalOverride ?? min(max(TimeInterval(code.interval), 1), 10)
            let s = Session(mode: mode, server: server, deviceName: name, code: code, interval: interval, expiresAt: now.addingTimeInterval(lifetime),
                            deadline: now.addingTimeInterval(timing.hardTimeout ?? lifetime + 5), approved: false)
            session = s
            set(.waitingForApproval(pending(s, offline: false)))
            await poll(s, g)
        } catch {
            fail(Self.failure(for: error), g)
        }
    }

    private func pending(_ s: Session, offline: Bool) -> Pending {
        Pending(mode: s.mode, userCode: s.code.userCode, url: Self.verificationURL(server: s.server, userCode: s.code.userCode)!,
                expiresAt: s.expiresAt, isOffline: offline)
    }

    // MARK: 2 - wait for the person

    private func poll(_ s: Session, _ g: Int) async {
        var failures = 0
        var lastError: Failure = .network
        while current(g) {
            if timing.now() >= s.deadline { return fail(.timedOut, g, keepSession: false) }
            let delay = failures == 0 ? s.interval : min(timing.maxBackoff, s.interval * pow(2, Double(failures)))
            do { try await timing.sleep(delay) } catch { return }
            guard current(g) else { return }
            let status: SyncClient.ConnectStatus
            do {
                status = try await transport.poll(server: s.server, deviceCode: s.code.deviceCode)
                guard current(g) else { return }
                if failures > 0 { failures = 0; set(.waitingForApproval(pending(s, offline: false))) }
            } catch {
                guard current(g) else { return }
                failures += 1
                lastError = Self.failure(for: error)
                if lastError != .network, !lastError.isRetryable { return fail(lastError, g) }
                if failures >= timing.maxConsecutiveFailures { return fail(lastError, g) }
                set(.waitingForApproval(pending(s, offline: true)))
                continue
            }
            switch status {
            case .pending: continue
            case .denied: return fail(.denied, g, keepSession: false)
            case .expired: return fail(.expired, g, keepSession: false)
            case .approved(let accountHasBox):
                if s.mode == .claimServerBox { continue }   // a claim is settled by the page itself: wait for consumed
                if accountHasBox { return fail(.accountHasBox, g, keepSession: false) }
                var approved = s
                approved.approved = true
                session = approved
                return await register(approved, g)
            case .consumed(let boxID):
                if s.mode == .claimServerBox { return await finishClaim(s, reportedBox: boxID, g) }
                return fail(.codeRejected, g, keepSession: false)   // someone else redeemed it
            }
        }
    }

    // MARK: 3 - register this Mac

    private func register(_ s: Session, _ g: Int) async {
        guard current(g) else { return }
        set(.registering(s.mode))
        var phrase: RecoveryPhrase?
        var pendingBefore = 0
        do {
            switch s.mode {
            case .newBox:
                phrase = try await vault.bootstrap(server: s.server, credential: .connect(deviceCode: s.code.deviceCode), deviceName: s.deviceName)
            case .linkLocalBox:
                if !(await vault.isUnlocked) { try await vault.unlock(reason: "Link this box to your account") }   // the window lapsed while waiting
                pendingBefore = (try? await vault.pendingChanges()) ?? 0
                try await vault.connectServer(s.server, credential: .connect(deviceCode: s.code.deviceCode))
            case .claimServerBox:
                return
            }
        } catch {
            let f = Self.failure(for: error)
            return fail(f, g, keepSession: f.isRetryable)
        }
        // From here the code is spent: the device key is registered and the box exists.
        session = nil
        let boxID = (try? await vault.identity())?.boxID
        var uploaded = 0, remaining = 0
        if s.mode == .linkLocalBox {
            set(.uploading(pending: pendingBefore))
            _ = try? await vault.sync()
            remaining = (try? await vault.pendingChanges()) ?? 0
            uploaded = max(0, pendingBefore - remaining)
        } else {
            _ = try? await vault.sync()
        }
        set(.linked(Linked(mode: s.mode, boxID: boxID, recoveryPhrase: phrase, itemsUploaded: uploaded, itemsStillPending: remaining)))
    }

    private func finishClaim(_ s: Session, reportedBox: String?, _ g: Int) async {
        let known = (try? await vault.identity())?.boxID
        if let reportedBox, let known, reportedBox != known { return fail(.boxMismatch, g, keepSession: false) }
        if known == nil, reportedBox != nil { _ = try? await vault.pollClaim(s.code) }   // records the box id
        session = nil
        let boxID = (try? await vault.identity())?.boxID
        set(.linked(Linked(mode: .claimServerBox, boxID: boxID, recoveryPhrase: nil, itemsUploaded: 0, itemsStillPending: 0)))
    }

    // MARK: helpers

    private func fail(_ f: Failure, _ g: Int, keepSession: Bool = true) {
        guard g == generation else { return }
        if !keepSession || !f.isRetryable { session = nil }
        set(.failed(f))
    }

    static func failure(for error: Error) -> Failure {
        switch error {
        case let e as Failure: return e
        case ConnectError.accountHasBox: return .accountHasBox
        case ConnectError.alreadyLinked: return .alreadyLinked
        case ConnectError.denied: return .denied
        case ConnectError.expired: return .expired
        case SyncError.notAuthorized: return .codeRejected
        case SyncError.network: return .network
        case SyncError.server(let status, _): return .server(status: status)
        case SyncError.malformedResponse, SyncError.tooLarge, SyncError.exists, SyncError.notFound, SyncError.conflict: return .server(status: nil)
        case KeyStoreError.userCancelled: return .biometryRefused
        case DeviceKeyError.biometryChanged: return .biometryChanged
        default: return .vaultUnavailable
        }
    }

    /// "ABCD-EFGH": what the server issues, nothing else gets into a URL.
    static func isUserCode(_ s: String) -> Bool {
        let parts = s.split(separator: "-", omittingEmptySubsequences: false)
        return parts.count == 2 && parts.allSatisfy { $0.count == 4 && $0.allSatisfy { $0.isASCII && ($0.isUppercase || $0.isNumber) } }
    }

    /// `<server>/connect?code=<user code>`. The address is ours; the server only supplies the code.
    static func verificationURL(server: URL, userCode: String) -> URL? {
        guard var c = URLComponents(url: server, resolvingAgainstBaseURL: false) else { return nil }
        c.path = "/connect"
        c.queryItems = [URLQueryItem(name: "code", value: userCode)]
        c.fragment = nil
        return c.url
    }
}
