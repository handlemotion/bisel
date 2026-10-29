import AppKit
import Observation
import BiselCore

/// Non-secret view of an item: what the list, the search index and the panel need. Passwords, notes and TOTP
/// secrets are never held here; they are decrypted on demand through the `Vault` actor.
struct ItemRow: Identifiable, Hashable, Sendable {
    let id: String
    let type: ItemType
    let title: String
    let urls: [String]
    let username: String
    let tags: [String]
    let updatedAt: Date
    let hasPassword: Bool
    let hasTOTP: Bool
    let totpPeriod: Int

    init(_ item: Item) {
        id = item.id; type = item.type; title = item.title; urls = item.urls; username = item.username ?? ""
        tags = item.tags; updatedAt = item.updatedAt; hasPassword = !(item.password ?? "").isEmpty; hasTOTP = item.totp != nil; totpPeriod = item.totp?.period ?? 30
    }

    var domain: String { SearchRecord.domain(of: urls.first) }
}

enum SyncState: Equatable {
    case idle
    case syncing
    case synced(Date)
    case offline(String)
    case failed(String)
}

/// Everything between the UI and BiselCore's `Vault` actor: lifecycle (set up / locked / unlocked), the in-memory
/// search index, sync, auto-lock. The command panel talks to it through `VaultSearchSource` / `VaultSecretProvider`.
@MainActor
@Observable
final class VaultService: VaultSearchSource, VaultSecretProvider {
    enum Phase: Equatable { case needsSetup, locked, unlocked }

    // MARK: observable state
    private(set) var phase: Phase = .needsSetup
    private(set) var rows: [ItemRow] = []
    private(set) var syncState: SyncState = .idle
    private(set) var pendingChanges = 0
    private(set) var lastConflicts = 0
    private(set) var undecryptable = 0
    private(set) var startupError: String?
    private(set) var deviceName = ""
    private(set) var serverURL: URL?
    private(set) var deviceID = ""
    /// Recovery phrase shown right after set-up, until the user confirms "I have stored it".
    private(set) var pendingPhrase: RecoveryPhrase?
    /// True from creating a brand-new box until its phrase is confirmed: the only time "Back" may throw the box away.
    private(set) var freshBox = false
    private(set) var unlockedAt: Date?
    var isBusy = false

    // MARK: VaultSearchSource
    var isUnlocked: Bool { phase == .unlocked }
    var provenanceLabel: String? { BiselEnvironment.usesSoftwareKeys ? "SOFTWARE KEYS" : nil }

    // MARK: wiring
    @ObservationIgnored private(set) var vault: Vault?
    @ObservationIgnored private let directory = BiselEnvironment.dataDirectory
    @ObservationIgnored private let usage: UsageStore
    @ObservationIgnored private let index = FuzzySearchIndex()
    @ObservationIgnored private var rowsByID: [String: ItemRow] = [:]
    @ObservationIgnored private var pollTimer: Timer?
    @ObservationIgnored private var syncing = false
    @ObservationIgnored private var syncChain: Task<Void, Never>?
    @ObservationIgnored private var otpGatedAt: [String: ContinuousClock.Instant] = [:]
    @ObservationIgnored private var lockMonitor: LockMonitor?
    /// Called on lock/unlock so the panel can redraw.
    @ObservationIgnored var onLockStateChange: (() -> Void)?

    static let fillWindowKey = "security.fillWindowMinutes"
    static let idleLockKey = "security.idleLockMinutes"
    static var fillWindowMinutes: Int { UserDefaults.standard.object(forKey: fillWindowKey) as? Int ?? 5 }
    static var idleLockMinutes: Int { UserDefaults.standard.object(forKey: idleLockKey) as? Int ?? 5 }

    init() {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        usage = UsageStore(directory: directory)
        do {
            let keyStore = BiselEnvironment.makeKeyStore(directory: directory)
            // The core's own window is a backstop (30 min); the app enforces the user's fill window and idle timeout.
            vault = try Vault(.init(location: StoreLocation(directory: directory), keyStore: keyStore, gate: AppGate(),
                                    fillWindow: 30 * 60, deviceKind: "mac"))
        } catch {
            startupError = "Could not open the local box store: \(error.localizedDescription)"
            Log.app.error("vault init failed: \(error.localizedDescription)")
        }
    }

    func start() async {
        lockMonitor = LockMonitor(service: self)
        lockMonitor?.start()
        await refreshPhase()
    }

    // MARK: phase

    func refreshPhase() async {
        guard let vault else { return }
        if let id = try? await vault.identity() {
            deviceName = id.deviceName; serverURL = id.serverURL; deviceID = id.deviceID
        }
        let configured = await vault.isConfigured
        let unlocked = await vault.isUnlocked
        pendingChanges = (try? await vault.pendingChanges()) ?? 0
        let new: Phase = !configured ? .needsSetup : (unlocked ? .unlocked : .locked)
        setPhase(new)
        if new == .unlocked { await reload() }
    }

    private func setPhase(_ new: Phase) {
        guard new != phase else { return }
        let was = phase
        phase = new
        if new == .unlocked {
            unlockedAt = Date()
            startPolling()
        } else {
            unlockedAt = nil
            stopPolling()
            if was == .unlocked { dropDecryptedState() }
        }
        Log.app.notice("vault phase \(String(describing: was), privacy: .public) -> \(String(describing: new), privacy: .public)")
        onLockStateChange?()
    }

    // MARK: unlock / lock

    /// Touch ID, then VK is held for the fill window. With software keys (Debug) the Secure Enclave prompt that would
    /// normally come from opening the device envelope doesn't exist, so the same biometric gate runs first.
    func unlock(reason: String = "Unlock your box") async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        if BiselEnvironment.usesSoftwareKeys { try await AppGate().authenticate(reason: reason) }
        do { try await vault.unlock(reason: reason) }
        catch let e as KeyStoreError where e == .userCancelled { throw e }
        setPhase(.unlocked)
        await reload()
        Task { await sync(reason: "unlock") }
        await resumeUnconfirmedRecovery()
    }

    /// Zeroes VK (inside the core) and drops every decrypted/derived thing the app holds.
    func lock(reason: String) {
        guard phase == .unlocked else { return }
        Log.app.notice("locking: \(reason)")
        setPhase(.locked)
        Task { await vault?.lock() }
        // Lock the core synchronously enough: a second call below is idempotent.
    }

    private func dropDecryptedState() {
        rows = []; rowsByID = [:]; otpGatedAt = [:]
        index.replace([])
        undecryptable = 0
        // pendingPhrase is deliberately kept: losing the only copy of a just-created phrase to an idle lock would be worse.
    }

    // MARK: set-up flows (all leave the vault unlocked on this Mac)

    func bootstrap(server: URL, token: String, deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let phrase = try await vault.bootstrap(server: server, bootstrapToken: token, deviceName: deviceName)
        setRecoveryUnconfirmed(true)   // the server now holds an envelope for a phrase nobody has confirmed storing yet
        pendingPhrase = phrase
        await refreshPhase()
        setPhase(.unlocked)
    }

    /// New vault that lives on this Mac only. A server can be connected later (Settings → Vault).
    func bootstrapLocal(deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let phrase = try await vault.bootstrapLocal(deviceName: deviceName)
        setRecoveryUnconfirmed(true)
        pendingPhrase = phrase
        freshBox = true
        await refreshPhase()
        setPhase(.unlocked)
    }

    /// Back from the recovery phrase of a box that was created a moment ago and holds nothing: erase it and start over.
    func discardNewBox() async {
        guard freshBox, pendingPhrase != nil, let vault else { return }
        isBusy = true; defer { isBusy = false }
        do { try await vault.removeLocalDevice() } catch { Log.app.error("discarding the new box failed") }
        setRecoveryUnconfirmed(false)
        pendingPhrase = nil
        freshBox = false
        await refreshPhase()
    }

    /// Registers this Mac's vault with a fresh server, then uploads everything made while it was local.
    func connectServer(server: URL, token: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        try await vault.connectServer(server, bootstrapToken: token)
        await refreshPhase()
        await sync(reason: "connect")
    }

    /// No server yet: nothing to sync, nothing to show as "synced".
    var isLocalOnly: Bool { phase != .needsSetup && serverURL == nil }

    func confirmPhraseStored() {
        freshBox = false
        pendingPhrase = nil
        setRecoveryUnconfirmed(false)
        Task { await sync(reason: "setup") }
    }

    func recover(server: URL, phrase: String, deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        try await vault.recover(server: server, phrase: try RecoveryPhrase(phrase), deviceName: deviceName)
        await refreshPhase()
        setPhase(.unlocked)
        await sync(reason: "recover")
        await reload()
    }

    func importBackup(from url: URL, phrase: String, server: URL, token: String, deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        try await vault.importBackup(from: url, phrase: try RecoveryPhrase(phrase), server: server, bootstrapToken: token,
                                     deviceName: deviceName)
        await refreshPhase()
        setPhase(.unlocked)
        await reload()
    }

    func exportBackup(to url: URL) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.exportBackup(to: url)
    }

    func rotateRecovery() async throws -> RecoveryPhrase {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        let phrase = try await vault.rotateRecovery()
        setRecoveryUnconfirmed(true)   // cleared by `confirmPhraseStored()` once the user re-enters words from it
        return phrase
    }

    // MARK: unconfirmed recovery phrase (security review M5)

    /// A marker file (no secret inside) that survives a quit or crash between "phrase generated" and "I have stored it".
    private var unconfirmedMarker: URL { directory.appendingPathComponent("recovery-unconfirmed") }
    var recoveryUnconfirmed: Bool { FileManager.default.fileExists(atPath: unconfirmedMarker.path) }

    private func setRecoveryUnconfirmed(_ on: Bool) {
        if on { FileManager.default.createFile(atPath: unconfirmedMarker.path, contents: Data()) }
        else { try? FileManager.default.removeItem(at: unconfirmedMarker) }
    }

    /// The phrase from last time was never confirmed and can't be shown again: make a new one (Touch ID) and show it.
    private func resumeUnconfirmedRecovery() async {
        guard phase == .unlocked, pendingPhrase == nil, recoveryUnconfirmed else { return }
        do {
            pendingPhrase = try await rotateRecovery()
            Log.app.notice("recovery phrase was never confirmed: issued a new one")
            AppModel.shared.showMainWindow()
        } catch { Log.app.error("could not re-issue the recovery phrase: \(describe(error))") }
    }

    // MARK: items

    /// Rebuilds rows and the search index from the encrypted store. Requires the vault to be unlocked.
    func reload() async {
        guard let vault, phase == .unlocked else { return }
        do {
            let listing = try await vault.items()
            guard phase == .unlocked else { return }   // locked while decrypting: discard
            let all = listing.items.map(ItemRow.init)
            apply(rows: all)
            undecryptable = listing.undecryptable.count
        } catch {
            Log.app.error("reload failed: \(describe(error))")
            if case BiselVault.VaultError.locked = error { setPhase(.locked) }
        }
    }

    private func apply(rows all: [ItemRow]) {
        rows = all.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        rowsByID = Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })
        index.replace(all.filter { $0.type == .login || $0.type == .secret }.map { r in
            let u = usage.entries[r.id]
            return SearchRecord(id: r.id, title: r.title, username: r.username, urls: r.urls, tags: r.tags,
                                lastUsed: u?.last ?? r.updatedAt, useCount: u?.count ?? 0)
        })
    }

    func item(id: String) async throws -> Item {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        return try await vault.item(id: id)
    }

    @discardableResult
    func save(_ item: Item) async throws -> Item {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        let saved = try await vault.save(item)
        await reload()
        pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges
        Task { await sync(reason: "save") }
        return saved
    }

    func delete(id: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.delete(id: id)
        usage.forget(id)
        await reload()
        pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges
        Task { await sync(reason: "delete") }
    }

    /// Imports many items without per-item syncing; one sync at the end.
    func saveMany(_ items: [Item], progress: (Int) -> Void = { _ in }) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        for (i, it) in items.enumerated() {
            var fresh = it
            fresh.id = ""
            try await vault.save(fresh)
            if i % 20 == 0 { progress(i + 1) }
        }
        progress(items.count)
        await reload()
        await sync(reason: "import")
    }

    // MARK: devices

    func devices() async throws -> [DeviceInfo] {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        return try await vault.devices()
    }

    func revoke(deviceID: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.revoke(deviceID: deviceID)
    }

    // MARK: sync

    private func startPolling() {
        pollTimer?.invalidate()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { Task { await self?.sync(reason: "poll") } }
        }
    }

    private func stopPolling() { pollTimer?.invalidate(); pollTimer = nil }

    /// Push local edits, resolve conflicts (remote wins; local edit kept as "<title> (conflict)"), pull. Offline-tolerant.
    func sync(reason: String) async {
        // Requests run one after another (a caller that awaits always sees a pass that started after its own edits);
        // the background poll just skips a tick while one is running.
        if reason == "poll" && syncing { return }
        let previous = syncChain
        let run = Task { await previous?.value; await performSync(reason: reason) }
        syncChain = run
        await run.value
    }

    private func performSync(reason: String) async {
        guard let vault, phase != .needsSetup, serverURL != nil else { return }
        syncing = true
        syncState = .syncing
        defer { syncing = false }
        do {
            let report = try await vault.sync()
            pendingChanges = (try? await vault.pendingChanges()) ?? 0
            syncState = .synced(Date())
            if !report.conflicts.isEmpty { lastConflicts = report.conflicts.count }
            Log.app.notice("sync(\(reason)): pushed=\(report.pushed) pulled=\(report.pulled) conflicts=\(report.conflicts.count) deferred=\(report.deferredConflicts.count)")
            if report.rotationAdopted, await !vault.isUnlocked {
                // Another device rotated the vault key (a revoke): the core locked itself. Drop everything and ask for Touch ID.
                setPhase(.locked)
                Toast.shared.show("Box key changed on another device. Unlock to continue", duration: .seconds(4))
                return
            }
            if report.pulled > 0 || report.pushed > 0 || !report.conflicts.isEmpty { await reload() }
            if !report.conflicts.isEmpty {
                Toast.shared.show("\(report.conflicts.count) sync conflict(s): your edit was kept as “… (conflict)”", isError: true, duration: .seconds(4))
            }
        } catch let e as SyncError {
            pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges
            switch e {
            case .network(let m): syncState = .offline(m)
            default: syncState = .failed(describe(e))
            }
            Log.app.notice("sync(\(reason)) failed: \(describe(e))")
        } catch {
            syncState = .failed(describe(error))
            Log.app.error("sync(\(reason)) failed: \(describe(error))")
        }
    }

    // MARK: VaultSearchSource / VaultSecretProvider (the command panel)

    func search(_ query: String, limit: Int) -> [VaultSearchResult] {
        guard isUnlocked else { return [] }
        return index.search(query, limit: limit).map {
            VaultSearchResult(id: $0.id, title: $0.title, username: $0.username, domain: $0.domain, tags: $0.tags,
                              hasPassword: rowsByID[$0.id]?.hasPassword ?? true, hasTOTP: rowsByID[$0.id]?.hasTOTP ?? true)
        }
    }

    func recordUse(id: String) {
        index.recordUse(id: id)
        usage.record(id)
    }

    func secret(_ kind: SecretKind, for id: String) async throws -> String {
        guard isUnlocked else { throw VaultError.locked }
        try await gateStrict(kind, id)
        let item: Item
        do { item = try await self.item(id: id) }
        catch BiselVault.VaultError.locked { setPhase(.locked); throw VaultError.locked }
        catch BiselVault.VaultError.notFound { throw VaultError.notFound }
        switch kind {
        case .username:
            guard let v = item.username, !v.isEmpty else { throw VaultError.unavailable(kind) }
            return v
        case .password:
            guard let v = item.password, !v.isEmpty else { throw VaultError.unavailable(kind) }
            return v
        case .totp:
            guard let p = item.totp else { throw VaultError.unavailable(kind) }
            do { return try TOTPGenerator.code(p).code } catch { throw VaultError.unavailable(kind) }
        }
    }

    /// SPEC §4 strict mode ("Require Touch ID to reveal or copy password and OTP"): every read of a password or OTP, from any caller
    /// (copy, fill, panel), needs a fresh `LAContext` check unless the caller just ran it (single-use credit). The panel refreshes a
    /// revealed OTP at each period boundary, so an OTP read for an item already revealed in the last 35 s does not prompt again.
    private func gateStrict(_ kind: SecretKind, _ id: String) async throws {
        guard SecuritySettings.requireTouchID, kind != .username else { return }
        if kind == .totp, let t = otpGatedAt[id], ContinuousClock.now - t < .seconds(35) { otpGatedAt[id] = .now; return }
        if !BiometricGate.consumeCredit() {
            try await BiometricGate.authenticate(reason: kind == .totp ? "Use one-time code" : "Use password", grantsCredit: false)
        }
        if kind == .totp { otpGatedAt[id] = .now }
    }

    func url(for id: String) -> URL? {
        guard let first = rowsByID[id]?.urls.first else { return nil }
        return URLPolicy.allowed(first)
    }

    func totpPeriod(for id: String) -> Int { rowsByID[id]?.totpPeriod ?? 30 }
}
