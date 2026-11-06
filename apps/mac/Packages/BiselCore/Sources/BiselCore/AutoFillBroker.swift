import Foundation
import Synchronization

/// What the app supplies to the broker: the Touch ID prompt.
public protocol AutoFillHost: Sendable {
    /// One Touch ID showing `reason`: it unlocks a locked box, and on an open one is a fresh check. Throws when it is not passed.
    func authenticate(_ reason: String) async throws
    /// A passkey was saved behind the app's back: show it, offer it, and sync it.
    func passkeysChanged() async
}

/// `Vault`'s passkey calls each take one check. The broker has already made it through the host, which can also unlock a locked box.
private struct CheckedByHost: BiometricGate {
    func authenticate(reason: String) async throws {}
}

/// Decides every request of the AutoFill extension (docs/SPEC.md §8, "AutoFill"). A password or a one-time code leaves only after
/// Touch ID, for a login whose own address belongs to the site the system named, and a passkey signs only after Touch ID, for exactly
/// the RP ID the system named. A code is made here: its setup key stays in the app. Nothing here logs.
public actor AutoFillBroker {
    /// How long the person has to choose from the list one Touch ID opened.
    static let choiceWindow: Duration = .seconds(120)

    private struct Choice {
        var ids: Set<String>
        var until: ContinuousClock.Instant
        /// A list of codes pays only for a code, and any other list never pays for one.
        var codes = false
    }

    private let vault: Vault
    private let host: any AutoFillHost
    private let isPublicSuffix: @Sendable (String) -> Bool
    private var busy = false
    private var choice: Choice?

    public init(vault: Vault, host: any AutoFillHost, isPublicSuffix: @escaping @Sendable (String) -> Bool) {
        self.vault = vault; self.host = host; self.isPublicSuffix = isPublicSuffix
    }

    public func handle(_ request: AutoFillRequest) async -> AutoFillResult {
        guard !busy else { return .refused(.busy) }
        busy = true
        defer { busy = false }
        do {
            switch request {
            case .list(let services): return .candidates(try await list(try Self.hosts(services)))
            case .credential(let id, let services): return try await credential(id, try Self.hosts(services))
            case .oneTimeCodes(let services): return .candidates(try await codes(try Self.hosts(services)))
            case .oneTimeCode(let id, let services): return try await oneTimeCode(id, try Self.hosts(services))
            case .passkeys(let rpID, let allowList): return .passkeys(try await passkeys(try relyingParty(rpID), allowList))
            case .passkeyAssertion(let rpID, let credentialID, let hash): return try await assertion(try relyingParty(rpID), credentialID, hash)
            case .passkeyRegistration(let request): return try await register(request)
            }
        }
        catch let e as AgentError { return .refused(e.code) }
        catch VaultError.locked { return .refused(.locked) }
        catch VaultError.notFound { return .refused(.notFound) }
        catch VaultError.notConfigured { return .refused(.locked) }
        catch KeyStoreError.userCancelled { return .refused(.denied) }
        catch PasskeyError.noCredential { return .refused(.notFound) }
        catch PasskeyError.excludedCredential { return .refused(.excludedCredential) }
        catch is PasskeyError { return .refused(.badRequest) }
        catch { return .refused(.failed) }
    }

    private static func hosts(_ services: [String]) throws -> [String] {
        let hosts = SiteMatch.hosts(of: services)
        guard !hosts.isEmpty else { throw AgentError(.badRequest) }
        return hosts
    }

    private func list(_ hosts: [String]) async throws -> [AutoFillCandidate] {
        try await host.authenticate("show your logins for \(AgentPrompt.clean(hosts[0], limit: 60))")
        let logins = try await vault.items().items.filter { Self.isFillable($0) && belongs($0, to: hosts) }
        choice = Choice(ids: Set(logins.map(\.id)), until: .now + Self.choiceWindow)
        return logins.map { AutoFillCandidate(id: $0.id, title: $0.title, username: $0.username ?? "") }
    }

    private func credential(_ id: String, _ hosts: [String]) async throws -> AutoFillResult {
        let open = await vault.isUnlocked
        let chosen = open && takeChoice(id)
        if !chosen {
            if open { _ = try await login(id, for: hosts) }   // no prompt for what would be refused anyway
            try await host.authenticate("fill your login on \(AgentPrompt.clean(hosts[0], limit: 60))")
        }
        let item = try await login(id, for: hosts)
        return .credential(username: item.username ?? "", password: AgentSecret(item.password ?? ""))
    }

    private func codes(_ hosts: [String]) async throws -> [AutoFillCandidate] {
        try await host.authenticate("show your one-time codes for \(AgentPrompt.clean(hosts[0], limit: 60))")
        let logins = try await vault.items().items.filter { Self.hasCode($0) && belongs($0, to: hosts) }
        choice = Choice(ids: Set(logins.map(\.id)), until: .now + Self.choiceWindow, codes: true)
        return logins.map { AutoFillCandidate(id: $0.id, title: $0.title, username: $0.username ?? "") }
    }

    private func oneTimeCode(_ id: String, _ hosts: [String]) async throws -> AutoFillResult {
        let open = await vault.isUnlocked
        let chosen = open && takeChoice(id, codes: true)
        if !chosen {
            if open { _ = try await login(id, for: hosts, Self.hasCode) }   // no prompt for what would be refused anyway
            try await host.authenticate("fill your one-time code on \(AgentPrompt.clean(hosts[0], limit: 60))")
        }
        let item = try await login(id, for: hosts, Self.hasCode)
        guard let parameters = item.totp else { throw AgentError(.noSuchField) }
        return .oneTimeCode(AgentSecret(try TOTPGenerator.code(parameters).code))   // after the prompt: the person may take a while
    }

    /// A public suffix is no site: nobody can own a passkey for all of `github.io`.
    private func relyingParty(_ rpID: String) throws -> String {
        let rp = PasskeyAuthenticator.normalized(rpID: rpID)
        guard !rp.isEmpty, !isPublicSuffix(rp) else { throw AgentError(.badRequest) }
        return rp
    }

    private func passkeys(_ rp: String, _ allowList: [Data]) async throws -> [AutoFillPasskey] {
        // No prompt for an empty answer: the extension then goes on to passwords, which ask for themselves.
        if await vault.isUnlocked, try await vault.passkeys(rpID: rp, allowList: allowList).isEmpty { return [] }
        try await host.authenticate("show your passkeys for \(AgentPrompt.clean(rp, limit: 60))")
        let matches = try await vault.passkeys(rpID: rp, allowList: allowList)
        choice = Choice(ids: Set(matches.map(\.itemID)), until: .now + Self.choiceWindow)
        return matches.map { AutoFillPasskey(credentialID: $0.credentialID, userName: $0.userName) }
    }

    private func assertion(_ rp: String, _ credentialID: Data, _ clientDataHash: Data) async throws -> AutoFillResult {
        var chosen = false
        if await vault.isUnlocked {   // no prompt for what would be refused anyway
            guard let held = try await vault.passkeys(rpID: rp, allowList: [credentialID]).first else { throw PasskeyError.noCredential }
            chosen = takeChoice(held.itemID)
        }
        if !chosen { try await host.authenticate("sign in to \(AgentPrompt.clean(rp, limit: 60))") }
        let signed = try await vault.assertPasskey(rpID: rp, credentialID: credentialID, clientDataHash: clientDataHash, gate: CheckedByHost())
        return .assertion(credentialID: signed.credentialID, userHandle: signed.userHandle,
                          authenticatorData: signed.authenticatorData, signature: signed.signature)
    }

    private func register(_ r: AutoFillPasskeyRegistration) async throws -> AutoFillResult {
        let rp = try relyingParty(r.rpID)
        guard r.algorithms.contains(PasskeyAuthenticator.es256) else { throw PasskeyError.unsupportedAlgorithm }
        try await host.authenticate("create a passkey for \(AgentPrompt.clean(rp, limit: 60))")
        let request = PasskeyRegistrationRequest(rpID: rp, userHandle: r.userHandle, userName: r.userName, userDisplayName: r.userDisplayName,
                                                 algorithms: r.algorithms, excludedCredentialIDs: r.excludedCredentialIDs)
        let made = try await vault.registerPasskey(request, gate: CheckedByHost())
        await host.passkeysChanged()
        return .registered(credentialID: made.credentialID, attestationObject: made.attestationObject)
    }

    /// Single use: a list pays for one password, one signature or one code.
    private func takeChoice(_ id: String, codes: Bool = false) -> Bool {
        defer { choice = nil }
        guard let choice, choice.codes == codes, ContinuousClock.now < choice.until else { return false }
        return choice.ids.contains(id)
    }

    private func login(_ id: String, for hosts: [String], _ usable: (Item) -> Bool = AutoFillBroker.isFillable) async throws -> Item {
        let item = try await vault.item(id: id)
        guard usable(item) else { throw AgentError(.noSuchField) }
        guard belongs(item, to: hosts) else { throw AgentError(.wrongSite) }
        return item
    }

    private static func isFillable(_ item: Item) -> Bool { item.type == .login && !(item.password ?? "").isEmpty }
    private static func hasCode(_ item: Item) -> Bool { item.type == .login && item.totp != nil }

    /// A login without an address belongs to no site. `SiteMatch` compares whole labels, so `github.com.evil.net` is not `github.com`.
    private func belongs(_ item: Item, to hosts: [String]) -> Bool {
        let own = SiteMatch.hosts(of: item.urls)
        return hosts.contains { page in own.contains { SiteMatch.matches(page: page, item: $0, isPublicSuffix: isPublicSuffix) } }
    }
}

/// One entry for the system's credential identity store. That store is plaintext outside the box, so this is all it gets: the site,
/// the username and the item's random id, and for a passkey the two public ids the system needs to offer it. Never a title, a note,
/// a key, a one-time code's setup key, or anything sealed.
public struct AutoFillIdentity: Sendable, Hashable {
    public struct Passkey: Sendable, Hashable {
        public var credentialID: Data
        public var userHandle: Data
        public init(credentialID: Data, userHandle: Data) { self.credentialID = credentialID; self.userHandle = userHandle }
    }

    public var domain: String
    public var username: String
    public var recordID: String
    /// Set on a passkey's entry, whose `domain` is its RP ID.
    public var passkey: Passkey?
    /// An entry for the login's one-time code, beside the one for its password. It says only that the login has a code.
    public var oneTimeCode: Bool
    public init(domain: String, username: String, recordID: String, passkey: Passkey? = nil, oneTimeCode: Bool = false) {
        self.domain = domain; self.username = username; self.recordID = recordID; self.passkey = passkey; self.oneTimeCode = oneTimeCode
    }

    /// One identity per site of each login with a password, and one per site of each login with a one-time code. A public suffix
    /// (`github.io`) is no site: the system would offer that login on every tenant under it. A name with no dot is not a domain either.
    public static func all(in items: [Item], isPublicSuffix: (String) -> Bool) -> [AutoFillIdentity] {
        var out = Set<AutoFillIdentity>()
        for item in items where item.type == .login {
            for host in SiteMatch.hosts(of: item.urls) where host.contains(".") && !isPublicSuffix(host) {
                if !(item.password ?? "").isEmpty { out.insert(AutoFillIdentity(domain: host, username: item.username ?? "", recordID: item.id)) }
                if item.totp != nil { out.insert(AutoFillIdentity(domain: host, username: item.username ?? "", recordID: item.id, oneTimeCode: true)) }
            }
        }
        for (item, credential) in PasskeyLookup.credentials(in: items) where credential.rpID.contains(".") && !isPublicSuffix(credential.rpID) {
            out.insert(AutoFillIdentity(domain: credential.rpID, username: credential.userName, recordID: item.id,
                                        passkey: Passkey(credentialID: credential.credentialID, userHandle: credential.userHandle)))
        }
        return out.sorted {
            ($0.domain, $0.username, $0.recordID, $0.oneTimeCode ? 1 : 0) < ($1.domain, $1.username, $1.recordID, $1.oneTimeCode ? 1 : 0)
        }
    }
}

/// The system's credential identity store, or a fake one in the flows.
public protocol AutoFillIdentitySink: Sendable {
    /// False while the person has not turned Bisel on in AutoFill settings: the system takes nothing then.
    func isEnabled() async -> Bool
    func replace(_ identities: [AutoFillIdentity]) async throws
    func clear() async throws
}

/// Keeps the identity store on the last thing asked for. Calls are synchronous and writes run one at a time, always the newest
/// state, so a `clear()` on lock can never be overtaken by a slow `publish` that started before it.
public final class AutoFillIdentitySync: Sendable {
    private struct State {
        var wanted: [AutoFillIdentity] = []
        /// What the store holds; nil when unknown (never written, or the last write failed).
        var applied: [AutoFillIdentity]?
        var draining = false
    }

    private let sink: any AutoFillIdentitySink
    private let state = Mutex(State())

    public init(sink: any AutoFillIdentitySink) { self.sink = sink }

    public func publish(_ identities: [AutoFillIdentity]) { set(identities) }
    public func clear() { set([]) }

    /// Tries again what could not be written: the person may have turned Bisel on since.
    public func refresh() { start() }

    /// Waits until the store is on the newest state, or the write failed.
    public func settled() async {
        while state.withLock({ $0.draining }) { try? await Task.sleep(for: .milliseconds(10)) }
    }

    private func set(_ identities: [AutoFillIdentity]) {
        state.withLock { $0.wanted = identities }
        start()
    }

    private func start() {
        let begin = state.withLock { s -> Bool in
            guard !s.draining, s.applied != s.wanted else { return false }
            s.draining = true
            return true
        }
        if begin { Task { await drain() } }
    }

    private func drain() async {
        while true {
            let next = state.withLock { s -> [AutoFillIdentity]? in
                if s.applied == s.wanted { s.draining = false; return nil }
                return s.wanted
            }
            guard let next else { return }
            do {
                if next.isEmpty { try await sink.clear() }
                else if await sink.isEnabled() { try await sink.replace(next) }
                else { throw CancellationError() }
                state.withLock { $0.applied = next }
            } catch {
                state.withLock { $0.applied = nil; $0.draining = false }
                return
            }
        }
    }
}
