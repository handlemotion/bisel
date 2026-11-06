import CryptoKit
import Foundation

/// What the app supplies to the broker: the Touch ID prompt, and what follows a save.
public protocol BrowserSaveHost: Sendable {
    /// One Touch ID showing `reason`: it unlocks a locked box, and on an open one is a fresh check. Throws when it is not passed.
    func authenticate(_ reason: String) async throws
    /// A login was saved behind the app's back: show it and sync it.
    func loginSaved() async
}

/// `updateItem` takes one check. The broker has already made it through the host, which can also unlock a locked box.
private struct CheckedByHost: BiometricGate {
    func authenticate(reason: String) async throws {}
}

/// Decides every request of the Chrome extension (docs/SPEC.md §8, "Chrome extension"). It writes, after Touch ID, and it never reads
/// back: `BrowserAnswer` has no room for anything from the box. Any program of this user can run the signed host, so Touch ID and the
/// check allowance below are the access control, not the extension's ID. Nothing here logs.
public actor BrowserSaveBroker {
    /// `.saveCheck` tells a caller whether a password it holds is the stored one. That is needed to stay quiet on every ordinary sign-in
    /// and to tell Save from Update, and it is a guess at the password, so wrong answers are rationed. A right one costs nothing: the
    /// person typing their password never runs out. Once spent, every answer is `.unknown`, right or wrong.
    static let window: Duration = .seconds(3600)
    static let missesPerLogin = 3
    static let missesInAll = 20
    static let saltLength = 16...64

    private let vault: Vault
    private let host: any BrowserSaveHost
    private let isPublicSuffix: @Sendable (String) -> Bool
    private var busy = false
    private var misses: [String: Int] = [:]
    private var windowEnds = ContinuousClock.now

    public init(vault: Vault, host: any BrowserSaveHost, isPublicSuffix: @escaping @Sendable (String) -> Bool) {
        self.vault = vault; self.host = host; self.isPublicSuffix = isPublicSuffix
    }

    public func handle(_ request: BrowserRequest) async -> BrowserAnswer {
        guard !busy else { return .refused(.busy) }
        busy = true
        defer { busy = false }
        do {
            switch request {
            case .saveCheck(let login, let salt, let digest): return try await check(login, salt, digest)
            case .save(let login, let password, let replace): return try await save(login, password, replace: replace)
            }
        }
        catch let e as AgentError { return .refused(e.code) }
        catch VaultError.locked, VaultError.notConfigured { return .refused(.locked) }
        catch KeyStoreError.userCancelled { return .refused(.denied) }
        catch is ItemValidationError { return .refused(.badRequest) }
        catch is ItemConflict { return .refused(.conflict) }
        catch { return .refused(.failed) }
    }

    private func check(_ login: BrowserLogin, _ salt: Data, _ digest: Data) async throws -> BrowserAnswer {
        let site = try Self.site(of: login, isPublicSuffix: isPublicSuffix)
        let username = try Self.username(of: login)
        guard Self.saltLength.contains(salt.count), digest.count == SHA256.byteCount else { throw AgentError(.badRequest) }
        guard await vault.isUnlocked else { return .unknown }
        let held = try await logins(on: site.host, username)

        if ContinuousClock.now >= windowEnds { misses = [:]; windowEnds = .now + Self.window }
        let key = held.first?.id ?? "\(site.host)\n\(username.lowercased())"
        guard misses[key, default: 0] < Self.missesPerLogin, misses.values.reduce(0, +) < Self.missesInAll else { return .unknown }

        if held.contains(where: { Self.digest(salt, $0.password ?? "") == digest }) { return .same }
        misses[key, default: 0] += 1
        return held.isEmpty ? .new : .differs
    }

    private func save(_ login: BrowserLogin, _ password: AgentSecret, replace: Bool) async throws -> BrowserAnswer {
        let site = try Self.site(of: login, isPublicSuffix: isPublicSuffix)
        let username = try Self.username(of: login)
        guard let text = String(data: password.bytes, encoding: .utf8), !text.isEmpty else { throw AgentError(.badRequest) }

        let shown = "\(AgentPrompt.clean(username, limit: 60)) on \(AgentPrompt.clean(site.host, limit: 60))"
        try await host.authenticate(replace ? "update the password of \(shown)" : "save a login for \(shown)")

        // Read only now: the box may have been locked until that prompt.
        let held = try await logins(on: site.host, username)
        if held.contains(where: { $0.password == text }) { return .unchanged }
        guard let item = held.first else {
            var draft = ItemDraft(type: .login)
            draft.title = site.host
            draft.urls = [site.origin]
            draft.username = username
            draft.password = text
            try await vault.createItem(draft)
            await host.loginSaved()
            return .saved
        }
        guard replace else { return .exists }
        var draft = ItemDraft(editing: item)
        draft.password = text
        try await vault.updateItem(draft, gate: CheckedByHost(), keepingPrevious: true)
        await host.loginSaved()
        return .saved
    }

    /// Logins with this username at this site, the one with the very host first, then the newest. A login without an address belongs to no site.
    private func logins(on host: String, _ username: String) async throws -> [Item] {
        let wanted = username.lowercased()
        return try await vault.items().items
            .filter { item in
                item.type == .login && item.username?.lowercased() == wanted
                    && SiteMatch.hosts(of: item.urls).contains { SiteMatch.matches(page: host, item: $0, isPublicSuffix: isPublicSuffix) }
            }
            .sorted { a, b in
                let exactA = SiteMatch.hosts(of: a.urls).contains(host), exactB = SiteMatch.hosts(of: b.urls).contains(host)
                return exactA != exactB ? exactA : a.updatedAt > b.updatedAt
            }
    }

    private static func digest(_ salt: Data, _ password: String) -> Data {
        Data(SHA256.hash(data: salt + Data(password.utf8)))
    }

    /// `https://host[:port]`, nothing else: a page reached over plain http or a whole public suffix is no place to file a password under.
    private static func site(of login: BrowserLogin, isPublicSuffix: (String) -> Bool) throws -> (origin: String, host: String) {
        guard let parts = URLComponents(string: login.site), parts.scheme == "https", parts.user == nil, parts.password == nil,
              parts.path.isEmpty, parts.query == nil, parts.fragment == nil, let name = parts.host, !name.isEmpty else {
            throw AgentError(.wrongSite)
        }
        let host = SiteMatch.normalized(name)
        guard !host.isEmpty, !isPublicSuffix(host) else { throw AgentError(.wrongSite) }
        return (login.site.lowercased(), host)
    }

    /// The Touch ID prompt shows it, so it must read as what it is.
    private static func username(of login: BrowserLogin) throws -> String {
        let username = login.username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !username.isEmpty, username.count <= 256, AgentPrompt.isPrintable(username) else { throw AgentError(.badRequest) }
        return username
    }
}
