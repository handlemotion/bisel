import Foundation
import BiselCore

/// A lightweight search hit. Deliberately contains NO secret: the panel renders these in a list,
/// and passwords are never rendered there (SPEC.md §8).
///
/// Display only: `title` and `username` are cleaned of direction and control characters (`DisplayText`) for every row,
/// detail, VoiceOver label and announcement. Copy and fill read the item itself (`VaultSecretProvider`), never these.
struct VaultSearchResult: Identifiable, Hashable, Sendable {
    let id: String
    let title: String
    let username: String
    let domain: String
    let tags: [String]
    /// What the item actually holds, so the panel only offers rows and actions that can work.
    var hasPassword = true
    var hasTOTP = true

    init(id: String, title: String, username: String, domain: String, tags: [String], hasPassword: Bool = true, hasTOTP: Bool = true) {
        self.id = id
        self.title = DisplayText.clean(title)
        self.username = DisplayText.clean(username)
        self.domain = domain
        self.tags = tags
        self.hasPassword = hasPassword
        self.hasTOTP = hasTOTP
    }
}

enum SecretKind: String, Sendable {
    case username, password, totp
}

/// What the command panel talks to for search. The real implementation (M3, after BiselCore) will build a
/// `FuzzySearchIndex` from decrypted items when the vault unlocks and drop it on lock.
/// Synchronous on purpose: the index is in memory and the panel must paint results in well under 50 ms.
@MainActor
protocol VaultSearchSource: AnyObject, Sendable {
    /// False while the vault is locked. The panel then shows an "Unlock" empty state.
    var isUnlocked: Bool { get }
    /// Footer label shown when the source is not the real vault (e.g. "DEV FIXTURE").
    var provenanceLabel: String? { get }
    /// `query` empty returns recents/frequent. Results are best-first.
    func search(_ query: String, limit: Int) -> [VaultSearchResult]
    func recordUse(id: String)
}

/// Secret access, kept apart from search so list rendering can never touch a password.
/// The real implementation does the `LAContext` evaluation for sensitive kinds (SPEC.md §4).
@MainActor
protocol VaultSecretProvider: AnyObject, Sendable {
    func secret(_ kind: SecretKind, for id: String) async throws -> String
    func url(for id: String) -> URL?
    /// Hosts of the item's addresses, for the fill origin check. Sources without addresses return none (no check).
    func hosts(for id: String) -> [String]
    /// Seconds a TOTP code lives (the item's `period`).
    func totpPeriod(for id: String) -> Int
}

extension VaultSecretProvider {
    func hosts(for id: String) -> [String] { [] }
    func totpPeriod(for id: String) -> Int { 30 }
}

enum VaultError: Error, LocalizedError {
    case locked, notFound, unavailable(SecretKind)
    var errorDescription: String? {
        switch self {
        case .locked: "Box is locked"
        case .notFound: "Item not found"
        case .unavailable(let k): "This item has no \(k.rawValue)"
        }
    }
}
