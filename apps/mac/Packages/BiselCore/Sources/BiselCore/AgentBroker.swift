@_exported import BiselAgent
import Foundation

/// What the app supplies to the broker: its switches, the Touch ID prompt and the fill, which all need AppKit.
public protocol AgentHost: Sendable {
    func isAllowed() async -> Bool
    func isUnlocked() async -> Bool
    /// One fresh Touch ID check showing `reason`. Throws `AgentError(.denied)` or `AgentError(.timeout)`.
    func approve(_ reason: String) async throws
    /// Checks the field in front with `AgentFillPolicy`, asks for approval, then types. Throws `AgentError`.
    func fill(_ item: Item, login: Bool, submit: Bool) async throws
    func didChange(_ reason: String) async
}

/// Decides every agent request (docs/AGENT-CLI.md). Secrets leave only as the answer to an approved `.run`; nothing here logs.
public actor AgentBroker {
    public static let searchWindow: Duration = .seconds(300)
    static let maxRefs = 8
    static let maxResults = 25

    private let vault: Vault
    private let host: any AgentHost
    private var busy = false
    private var searchApprovedUntil: ContinuousClock.Instant?

    public init(vault: Vault, host: any AgentHost) { self.vault = vault; self.host = host }

    /// The box locked, or agent access changed: the next search asks again.
    public func resetSearchWindow() { searchApprovedUntil = nil }

    public func handle(_ request: AgentRequest) async -> AgentResult {
        let allowed = await host.isAllowed()
        let hostUnlocked = await host.isUnlocked()
        let unlocked = await vault.isUnlocked && hostUnlocked
        if case .status = request { return .status(AgentStatus(unlocked: unlocked, agentsAllowed: allowed)) }
        guard allowed else { return .refused(.agentsOff) }
        guard unlocked else { return .refused(.locked) }
        guard !busy else { return .refused(.busy) }
        busy = true
        defer { busy = false }
        do { return try await perform(request) }
        catch let e as AgentError { return .refused(e.code) }
        catch VaultError.locked { return .refused(.locked) }
        catch VaultError.notFound { return .refused(.notFound) }
        catch KeyStoreError.userCancelled { return .refused(.denied) }
        catch is ItemValidationError { return .refused(.badRequest) }
        catch is ItemConflict { return .refused(.conflict) }
        catch { return .refused(.failed) }
    }

    private func perform(_ request: AgentRequest) async throws -> AgentResult {
        switch request {
        case .status: return .done
        case .search(let text): return .items(try await search(text))
        case .run(let refs, let command): return .secrets(try await run(refs, command))
        case .fill(let id, let login, let submit):
            try await host.fill(try await vault.item(id: id), login: login, submit: submit)
            return .done
        case .add(let fields, let password): return .saved(id: try await add(fields, password))
        case .edit(let id, let fields):
            try await edit(id, fields)
            return .saved(id: id)
        case .trash(let id):
            let item = try await vault.item(id: id)
            let gate = AgentGate(host: host, reason: "let an agent move \(AgentPrompt.clean(item.title)) to the trash")
            _ = try await vault.trashItem(id: id, gate: gate)
            await host.didChange("agent")
            return .saved(id: id)
        }
    }

    private func search(_ text: String) async throws -> [AgentItem] {
        let query = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { throw AgentError(.badRequest) }
        if searchApprovedUntil.map({ $0 <= .now }) ?? true {
            try await host.approve("let an agent search item names in your box for 5 minutes")
            searchApprovedUntil = .now + Self.searchWindow
        }
        let items = try await vault.items().items.filter { $0.type != .passkey }
        return items
            .filter { $0.title.lowercased().contains(query) || SiteMatch.hosts(of: $0.urls).contains { $0.contains(query) } }
            .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
            .prefix(Self.maxResults)
            .map(Self.listing)
    }

    private static func listing(_ item: Item) -> AgentItem {
        var has: [String] = []
        if !(item.password ?? "").isEmpty { has.append("password") }
        if item.totp != nil { has.append("totp") }
        return AgentItem(id: item.id, title: item.title, domain: SiteMatch.hosts(of: item.urls).first, has: has, fields: item.fields.map(\.label))
    }

    private func run(_ refs: [AgentSecretRef], _ command: [String]) async throws -> [AgentSecret] {
        guard (1...Self.maxRefs).contains(refs.count) else { throw AgentError(.badRequest) }
        guard let shown = AgentPrompt.command(command) else { throw AgentError(.commandRefused) }
        var names: [String] = []
        for ref in refs {
            let item = try await vault.item(id: ref.item)
            _ = try Self.value(ref.field, of: item)
            names.append("\(AgentPrompt.clean(item.title, limit: 40)) \(Self.label(ref.field))")
        }
        try await host.approve("give \(names.joined(separator: ", ")) to \(shown)")
        // Read again: the prompt is a suspension point and the item may have changed behind it.
        var values: [AgentSecret] = []
        for ref in refs { values.append(AgentSecret(try Self.value(ref.field, of: try await vault.item(id: ref.item)))) }
        return values
    }

    private static func label(_ field: AgentField) -> String {
        switch field {
        case .password: "password"
        case .username: "username"
        case .totp: "one-time code"
        case .custom(let label): AgentPrompt.clean(label, limit: 30)
        }
    }

    private static func value(_ field: AgentField, of item: Item) throws -> String {
        let found: String?
        switch field {
        case .password: found = item.password
        case .username: found = item.username
        case .totp: found = try item.totp.map { try TOTPGenerator.code($0).code }
        case .custom(let label): found = item.fields.first { $0.label == label }?.value
        }
        guard let found, !found.isEmpty else { throw AgentError(.noSuchField) }
        return found
    }

    private func add(_ fields: AgentItemFields, _ password: AgentSecret?) async throws -> String {
        guard let title = fields.title, Self.showable(fields) else { throw AgentError(.badRequest) }
        var draft = ItemDraft(type: .login)
        draft.title = title
        draft.urls = fields.url.map { [$0] } ?? []
        draft.username = fields.username ?? ""
        if let password {
            guard let text = String(data: password.bytes, encoding: .utf8), !text.isEmpty else { throw AgentError(.badRequest) }
            draft.password = text
        } else {
            draft.password = try PasswordGenerator.generate().value
        }
        guard ItemValidator.issues(for: draft).isEmpty else { throw AgentError(.badRequest) }
        try await host.approve("let an agent add \(Self.changes(fields))")
        let item = try await vault.createItem(draft)
        await host.didChange("agent")
        return item.id
    }

    private func edit(_ id: String, _ fields: AgentItemFields) async throws {
        guard !fields.isEmpty, Self.showable(fields) else { throw AgentError(.badRequest) }
        let item = try await vault.item(id: id)
        var draft = ItemDraft(editing: item)
        if let title = fields.title { draft.title = title }
        if let username = fields.username { draft.username = username }
        if let url = fields.url {
            if draft.urls.isEmpty { draft.urls = [url] } else { draft.urls[0] = url }
        }
        let gate = AgentGate(host: host, reason: "let an agent change \(AgentPrompt.clean(item.title)): \(Self.changes(fields))")
        try await vault.updateItem(draft, gate: gate)
        await host.didChange("agent")
    }

    /// An address decides where a later fill may type, so a change to one must show in the prompt in full.
    private static func showable(_ fields: AgentItemFields) -> Bool {
        [fields.title, fields.url, fields.username].compactMap(\.self).allSatisfy { AgentPrompt.isPrintable($0) && $0.count <= 120 }
    }

    private static func changes(_ fields: AgentItemFields) -> String {
        var parts: [String] = []
        if let title = fields.title { parts.append("title \"\(title)\"") }
        if let url = fields.url { parts.append("address \"\(url)\"") }
        if let username = fields.username { parts.append("username \"\(username)\"") }
        return parts.joined(separator: ", ")
    }
}

/// Stands in for the configured gate on an agent's edit or trash, so the core keeps its check where it is and the prompt says who asks.
private struct AgentGate: BiometricGate {
    let host: any AgentHost
    let reason: String
    func authenticate(reason _: String) async throws { try await host.approve(reason) }
}

/// What the page in front must look like before an agent's fill even asks for Touch ID. Stricter than a person's fill: browsers only,
/// a readable address that matches, no forced plan.
public enum AgentFillPolicy {
    public struct Field: Sendable {
        public var isBrowser: Bool
        public var isTerminal: Bool
        public var isTextInput: Bool
        public var isSecure: Bool
        public var isCode: Bool
        public var pageHost: String?
        public init(isBrowser: Bool, isTerminal: Bool, isTextInput: Bool, isSecure: Bool, isCode: Bool, pageHost: String?) {
            self.isBrowser = isBrowser; self.isTerminal = isTerminal; self.isTextInput = isTextInput
            self.isSecure = isSecure; self.isCode = isCode; self.pageHost = pageHost
        }
    }

    public static func refusal(_ field: Field, itemHosts: [String], login: Bool, matches: (_ page: String, _ item: String) -> Bool) -> AgentCode? {
        guard !itemHosts.isEmpty, field.isBrowser, !field.isTerminal, let page = field.pageHost, !page.isEmpty,
              itemHosts.contains(where: { matches(page, $0) }) else { return .wrongSite }
        guard field.isTextInput else { return .notPasswordField }
        if login { return field.isSecure ? .notPasswordField : nil }
        return field.isSecure || field.isCode ? nil : .notPasswordField
    }
}
