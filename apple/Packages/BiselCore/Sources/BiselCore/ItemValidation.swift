import Foundation

public enum ItemLimits {
    /// The encoded (JSON) item, before encryption.
    public static let maxItemBytes = 256 * 1024
    public static let maxTitleLength = 200
    public static let maxURLs = 20
    public static let maxURLLength = 2048
    public static let maxTags = 50
    public static let maxTagLength = 64
    public static let maxCustomFields = 50
    public static let maxFieldLabelLength = 100
}

/// The part of an item a validation issue or a merge conflict points at.
public enum ItemFieldID: String, Sendable, CaseIterable, Codable {
    case type, title, urls, username, password, totp, notes, fields, tags
    /// The whole item (too large).
    case size
}

public struct ItemIssue: Sendable, Equatable, Hashable {
    public enum Code: String, Sendable {
        /// Title (every type) and the secret value (type `secret`) cannot be empty.
        case required
        case tooLong
        /// Too many addresses, tags or custom fields.
        case tooMany
        case invalidURL
        /// Only http and https addresses are kept (no javascript:, file:, mailto:, ...).
        case unsupportedURLScheme
        case totpNotBase32
        case totpTooShort
        /// A counter-based (`hotp`) URI.
        case totpUnsupported
        case totpBadParameters
        /// A custom field has a value but no label.
        case labelRequired
        /// The item would be bigger than `ItemLimits.maxItemBytes` once encoded.
        case tooLarge
        /// New items cannot be passkeys, and an item cannot become or stop being one.
        case unsupportedType
    }

    public let field: ItemFieldID
    public let code: Code
    /// Which address or custom field, for `urls` and `fields`.
    public let index: Int?

    public init(_ field: ItemFieldID, _ code: Code, index: Int? = nil) { self.field = field; self.code = code; self.index = index }
}

public struct ItemValidationError: Error, Sendable, Equatable {
    public let issues: [ItemIssue]
    public init(issues: [ItemIssue]) { self.issues = issues }
}

public enum URLNormalization: Sendable, Equatable {
    case empty
    case normalized(String)
    case invalid
    case unsupportedScheme
}

/// A draft's contents after trimming and parsing, in the shape of an `Item` and cut down to what its type can hold.
struct NormalizedContent: Equatable {
    var type: ItemType
    var title: String
    var urls: [String]
    var username: String?
    var password: String?
    var totp: TOTPParameters?
    var notes: String?
    var fields: [CustomField]
    var tags: [String]
}

/// Every rule an item has to follow, in one place.
public enum ItemValidator {
    /// Trims, adds `https://` when there is no scheme, lowercases scheme and host, drops a bare trailing `/`. Only http(s) with
    /// a host and no embedded credentials is accepted.
    public static func normalizeURL(_ raw: String) -> URLNormalization {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return .empty }
        guard !t.contains(where: { $0.isWhitespace || $0.unicodeScalars.contains { $0.properties.generalCategory == .control } }),
              t.count <= ItemLimits.maxURLLength else { return .invalid }
        let withScheme: String
        if let r = t.range(of: "://") {
            let scheme = t[..<r.lowerBound].lowercased()
            guard !scheme.isEmpty, scheme.allSatisfy({ $0.isLetter || $0.isNumber || "+.-".contains($0) }) else { return .invalid }
            guard scheme == "http" || scheme == "https" else { return .unsupportedScheme }
            withScheme = t
        } else if let colon = t.firstIndex(of: ":"), !t.hasPrefix("["),
                  t[..<colon].allSatisfy({ $0.isLetter || $0.isNumber || "+.-".contains($0) }),
                  !t[t.index(after: colon)...].prefix(while: { $0 != "/" && $0 != "?" && $0 != "#" }).allSatisfy(\.isNumber) {
            return .unsupportedScheme   // "javascript:alert(1)", "mailto:x"; "host:8080/path" falls through
        } else {
            withScheme = "https://" + t
        }
        guard var c = URLComponents(string: withScheme), let host = c.host, !host.isEmpty,
              c.user == nil, c.password == nil else { return .invalid }
        c.scheme = c.scheme?.lowercased()
        c.host = host.lowercased()
        if c.path == "/", c.query == nil, c.fragment == nil { c.path = "" }
        guard let out = c.string else { return .invalid }
        return .normalized(out)
    }

    /// Every problem with the draft, in field order. Empty means it can be saved.
    public static func issues(for draft: ItemDraft) -> [ItemIssue] {
        var issues: [ItemIssue] = []
        _ = normalize(draft, into: &issues)
        return issues
    }

    /// The item a create would store (`id` is the draft's, dates are now). Throws `ItemValidationError`.
    public static func item(from draft: ItemDraft) throws -> Item {
        makeItem(try validated(draft), id: draft.id, over: draft.base)
    }

    /// Nil when the encoded item fits in `ItemLimits.maxItemBytes`.
    public static func sizeIssue(for item: Item) -> ItemIssue? {
        guard let data = try? ItemCodec.encode(item), data.count <= ItemLimits.maxItemBytes else { return ItemIssue(.size, .tooLarge) }
        return nil
    }

    static func validated(_ draft: ItemDraft) throws -> NormalizedContent {
        var issues: [ItemIssue] = []
        let n = normalize(draft, into: &issues)
        guard issues.isEmpty else { throw ItemValidationError(issues: issues) }
        return n
    }

    static func makeItem(_ n: NormalizedContent, id: String, over base: Item?) -> Item {
        var item = base ?? Item(id: id, title: n.title)
        item.id = id; item.type = n.type; item.title = n.title; item.urls = n.urls; item.username = n.username
        item.password = n.password; item.totp = n.totp; item.notes = n.notes; item.fields = n.fields; item.tags = n.tags
        return item
    }

    static func normalize(_ d: ItemDraft, into issues: inout [ItemIssue]) -> NormalizedContent {
        var n = NormalizedContent(type: d.type, title: "", urls: [], username: nil, password: nil, totp: nil, notes: nil, fields: [], tags: [])

        // type: login, note and secret can be chosen; a passkey stays a passkey and cannot be made from a draft.
        if d.type == .passkey {
            if d.base?.type != .passkey { issues.append(ItemIssue(.type, .unsupportedType)) }
        } else if d.base?.type == .passkey {
            issues.append(ItemIssue(.type, .unsupportedType))
        }

        n.title = d.title.trimmingCharacters(in: .whitespacesAndNewlines)
        if n.title.isEmpty { issues.append(ItemIssue(.title, .required)) }
        else if n.title.count > ItemLimits.maxTitleLength { issues.append(ItemIssue(.title, .tooLong)) }

        let hasURLs = d.type == .login || d.type == .secret || d.type == .passkey
        if hasURLs {
            var seen = Set<String>()
            for (i, raw) in d.urls.enumerated() {
                // An address the item already had is kept as it was, even if today's rules would refuse it (an import may have
                // stored an app link); only what the user typed new is checked.
                if d.base?.urls.contains(raw) == true { if seen.insert(raw).inserted { n.urls.append(raw) }; continue }
                switch normalizeURL(raw) {
                case .empty: continue
                case .invalid: issues.append(ItemIssue(.urls, .invalidURL, index: i))
                case .unsupportedScheme: issues.append(ItemIssue(.urls, .unsupportedURLScheme, index: i))
                case .normalized(let u): if seen.insert(u).inserted { n.urls.append(u) }
                }
            }
            if n.urls.count > ItemLimits.maxURLs { issues.append(ItemIssue(.urls, .tooMany)) }
        }

        if d.type == .login || d.type == .secret || d.type == .passkey {
            let u = d.username.trimmingCharacters(in: .whitespacesAndNewlines)
            n.username = u.isEmpty ? nil : u
        }
        if d.type == .login || d.type == .secret {
            n.password = d.password.isEmpty ? nil : d.password
            if d.type == .secret, n.password == nil { issues.append(ItemIssue(.password, .required)) }
        } else if d.type == .passkey {
            n.password = d.base?.password   // a passkey item's own fields are not editable here
        }

        if d.type == .login || d.type == .passkey {
            let raw = d.totp.trimmingCharacters(in: .whitespacesAndNewlines)
            if !raw.isEmpty {
                do { n.totp = try TOTPSetup.parse(raw).params }
                catch {
                    let code: ItemIssue.Code = switch error {
                    case .unsupportedType: .totpUnsupported
                    case .tooShort: .totpTooShort
                    case .badParameters: .totpBadParameters
                    case .empty, .missingSecret, .notBase32: .totpNotBase32
                    }
                    issues.append(ItemIssue(.totp, code))
                }
            }
        }

        if !d.notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { n.notes = d.notes }

        var seenTags = Set<String>()
        for raw in d.tags {
            let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !t.isEmpty, seenTags.insert(t.lowercased()).inserted else { continue }
            if t.count > ItemLimits.maxTagLength { issues.append(ItemIssue(.tags, .tooLong)) }
            n.tags.append(t)
        }
        if n.tags.count > ItemLimits.maxTags { issues.append(ItemIssue(.tags, .tooMany)) }

        for (i, f) in d.fields.enumerated() {
            let label = f.label.trimmingCharacters(in: .whitespacesAndNewlines)
            if label.isEmpty && f.value.isEmpty { continue }   // an untouched blank row
            if label.isEmpty { issues.append(ItemIssue(.fields, .labelRequired, index: i)); continue }
            if label.count > ItemLimits.maxFieldLabelLength { issues.append(ItemIssue(.fields, .tooLong, index: i)) }
            n.fields.append(CustomField(label: label, value: f.value, secret: f.secret))
        }
        if n.fields.count > ItemLimits.maxCustomFields { issues.append(ItemIssue(.fields, .tooMany)) }

        // Size last, and only when the rest is fine (it needs a complete item).
        if issues.isEmpty, let big = sizeIssue(for: makeItem(n, id: d.id, over: d.base)) { issues.append(big) }
        return n
    }
}
