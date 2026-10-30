import Foundation

/// What an add/edit form holds: plain strings exactly as typed. Nothing here is trimmed or parsed; `ItemValidator` turns a
/// draft into an `Item` (or a list of issues per field).
public struct ItemDraft: Sendable, Equatable {
    /// The item's id. For a new draft this is a fresh random id, so creating the same draft twice (a double Return, a retry
    /// after an error) can never produce two items.
    public let id: String
    /// The item as it was when the form was opened. Present for edits: it is what stale-revision detection compares against.
    public let base: Item?

    public var type: ItemType
    public var title = ""
    public var urls: [String] = []
    public var username = ""
    public var password = ""
    /// A bare base32 secret or an `otpauth://totp/...` URI. Empty means no one-time code.
    public var totp = ""
    public var notes = ""
    public var fields: [CustomField] = []
    public var tags: [String] = []

    public var isNew: Bool { base == nil }

    /// An empty draft for a new item.
    public init(type: ItemType = .login) {
        id = BiselRandom.identifier(); base = nil; self.type = type
    }

    /// A draft for editing `item`. Saving it against a newer revision merges instead of overwriting.
    public init(editing item: Item) {
        id = item.id; base = item; type = item.type
        Self.fill(&self, from: item)
    }

    /// A new draft pre-filled from `item` (duplicate).
    public init(copying item: Item) {
        id = BiselRandom.identifier(); base = nil; type = item.type
        Self.fill(&self, from: item)
    }

    private static func fill(_ d: inout ItemDraft, from item: Item) {
        d.type = item.type; d.title = item.title; d.urls = item.urls; d.username = item.username ?? ""
        d.password = item.password ?? ""; d.totp = item.totp.map(TOTPSetup.text(for:)) ?? ""
        d.notes = item.notes ?? ""; d.fields = item.fields; d.tags = item.tags
    }
}

// A draft holds a password, a one-time-code secret and notes: its textual and reflected forms show nothing.
extension ItemDraft: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "ItemDraft(id: \(id), type: \(type.rawValue), contents redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }
}
