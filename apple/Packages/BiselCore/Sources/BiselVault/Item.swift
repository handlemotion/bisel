import Foundation
import BiselTOTP

public enum ItemType: String, Codable, Sendable, CaseIterable {
    case login, note, secret, passkey
}

public struct CustomField: Codable, Sendable, Equatable {
    public var label: String
    public var value: String
    public var secret: Bool
    public init(label: String, value: String, secret: Bool = false) {
        self.label = label; self.value = value; self.secret = secret
    }
}

/// Arbitrary JSON, used so the reserved `passkey` blob round-trips losslessly.
public enum JSONValue: Codable, Sendable, Equatable {
    case null, bool(Bool), number(Double), string(String), array([JSONValue]), object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([JSONValue].self) { self = .array(v) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }
}

/// Decrypted item. `id` is the server record id and is not part of the encrypted payload (it is bound
/// into the AEAD associated data instead).
public struct Item: Sendable, Equatable, Identifiable {
    public var id: String
    public var type: ItemType
    public var title: String
    public var urls: [String]
    public var username: String?
    public var password: String?
    public var totp: TOTPParameters?
    public var notes: String?
    public var fields: [CustomField]
    public var tags: [String]
    public var createdAt: Date
    public var updatedAt: Date
    public var passkey: JSONValue?

    public init(id: String = "", type: ItemType = .login, title: String, urls: [String] = [],
                username: String? = nil, password: String? = nil, totp: TOTPParameters? = nil,
                notes: String? = nil, fields: [CustomField] = [], tags: [String] = [],
                createdAt: Date = Date(), updatedAt: Date = Date(), passkey: JSONValue? = nil) {
        self.id = id; self.type = type; self.title = title; self.urls = urls; self.username = username
        self.password = password; self.totp = totp; self.notes = notes; self.fields = fields; self.tags = tags
        self.createdAt = createdAt; self.updatedAt = updatedAt; self.passkey = passkey
    }
}

/// Item without secrets, for list / search UIs.
public struct ItemSummary: Sendable, Equatable, Identifiable {
    public let id: String
    public let type: ItemType
    public let title: String
    public let urls: [String]
    public let username: String?
    public let tags: [String]
    public let updatedAt: Date
    public let hasTOTP: Bool
    public init(_ item: Item) {
        id = item.id; type = item.type; title = item.title; urls = item.urls; username = item.username
        tags = item.tags; updatedAt = item.updatedAt; hasTOTP = item.totp != nil
    }
}

/// Versioned plaintext payload (§5).
struct ItemPayload: Codable {
    var v: Int = 1
    var type: ItemType
    var title: String
    var urls: [String]
    var username: String?
    var password: String?
    var totp: TOTPParameters?
    var notes: String?
    var fields: [CustomField]
    var tags: [String]
    var createdAt: Date
    var updatedAt: Date
    var passkey: JSONValue?
}

public enum ItemCodec {
    private static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        e.dateEncodingStrategy = .custom { date, enc in
            var c = enc.singleValueContainer()
            try c.encode(date.formatted(.iso8601))
        }
        return e
    }

    private static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            if let date = try? Date(s, strategy: .iso8601) { return date }
            if let date = try? Date(s, strategy: Date.ISO8601FormatStyle(includingFractionalSeconds: true)) { return date }
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "bad RFC3339 date \(s)"))
        }
        return d
    }

    public static func encode(_ item: Item) throws -> Data {
        try encoder().encode(ItemPayload(type: item.type, title: item.title, urls: item.urls,
                                         username: item.username, password: item.password, totp: item.totp,
                                         notes: item.notes, fields: item.fields, tags: item.tags,
                                         createdAt: item.createdAt, updatedAt: item.updatedAt, passkey: item.passkey))
    }

    public static func decode(_ data: Data, id: String) throws -> Item {
        let p = try decoder().decode(ItemPayload.self, from: data)
        guard p.v == 1 else { throw VaultError.unsupportedPayloadVersion(p.v) }
        return Item(id: id, type: p.type, title: p.title, urls: p.urls, username: p.username, password: p.password,
                    totp: p.totp, notes: p.notes, fields: p.fields, tags: p.tags,
                    createdAt: p.createdAt, updatedAt: p.updatedAt, passkey: p.passkey)
    }
}

public enum VaultError: Error, Sendable, Equatable {
    case locked
    case notFound(String)
    case unsupportedPayloadVersion(Int)
    case notConfigured
    case alreadyConfigured
    case noTOTP
    case needsUnlockToResolveConflict(String)
    case badBackup(String)
}
