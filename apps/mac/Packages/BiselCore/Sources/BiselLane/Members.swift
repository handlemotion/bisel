import Foundation
import BiselCrypto

// Lane-neutral descriptions of a box's devices, recovery material and history. They started as the server's wire types
// and keep their JSON shape, so `ServerLane` decodes them as they are.

/// Device as listed by the server (no envelope).
public struct DeviceInfo: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var kind: String
    public var sigPubkey: String
    public var encPubkey: String
    public var createdAt: Int
    public var lastSeenAt: Int?
    public var revokedAt: Int?
    /// Set while a device registered through the recovery phrase is held back; it cannot sign requests before then.
    public var activatesAt: Int?
    public var isRevoked: Bool { revokedAt != nil }

    public init(id: String, name: String, kind: String, sigPubkey: String, encPubkey: String, createdAt: Int,
                lastSeenAt: Int? = nil, revokedAt: Int? = nil, activatesAt: Int? = nil) {
        self.id = id; self.name = Data.sanitizedName(name); self.kind = kind; self.sigPubkey = sigPubkey; self.encPubkey = encPubkey
        self.createdAt = createdAt; self.lastSeenAt = lastSeenAt; self.revokedAt = revokedAt; self.activatesAt = activatesAt
    }
    public func isPending(at now: Date = Date()) -> Bool { (activatesAt ?? 0) > Int(now.timeIntervalSince1970) && !isRevoked }

    // Names come from the server (and ultimately from other devices): strip control, bidi and separator characters.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = Data.sanitizedName(try c.decode(String.self, forKey: .name))
        kind = try c.decode(String.self, forKey: .kind)
        sigPubkey = try c.decode(String.self, forKey: .sigPubkey)
        encPubkey = try c.decode(String.self, forKey: .encPubkey)
        createdAt = try c.decode(Int.self, forKey: .createdAt)
        lastSeenAt = try c.decodeIfPresent(Int.self, forKey: .lastSeenAt)
        revokedAt = try c.decodeIfPresent(Int.self, forKey: .revokedAt)
        activatesAt = try c.decodeIfPresent(Int.self, forKey: .activatesAt)
    }
}

public struct RecoveryMaterial: Codable, Sendable, Equatable {
    public var alg: String
    public var pubkey: String
    /// X25519 key the recovery envelope is sealed to. Empty on servers that predate rotation.
    public var encPubkey: String?
    public var envelope: String

    public init(alg: String = "ed25519", pubkey: String, encPubkey: String?, envelope: String) {
        self.alg = alg; self.pubkey = pubkey; self.encPubkey = encPubkey; self.envelope = envelope
    }
}

/// Something that happened to the vault on the server: `bootstrap`, `approve`, `revoke`, `rotate`, `recovery`, `recovery_rotate`.
public struct ServerEvent: Codable, Sendable, Equatable, Identifiable {
    public var id: Int
    public var ts: Int
    public var deviceId: String?
    public var type: String
    public var subjectId: String?
    public var date: Date { Date(timeIntervalSince1970: TimeInterval(ts)) }

    public init(id: Int, ts: Int, deviceId: String?, type: String, subjectId: String?) {
        self.id = id; self.ts = ts; self.deviceId = deviceId; self.type = type; self.subjectId = subjectId
    }
}

