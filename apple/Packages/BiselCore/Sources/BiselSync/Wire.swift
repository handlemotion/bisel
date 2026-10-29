import Foundation
import BiselCrypto
import BiselVault

/// Wire types for SPEC §6 / server/README.md. Binary values travel as unpadded base64url strings.
public struct WireDevice: Codable, Sendable, Equatable {
    public var id: String
    public var name: String
    public var kind: String
    public var sigPubkey: String
    public var encPubkey: String
    public var envelope: String?
    /// Epoch of the vault key `envelope` was built from. Sent when approving a device; the server refuses a stale one.
    public var epoch: Int?

    public init(id: String, name: String, kind: String, sigPubkey: Data, encPubkey: Data, envelope: Data?, epoch: Int? = nil) {
        self.id = id; self.name = name; self.kind = kind
        self.sigPubkey = sigPubkey.base64URLEncoded(); self.encPubkey = encPubkey.base64URLEncoded()
        self.envelope = envelope?.base64URLEncoded()
        self.epoch = epoch
    }
}

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
    public var isRevoked: Bool { revokedAt != nil }
}

struct WireItem: Codable, Sendable {
    var id: String
    var rev: Int
    var seq: Int
    var deleted: Bool
    var blob: String
    var updatedAt: Int

    var record: StoredRecord? {
        guard let blob = Data(base64URLEncoded: blob) else { return nil }
        return StoredRecord(id: id, rev: rev, seq: seq, deleted: deleted, blob: blob, updatedAt: updatedAt)
    }
}

public struct RecoveryMaterial: Codable, Sendable, Equatable {
    public var alg: String
    public var pubkey: String
    /// X25519 key the recovery envelope is sealed to. Empty on servers that predate rotation.
    public var encPubkey: String?
    public var envelope: String
}

struct SyncPageWire: Codable, Sendable {
    var items: [WireItem]
    var hasMore: Bool
    var nextSince: Int
    var headSeq: Int
    var epoch: Int
    var devices: [DeviceInfo]
    var recovery: RecoveryMaterial?
}

struct ItemResponse: Codable { var item: WireItem }
struct ConflictResponse: Codable { var error: String; var current: WireItem?; var epoch: Int?; var headSeq: Int? }
struct DevicesResponse: Codable { var devices: [DeviceInfo] }
struct EnvelopeResponse: Codable { var deviceId: String; var envelope: String; var epoch: Int }
struct BootstrapRequest: Codable { var device: WireDevice; var recoveryPubkey: String; var recoveryEncPubkey: String; var recoveryEnvelope: String }
struct PutRequest: Codable { var baseRev: Int; var epoch: Int; var blob: String }
struct RecoveryRotateRequest: Codable { var recoveryPubkey: String; var recoveryEncPubkey: String; var recoveryEnvelope: String; var epoch: Int }
struct RecoverySessionRequest: Codable { var device: WireDevice; var epoch: Int }
struct RecoverySessionResponse: Codable { var recoveryEnvelope: String; var headSeq: Int; var epoch: Int }

struct RotateItemWire: Codable { var id: String; var rev: Int; var key: String }
struct RotateDeviceWire: Codable { var id: String; var envelope: String }
struct RotateRequest: Codable {
    var baseEpoch: Int
    var baseSeq: Int
    var revoke: String?
    var items: [RotateItemWire]
    var devices: [RotateDeviceWire]
    var recoveryEnvelope: String

    // The server's schema expects `revoke` to be present (null = rotate only).
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(baseEpoch, forKey: .baseEpoch)
        try c.encode(baseSeq, forKey: .baseSeq)
        try c.encode(revoke, forKey: .revoke)
        try c.encode(items, forKey: .items)
        try c.encode(devices, forKey: .devices)
        try c.encode(recoveryEnvelope, forKey: .recoveryEnvelope)
    }
}
struct RotateResponse: Codable { var epoch: Int; var headSeq: Int }
