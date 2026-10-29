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

    public init(id: String, name: String, kind: String, sigPubkey: Data, encPubkey: Data, envelope: Data?) {
        self.id = id; self.name = name; self.kind = kind
        self.sigPubkey = sigPubkey.base64URLEncoded(); self.encPubkey = encPubkey.base64URLEncoded()
        self.envelope = envelope?.base64URLEncoded()
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
    public var envelope: String
}

struct SyncPageWire: Codable, Sendable {
    var items: [WireItem]
    var hasMore: Bool
    var nextSince: Int
    var headSeq: Int
    var devices: [DeviceInfo]
    var recovery: RecoveryMaterial?
}

struct ItemResponse: Codable { var item: WireItem }
struct ConflictResponse: Codable { var error: String; var current: WireItem? }
struct DevicesResponse: Codable { var devices: [DeviceInfo] }
struct EnvelopeResponse: Codable { var deviceId: String; var envelope: String }
struct BootstrapRequest: Codable { var device: WireDevice; var recoveryPubkey: String; var recoveryEnvelope: String }
struct PutRequest: Codable { var baseRev: Int; var blob: String }
struct RotateRequest: Codable { var recoveryPubkey: String; var recoveryEnvelope: String }
struct RecoverySessionRequest: Codable { var device: WireDevice }
struct RecoverySessionResponse: Codable { var recoveryEnvelope: String; var headSeq: Int }
