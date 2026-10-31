import Foundation
import BiselCrypto
import BiselLane
import BiselVault

/// Wire types for SPEC §6 / apps/server/README.md. Binary values travel as unpadded base64url strings.
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

struct SyncPageWire: Codable, Sendable {
    var items: [WireItem]
    var hasMore: Bool
    var nextSince: Int
    var headSeq: Int
    var epoch: Int
    var devices: [DeviceInfo]
    var events: [ServerEvent]?
    var recovery: RecoveryMaterial?
}

struct HistoryEntryWire: Codable, Sendable {
    var id: Int
    var itemId: String
    var rev: Int
    var kind: String
    var blob: String
    var deleted: Int
    var epoch: Int
    var replacedAt: Int
}
struct HistoryResponse: Codable { var entries: [HistoryEntryWire] }

struct ItemResponse: Codable { var item: WireItem }
struct ConflictResponse: Codable { var error: String; var current: WireItem?; var epoch: Int?; var headSeq: Int? }
struct DevicesResponse: Codable { var devices: [DeviceInfo] }
struct EnvelopeResponse: Codable { var deviceId: String; var envelope: String; var epoch: Int }
struct BootstrapRequest: Codable {
    var device: WireDevice; var recoveryPubkey: String; var recoveryEncPubkey: String; var recoveryEnvelope: String; var adminPubkey: String
}
struct DeleteItemRequest: Codable { var epoch: Int; var marker: String }
struct PutRequest: Codable { var baseRev: Int; var epoch: Int; var blob: String }
struct RecoveryRotateRequest: Codable { var recoveryPubkey: String; var recoveryEncPubkey: String; var recoveryEnvelope: String; var epoch: Int }
struct RecoverySessionRequest: Codable { var device: WireDevice; var epoch: Int }
struct RecoveredDeviceWire: Codable { var id: String; var activatesAt: Int? }
struct RecoverySessionResponse: Codable { var recoveryEnvelope: String; var headSeq: Int; var epoch: Int; var device: RecoveredDeviceWire? }

struct RotateItemWire: Codable { var id: String; var rev: Int; var key: String }
struct RotateDeviceWire: Codable { var id: String; var envelope: String }
struct RotateTombstoneWire: Codable { var id: String; var rev: Int; var marker: String }
struct RotateRequest: Codable {
    var baseEpoch: Int
    var baseSeq: Int
    var revoke: String?
    var newAdminPubkey: String
    var tombstones: [RotateTombstoneWire]
    var items: [RotateItemWire]
    var devices: [RotateDeviceWire]
    var recoveryEnvelope: String

    // The server's schema expects `revoke` to be present (null = rotate only).
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(baseEpoch, forKey: .baseEpoch)
        try c.encode(baseSeq, forKey: .baseSeq)
        try c.encode(revoke, forKey: .revoke)
        try c.encode(newAdminPubkey, forKey: .newAdminPubkey)
        try c.encode(tombstones, forKey: .tombstones)
        try c.encode(items, forKey: .items)
        try c.encode(devices, forKey: .devices)
        try c.encode(recoveryEnvelope, forKey: .recoveryEnvelope)
    }
}
struct RotateResponse: Codable { var epoch: Int; var headSeq: Int }

struct BootstrapResponse: Codable { var deviceId: String; var boxId: String?; var headSeq: Int?; var epoch: Int? }
struct ConnectStartRequest: Codable { var deviceName: String }
struct ConnectPollRequest: Codable { var deviceCode: String }
struct ConnectCodeResponse: Codable { var deviceCode: String; var userCode: String; var verificationUri: String; var expiresIn: Int; var interval: Int }
struct ConnectPollResponse: Codable { var status: String; var accountHasBox: Bool?; var boxId: String? }
