import Foundation
import BiselCrypto
import BiselLane
import BiselVault

/// What a lane needs to offer beyond records: the control operations of a box (members, admitting and revoking a device,
/// the key rotation, recovery). `ServerLane` forwards them to the server's endpoints; a record-based lane implements them
/// as signed control records (docs/SYNC-LANES.md §2, §4, §5).
public protocol BoxLane: SyncLane {
    func members() async throws -> [DeviceInfo]
    /// Seals nothing itself: `device.envelope` already holds the vault key sealed to the new device.
    func admit(_ device: WireDevice, admin: AdminSigner) async throws
    func revokeDevice(id: String, admin: AdminSigner) async throws
    /// This device's own envelope and the epoch of the vault key inside it.
    func ownEnvelope() async throws -> (envelope: Data, epoch: Int)
    func rotateRecovery(publicKey: Data, encryptionPublicKey: Data, envelope: Data, epoch: Int, admin: AdminSigner) async throws
    func rotate(baseEpoch: Int, baseSeq: Int, revoke: String?, newAdminPublicKey: Data,
                items: [(id: String, rev: Int, wrappedKey: Data)], tombstones: [(id: String, rev: Int, marker: Data)],
                devices: [(id: String, envelope: Data)], recoveryEnvelope: Data, admin: AdminSigner) async throws -> RotateOutcome
    /// Fresh install, recovery step 1: the recovery envelope and its epoch. The lane must have been built to authenticate with the recovery key.
    func recoveryEnvelope() async throws -> (envelope: Data, epoch: Int)
    /// Recovery step 3: registers the replacement device. Returns when it may start syncing (nil = now).
    @discardableResult
    func recoveryRegister(device: WireDevice, epoch: Int) async throws -> Date?
    /// Creates the box on a lane that needs no credential for it. A server box is created through `SyncClient.bootstrap`.
    func create(_ box: NewBox) async throws -> SyncClient.BootstrapResult
}

public extension BoxLane {
    func create(_ box: NewBox) async throws -> SyncClient.BootstrapResult { throw LaneError.unsupported }
}

/// Everything a lane stores when a box is created: the first device and the recovery material.
public struct NewBox: Sendable {
    public var device: WireDevice
    public var recoveryPublicKey: Data
    public var recoveryEncryptionPublicKey: Data
    public var recoveryEnvelope: Data
    public var adminPublicKey: Data
    public init(device: WireDevice, recoveryPublicKey: Data, recoveryEncryptionPublicKey: Data, recoveryEnvelope: Data, adminPublicKey: Data) {
        self.device = device; self.recoveryPublicKey = recoveryPublicKey; self.recoveryEncryptionPublicKey = recoveryEncryptionPublicKey
        self.recoveryEnvelope = recoveryEnvelope; self.adminPublicKey = adminPublicKey
    }
}

/// The Bisel server as a lane: `SyncClient` with the wire format untouched.
///
/// Tags are `"<rev>.<seq>"`: the server compare-and-sets on the revision the writer last saw, so the revision is what an
/// `expect: .tag` turns into.
public struct ServerLane: BoxLane {
    public let client: SyncClient
    let boxID: String?
    /// The vault key, for the admin signature the server wants on writes to the manifest. nil while locked.
    let vaultKey: @Sendable () -> LockedKey?
    /// The newest event this device has shown; the server only sends later ones.
    let eventsSince: Int?

    public init(client: SyncClient, boxID: String?, eventsSince: Int? = nil, vaultKey: @escaping @Sendable () -> LockedKey? = { nil }) {
        self.client = client; self.boxID = boxID; self.eventsSince = eventsSince; self.vaultKey = vaultKey
    }

    public var id: LaneID { LaneID("server:\(client.baseURL.host ?? "-"):\(boxID ?? "-")") }
    public var capabilities: LaneCapabilities { .init(atomicBatch: 0, enforcesExpect: true, history: true, perDeviceAuth: true) }
    public func identity() async throws -> LaneIdentity { LaneIdentity(boxID ?? "-") }

    public func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges {
        let from = since.flatMap { Int($0.rawValue) } ?? 0
        let page = try await client.pull(since: from, limit: limit, eventsSince: eventsSince)
        return LaneChanges(upserts: page.records.map(Self.laneRecord), cursor: LaneCursor(String(page.nextSince)), hasMore: page.hasMore,
                           meta: LaneMeta(epoch: page.epoch, headSeq: page.headSeq, members: page.devices, events: page.events, recovery: page.recovery))
    }

    public func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] {
        var results: [LaneWriteResult] = []
        for w in batch {
            let r = w.record
            var admin: AdminSigner?
            if r.kind == .manifest {
                // Without the vault key the manifest cannot be signed for: the engine keeps it pending until the next unlocked sync.
                guard let vk = vaultKey() else { throw SyncError.server(status: 403, code: "admin_signature_required") }
                var raw = try vk.rawBytes()
                defer { raw.zeroize() }
                admin = try AdminSigner(vaultKey: raw)
            }
            let baseRev: Int
            switch w.expect {
            case .absent: baseRev = 0
            case .tag(let t): baseRev = Self.rev(of: t)
            case .any: baseRev = 0
            }
            let outcome = r.kind == .tombstone
                ? try await client.delete(id: r.id, baseRev: baseRev, marker: r.blob, epoch: r.epoch, admin: admin)
                : try await client.put(id: r.id, baseRev: baseRev, blob: r.blob, epoch: r.epoch, admin: admin)
            switch outcome {
            case .accepted(let rec): results.append(.accepted(Self.laneRecord(rec)))
            case .conflict(let current): results.append(.conflict(current: current.map(Self.laneRecord)))
            case .staleEpoch(let serverEpoch): results.append(.rejected(.staleEpoch(serverEpoch: serverEpoch)))
            }
        }
        return results
    }

    // MARK: control, as the server's endpoints

    public func members() async throws -> [DeviceInfo] { try await client.devices() }
    public func admit(_ device: WireDevice, admin: AdminSigner) async throws { try await client.addDevice(device, admin: admin) }
    public func revokeDevice(id: String, admin: AdminSigner) async throws { try await client.revokeDevice(id: id, admin: admin) }
    public func ownEnvelope() async throws -> (envelope: Data, epoch: Int) { try await client.envelope() }
    public func rotateRecovery(publicKey: Data, encryptionPublicKey: Data, envelope: Data, epoch: Int, admin: AdminSigner) async throws {
        try await client.rotateRecovery(publicKey: publicKey, encryptionPublicKey: encryptionPublicKey, envelope: envelope, epoch: epoch, admin: admin)
    }
    public func rotate(baseEpoch: Int, baseSeq: Int, revoke: String?, newAdminPublicKey: Data,
                       items: [(id: String, rev: Int, wrappedKey: Data)], tombstones: [(id: String, rev: Int, marker: Data)],
                       devices: [(id: String, envelope: Data)], recoveryEnvelope: Data, admin: AdminSigner) async throws -> RotateOutcome {
        try await client.rotate(baseEpoch: baseEpoch, baseSeq: baseSeq, revoke: revoke, newAdminPublicKey: newAdminPublicKey, items: items,
                                tombstones: tombstones, devices: devices, recoveryEnvelope: recoveryEnvelope, admin: admin)
    }
    public func recoveryEnvelope() async throws -> (envelope: Data, epoch: Int) { try await client.recoveryEnvelope() }
    public func recoveryRegister(device: WireDevice, epoch: Int) async throws -> Date? { try await client.recoveryRegister(device: device, epoch: epoch) }

    // MARK: record mapping

    /// The revision a tag of this lane stands for.
    static func rev(of tag: LaneTag) -> Int { Int(tag.rawValue.split(separator: ".").first ?? "") ?? 0 }
    static func tag(_ r: StoredRecord) -> LaneTag { LaneTag("\(r.rev).\(r.seq)") }

    static func laneRecord(_ r: StoredRecord) -> LaneRecord {
        let kind: LaneKind = r.deleted ? .tombstone : (r.id == ReservedRecord.manifestID ? .manifest : .item)
        return LaneRecord(kind: kind, id: r.id, rev: r.rev, epoch: 0, blob: r.blob, tag: tag(r), order: r.seq, updatedAt: r.updatedAt)
    }
}
