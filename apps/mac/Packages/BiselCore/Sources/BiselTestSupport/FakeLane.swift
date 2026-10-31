import Foundation
import BiselCrypto
import BiselLane
import BiselSync
import BiselVault

/// An in-memory lane for flow tests: the storage behind one box, and a handle per device.
///
/// Records follow the server's conventions so the same engine flows run against it: a write is compare-and-set on the tag
/// `"<rev>.<order>"`, the order is a counter that only goes up, and a rotation re-wraps every item in one step. It enforces
/// nothing about who may write (a real shared store cannot): that is the verifier's job.
public final class FakeLane: @unchecked Sendable {
    struct Member {
        var info: DeviceInfo
        var envelope: Data?
    }

    struct State {
        var records: [String: LaneRecord] = [:]
        var head = 0
        var epoch = 1
        var members: [Member] = []
        var recovery: RecoveryMaterial?
        var events: [ServerEvent] = []
        var nextEvent = 1
    }

    /// A copy of everything the lane holds: restoring one is the lane being rolled back to an older snapshot.
    public struct Snapshot: Sendable { let state: State }

    private let lock = NSLock()
    private var state = State()
    public let name: String

    public init(name: String = "fake") { self.name = name }

    /// The lane as seen by `deviceID` (nil: a caller with no device yet, as in recovery).
    public func endpoint(deviceID: String?) -> FakeLaneEndpoint { FakeLaneEndpoint(lane: self, deviceID: deviceID) }

    // MARK: what a hostile or failing store can do

    public func snapshot() -> Snapshot { lock.withLock { Snapshot(state: state) } }
    public func restore(_ snapshot: Snapshot) { lock.withLock { state = snapshot.state } }

    /// Loses the newest write, as a store restored from a slightly older point would.
    public func loseNewestWrite() {
        lock.withLock {
            guard let newest = state.records.values.max(by: { $0.order < $1.order }) else { return }
            state.records[newest.id] = nil
            state.head -= 1
        }
    }

    /// Replaces an item with a tombstone carrying a marker nobody sealed, as a store (or a device without the key) can.
    public func forgeDelete(id: String) {
        lock.withLock {
            guard let cur = state.records[id] else { return }
            state.head += 1
            state.records[id] = LaneRecord(kind: .tombstone, id: id, rev: cur.rev + 1, epoch: state.epoch, blob: Data(repeating: 1, count: 32),
                                           tag: Self.tag(rev: cur.rev + 1, order: state.head), order: state.head, updatedAt: Self.now)
        }
    }

    public func record(_ id: String) -> LaneRecord? { lock.withLock { state.records[id] } }
    public func records() -> [LaneRecord] { lock.withLock { state.records.values.sorted { $0.order < $1.order } } }
    public var epoch: Int { lock.withLock { state.epoch } }

    // MARK: shared

    static func tag(rev: Int, order: Int) -> LaneTag { LaneTag("\(rev).\(order)") }
    static var now: Int { Int(Date().timeIntervalSince1970) }

    func withState<T>(_ body: (inout State) throws -> T) rethrows -> T { try lock.withLock { try body(&state) } }
}

public struct FakeLaneEndpoint: BoxLane {
    let lane: FakeLane
    let deviceID: String?

    public var id: LaneID { LaneID("fake:\(lane.name)") }
    public var capabilities: LaneCapabilities { .init(atomicBatch: 0, enforcesExpect: true) }
    public func identity() async throws -> LaneIdentity { LaneIdentity(lane.name) }

    public func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges {
        let from = since.flatMap { Int($0.rawValue) } ?? 0
        return lane.withState { st in
            let page = st.records.values.filter { $0.order > from }.sorted { $0.order < $1.order }
            let slice = Array(page.prefix(limit))
            let meta = LaneMeta(epoch: st.epoch, headSeq: st.head, members: st.members.map(\.info), events: st.events, recovery: st.recovery)
            return LaneChanges(upserts: slice, cursor: LaneCursor(String(slice.last?.order ?? from)), hasMore: page.count > slice.count, meta: meta)
        }
    }

    public func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] {
        lane.withState { st in
            batch.map { w in
                var r = w.record
                if r.epoch != st.epoch { return .rejected(.staleEpoch(serverEpoch: st.epoch)) }
                let current = st.records[r.id]
                switch w.expect {
                case .absent: if current != nil { return .conflict(current: current) }
                case .tag(let t): if current?.tag != t { return .conflict(current: current) }
                case .any: break
                }
                st.head += 1
                r.order = st.head
                r.tag = FakeLane.tag(rev: r.rev, order: st.head)
                r.updatedAt = FakeLane.now
                st.records[r.id] = r
                return .accepted(r)
            }
        }
    }

    // MARK: control

    public func members() async throws -> [DeviceInfo] { lane.withState { $0.members.map(\.info) } }

    public func admit(_ device: WireDevice, admin: AdminSigner) async throws {
        try lane.withState { st in
            if let epoch = device.epoch, epoch != st.epoch { throw RotationError.staleEpoch(serverEpoch: st.epoch) }
            st.members.append(.init(info: DeviceInfo(id: device.id, name: device.name, kind: device.kind, sigPubkey: device.sigPubkey,
                                                     encPubkey: device.encPubkey, createdAt: FakeLane.now),
                                    envelope: device.envelope.flatMap { Data(base64URLEncoded: $0) }))
            FakeLaneEndpoint.log(&st, "approve", device: deviceID, subject: device.id)
        }
    }

    public func revokeDevice(id: String, admin: AdminSigner) async throws {
        lane.withState { st in
            guard let i = st.members.firstIndex(where: { $0.info.id == id }) else { return }
            st.members[i].info.revokedAt = FakeLane.now
            st.members[i].envelope = nil
            FakeLaneEndpoint.log(&st, "revoke", device: deviceID, subject: id)
        }
    }

    public func ownEnvelope() async throws -> (envelope: Data, epoch: Int) {
        try lane.withState { st in
            guard let envelope = st.members.first(where: { $0.info.id == deviceID && !$0.info.isRevoked })?.envelope else { throw SyncError.notFound }
            return (envelope, st.epoch)
        }
    }

    public func rotateRecovery(publicKey: Data, encryptionPublicKey: Data, envelope: Data, epoch: Int, admin: AdminSigner) async throws {
        try lane.withState { st in
            if epoch != st.epoch { throw RotationError.staleEpoch(serverEpoch: st.epoch) }
            st.recovery = RecoveryMaterial(pubkey: publicKey.base64URLEncoded(), encPubkey: encryptionPublicKey.base64URLEncoded(),
                                           envelope: envelope.base64URLEncoded())
            FakeLaneEndpoint.log(&st, "recovery_rotate", device: deviceID, subject: nil)
        }
    }

    public func rotate(baseEpoch: Int, baseSeq: Int, revoke: String?, newAdminPublicKey: Data,
                       items: [(id: String, rev: Int, wrappedKey: Data)], tombstones: [(id: String, rev: Int, marker: Data)],
                       devices: [(id: String, envelope: Data)], recoveryEnvelope: Data, admin: AdminSigner) async throws -> RotateOutcome {
        lane.withState { st in
            guard baseEpoch == st.epoch, baseSeq == st.head,
                  items.allSatisfy({ st.records[$0.id]?.rev == $0.rev && st.records[$0.id]?.kind != .tombstone }),
                  tombstones.allSatisfy({ st.records[$0.id]?.rev == $0.rev && st.records[$0.id]?.kind == .tombstone })
            else { return .conflict(epoch: st.epoch, headSeq: st.head) }
            st.epoch += 1
            for item in items {
                guard var r = st.records[item.id] else { continue }
                st.head += 1
                r.blob = item.wrappedKey + r.blob.dropFirst(ItemSealer.wrappedKeyLength)
                r.order = st.head; r.tag = FakeLane.tag(rev: r.rev, order: st.head); r.epoch = st.epoch
                st.records[item.id] = r
            }
            for tomb in tombstones {
                guard var r = st.records[tomb.id] else { continue }
                st.head += 1
                r.blob = tomb.marker
                r.order = st.head; r.tag = FakeLane.tag(rev: r.rev, order: st.head); r.epoch = st.epoch
                st.records[tomb.id] = r
            }
            for i in st.members.indices {
                let m = st.members[i].info
                if m.id == revoke { st.members[i].info.revokedAt = FakeLane.now; st.members[i].envelope = nil }
                else if let d = devices.first(where: { $0.id == m.id }) { st.members[i].envelope = d.envelope }
            }
            if var recovery = st.recovery { recovery.envelope = recoveryEnvelope.base64URLEncoded(); st.recovery = recovery }
            FakeLaneEndpoint.log(&st, "rotate", device: deviceID, subject: revoke)
            return .rotated(epoch: st.epoch, headSeq: st.head)
        }
    }

    public func recoveryEnvelope() async throws -> (envelope: Data, epoch: Int) {
        try lane.withState { st in
            guard let envelope = st.recovery.flatMap({ Data(base64URLEncoded: $0.envelope) }) else { throw SyncError.notAuthorized }
            return (envelope, st.epoch)
        }
    }

    public func recoveryRegister(device: WireDevice, epoch: Int) async throws -> Date? {
        try lane.withState { st in
            if epoch != st.epoch { throw RotationError.staleEpoch(serverEpoch: st.epoch) }
            st.members.append(.init(info: DeviceInfo(id: device.id, name: device.name, kind: device.kind, sigPubkey: device.sigPubkey,
                                                     encPubkey: device.encPubkey, createdAt: FakeLane.now),
                                    envelope: device.envelope.flatMap { Data(base64URLEncoded: $0) }))
            FakeLaneEndpoint.log(&st, "recovery", device: device.id, subject: device.id)
            return nil
        }
    }

    public func create(_ box: NewBox) async throws -> SyncClient.BootstrapResult {
        lane.withState { st in
            st.members = [.init(info: DeviceInfo(id: box.device.id, name: box.device.name, kind: box.device.kind, sigPubkey: box.device.sigPubkey,
                                                 encPubkey: box.device.encPubkey, createdAt: FakeLane.now),
                                envelope: box.device.envelope.flatMap { Data(base64URLEncoded: $0) })]
            st.recovery = RecoveryMaterial(pubkey: box.recoveryPublicKey.base64URLEncoded(), encPubkey: box.recoveryEncryptionPublicKey.base64URLEncoded(),
                                           envelope: box.recoveryEnvelope.base64URLEncoded())
            FakeLaneEndpoint.log(&st, "bootstrap", device: box.device.id, subject: box.device.id)
            return SyncClient.BootstrapResult(deviceID: box.device.id, boxID: nil, headSeq: st.head, epoch: st.epoch)
        }
    }

    private static func log(_ st: inout FakeLane.State, _ type: String, device: String?, subject: String?) {
        st.events.append(ServerEvent(id: st.nextEvent, ts: FakeLane.now, deviceId: device, type: type, subjectId: subject))
        st.nextEvent += 1
    }
}
