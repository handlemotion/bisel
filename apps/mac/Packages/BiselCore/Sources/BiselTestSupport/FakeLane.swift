import Foundation
import BiselLane

/// Storage for flow tests, standing in for a lane that enforces nothing (a CloudKit zone): records by id with a
/// compare-and-set tag, an atomic commit, and nothing else. It does not know what a device, an epoch or a signature is.
/// Wrap it in a `RecordBox` to use it as a box.
///
/// It can also misbehave the ways an untrusted store can (docs/SYNC-LANES.md §7): roll back to an older snapshot, silently
/// lose a record, report a hard delete, replay an old version, serve records out of order, or take a record someone forged.
public final class FakeLane: SyncLane, @unchecked Sendable {
    struct State {
        var records: [String: LaneRecord] = [:]
        var order = 0
        var removed: [LaneRecordRef] = []
        var reordering = false
    }

    /// A copy of everything the lane holds: restoring one is the lane being rolled back to an older snapshot.
    public struct Snapshot: Sendable { let state: State }

    private let lock = NSLock()
    private var state = State()
    public let name: String

    public init(name: String = "fake") { self.name = name }

    public var id: LaneID { LaneID("fake:\(name)") }
    public var capabilities: LaneCapabilities { .init(atomicBatch: 1000, enforcesExpect: true, repairs: true) }
    public func identity() async throws -> LaneIdentity { LaneIdentity(name) }

    public func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges {
        let from = since.flatMap { Int($0.rawValue) } ?? 0
        return lock.withLock {
            let page = state.records.values.filter { $0.order > from }.sorted { $0.order < $1.order }
            var slice = Array(page.prefix(limit))
            let cursor = slice.last?.order ?? from
            if state.reordering { slice.reverse() }
            let removed = state.removed
            state.removed = []
            return LaneChanges(upserts: slice, removed: removed, cursor: LaneCursor(String(cursor)), hasMore: page.count > slice.count)
        }
    }

    public func read(_ refs: [LaneRecordRef]) async throws -> [LaneRecord?] {
        lock.withLock { refs.map { ref in state.records[ref.id].flatMap { $0.kind == ref.kind ? $0 : nil } } }
    }

    public func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] {
        lock.withLock { batch.map { put($0) } }
    }

    public func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult] {
        lock.withLock {
            let failures = atomic.map { check($0) }
            if failures.contains(where: { $0 != nil }) {
                return failures.map { $0.map { .conflict(current: $0.current) } ?? .rejected(.forbidden) }
            }
            return atomic.map { put($0) }
        }
    }

    private func check(_ w: LaneWrite) -> (current: LaneRecord?, Void)? {
        let current = state.records[w.record.id]
        switch w.expect {
        case .absent: return current != nil ? (current, ()) : nil
        case .tag(let t): return current?.tag != t ? (current, ()) : nil
        case .any: return nil
        }
    }

    private func put(_ w: LaneWrite) -> LaneWriteResult {
        if let failure = check(w) { return .conflict(current: failure.current) }
        var r = w.record
        state.order += 1
        r.order = state.order
        r.tag = Self.tag(r, state.order)
        r.updatedAt = Int(Date().timeIntervalSince1970)
        state.records[r.id] = r
        return .accepted(r)
    }

    static func tag(_ r: LaneRecord, _ order: Int) -> LaneTag { LaneTag("\(r.rev).\(order)") }

    // MARK: what the store can see and do to itself

    public func record(_ id: String) -> LaneRecord? { lock.withLock { state.records[id] } }
    public func records() -> [LaneRecord] { lock.withLock { state.records.values.sorted { $0.order < $1.order } } }

    // MARK: how an untrusted store misbehaves

    public func snapshot() -> Snapshot { lock.withLock { Snapshot(state: state) } }
    /// Rolls the whole store back. Its cursor numbering goes back too, so a reader that only asks for what is new sees nothing.
    public func restore(_ snapshot: Snapshot) { lock.withLock { state = snapshot.state } }

    /// Forgets a record without a word.
    public func dropSilently(_ id: String) { lock.withLock { state.records[id] = nil } }

    /// Deletes a record for good and says so on the next fetch (CloudKit reports removed record ids).
    public func hardDelete(_ id: String) {
        lock.withLock {
            guard let r = state.records.removeValue(forKey: id) else { return }
            state.removed.append(LaneRecordRef(kind: r.kind, id: id))
        }
    }

    /// Serves an older copy of a record as if it were new.
    public func replay(_ old: LaneRecord) {
        lock.withLock {
            var r = old
            state.order += 1
            r.order = state.order
            r.tag = Self.tag(r, state.order)
            state.records[r.id] = r
        }
    }

    /// Takes a record exactly as given (a forged control record, or a write by a device the box never approved).
    public func inject(_ record: LaneRecord) { replay(record) }

    /// Within a page, the newest records come first.
    public func setReordering(_ on: Bool) { lock.withLock { state.reordering = on } }

    /// Replaces an item with a tombstone whose marker nobody sealed, as a device without the key can.
    public func forgeDelete(id: String) {
        lock.withLock {
            guard let cur = state.records[id] else { return }
            state.order += 1
            let forged = LaneRecord(kind: .tombstone, id: id, rev: cur.rev + 1, epoch: cur.epoch, blob: Data(repeating: 1, count: 32), order: state.order,
                                    updatedAt: Int(Date().timeIntervalSince1970))
            var r = forged
            r.tag = Self.tag(r, state.order)
            state.records[id] = r
        }
    }
}
