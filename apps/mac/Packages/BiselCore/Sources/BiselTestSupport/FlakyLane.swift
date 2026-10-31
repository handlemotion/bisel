import Foundation
import BiselLane
import BiselSync

/// Any lane, failing on cue: the contract flows wrap every storage lane in one (pass-through until armed), so a rotation the
/// storage stops taking part-way runs the same on `FakeLane` and on CloudKit. Dev/test only.
///
/// Armed with `failWrites(after:silently:)`, it forwards `n` more records (counted per record across `write` and `commit`),
/// then every further write fails: loudly (`SyncError.network`, as a dropped connection) or silently (reported accepted,
/// never stored, as a store that loses writes). A `write` that crosses the line forwards the records before it; a `commit` that
/// would cross it fails whole. Reads, fetches and removes always pass through.
public final class FlakyLane: SyncLane, @unchecked Sendable {
    public let base: any SyncLane
    private let lock = NSLock()
    private var budget: Int?
    private var silent = false

    public init(_ base: any SyncLane) { self.base = base }

    public func failWrites(after n: Int, silently: Bool = false) { lock.withLock { budget = max(n, 0); silent = silently } }
    public func heal() { lock.withLock { budget = nil } }

    public var id: LaneID { base.id }
    public var capabilities: LaneCapabilities { base.capabilities }
    public func identity() async throws -> LaneIdentity { try await base.identity() }
    public func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges { try await base.fetch(since: since, limit: limit) }
    public func read(_ refs: [LaneRecordRef]) async throws -> [LaneRecord?] { try await base.read(refs) }
    public func changes() -> AsyncStream<LaneSignal> { base.changes() }
    public func erase(confirmed: LaneEraseToken) async throws { try await base.erase(confirmed: confirmed) }
    public func prepare() async throws { try await base.prepare() }
    public func remove(_ refs: [LaneRecordRef]) async throws { try await base.remove(refs) }

    /// How many of `count` records may go through, and whether the rest fail silently.
    private func take(_ count: Int, whole: Bool) -> (allowed: Int, silent: Bool) {
        lock.withLock {
            guard let left = budget else { return (count, silent) }
            let allowed = whole ? (count <= left ? count : 0) : min(count, left)
            budget = left - allowed
            return (allowed, silent)
        }
    }

    private static func dropped(_ w: LaneWrite) -> LaneWriteResult {
        var r = w.record
        r.tag = LaneTag("dropped.\(UUID().uuidString)")
        return .accepted(r)
    }

    public func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] {
        let (allowed, silent) = take(batch.count, whole: false)
        var results = allowed > 0 ? try await base.write(Array(batch.prefix(allowed))) : []
        guard allowed < batch.count else { return results }
        if !silent { throw SyncError.network("the lane stopped taking writes") }
        results += batch.dropFirst(allowed).map(Self.dropped)
        return results
    }

    public func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult] {
        let (allowed, silent) = take(atomic.count, whole: true)
        if allowed == atomic.count { return try await base.commit(atomic) }
        if !silent { throw SyncError.network("the lane stopped taking writes") }
        return atomic.map(Self.dropped)
    }
}
