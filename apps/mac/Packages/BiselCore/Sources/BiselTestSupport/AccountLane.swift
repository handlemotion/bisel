import Foundation
import BiselLane

/// Storage as one Mac's iCloud sees it: the account the box was put on, signed out, or another account signed in, whose
/// storage is a different store that knows nothing of the box. It wraps any storage (a `FakeLane`, a CloudKit zone), so the
/// account flows of the lane contract run the same on both. The lane's id (its address) never changes: what changes is who
/// owns what is behind it, which is exactly what `SyncLane.identity()` is there to tell.
public final class AccountLane: SyncLane, @unchecked Sendable {
    public enum Account: Sendable, Equatable { case first, second, signedOut(String) }

    private let first: any SyncLane
    private let makeSecond: @Sendable () async throws -> any SyncLane
    private let lock = NSLock()
    private var account = Account.first
    private var second: (any SyncLane)?

    /// `second` is made the first time the other account is signed in.
    public init(_ first: any SyncLane, second: @escaping @Sendable () async throws -> any SyncLane) {
        self.first = first
        makeSecond = second
    }

    public func signIn(_ account: Account) { lock.withLock { self.account = account } }
    public var signedIn: Account { lock.withLock { account } }

    private func current() async throws -> any SyncLane {
        switch lock.withLock({ account }) {
        case .first: return first
        case .signedOut(let reason): throw LaneError.accountUnavailable(reason)
        case .second:
            if let made = lock.withLock({ second }) { return made }
            let made = try await makeSecond()
            lock.withLock { second = made }
            return made
        }
    }

    public var id: LaneID { first.id }
    public var capabilities: LaneCapabilities { first.capabilities }
    public func identity() async throws -> LaneIdentity {
        let account = lock.withLock { self.account }
        let underlying = try await current().identity()
        return LaneIdentity("\(account == .first ? "first" : "second")/\(underlying.rawValue)")
    }
    public func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges { try await current().fetch(since: since, limit: limit) }
    public func read(_ refs: [LaneRecordRef]) async throws -> [LaneRecord?] { try await current().read(refs) }
    public func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] { try await current().write(batch) }
    public func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult] { try await current().commit(atomic) }
    public func changes() -> AsyncStream<LaneSignal> { first.changes() }
    public func erase(confirmed: LaneEraseToken) async throws { try await current().erase(confirmed: confirmed) }
    public func prepare() async throws { try await current().prepare() }
    public func remove(_ refs: [LaneRecordRef]) async throws { try await current().remove(refs) }
}
