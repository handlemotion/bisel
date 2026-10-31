import Foundation
import BiselLane

/// The person's iCloud for flow tests: one private database per Apple Account, a `FakeLane` per box in it, at `fakehome://icloud/<zone>`.
/// It can sign out, switch to another account (whose database knows nothing of the first one's boxes), go offline, fill up,
/// or be off for the app, so every first-run and account path runs without CloudKit.
public final class FakeHome: BoxHome, @unchecked Sendable {
    public enum Account: Sendable, Equatable { case first, second, signedOut }

    private let lock = NSLock()
    private var account = Account.first
    /// Per account, the stores by zone.
    private var stores: [Account: [String: FakeLane]] = [:]
    private var routes: [String: HomeLane] = [:]
    private var refusal: HomeUnavailable?
    private var full = false
    private var counter = 0

    public init() {}

    // MARK: what a test does to it

    public func signIn(_ account: Account) { lock.withLock { self.account = account } }
    /// Reported by `availability()` and thrown by every call to its storage (`.offline` as a dropped connection would be).
    public func refuse(_ reason: HomeUnavailable?) { lock.withLock { refusal = reason } }
    /// The account's storage is full: every write is rejected with `.quota`, as CloudKit's `quotaExceeded`.
    public func fill(_ on: Bool) { lock.withLock { full = on } }

    /// The store of `zone` on `account` (made empty if it never existed).
    public func store(_ zone: String, on account: Account = .first) -> FakeLane {
        lock.withLock { store(zone, account) }
    }

    private func store(_ zone: String, _ account: Account) -> FakeLane {
        if let made = stores[account]?[zone] { return made }
        let made = FakeLane(name: "\(account)-\(zone)")
        stores[account, default: [:]][zone] = made
        return made
    }

    /// The lane provider a test vault is built with: this home's addresses go to its storage, as the app's `CloudBox.provider`.
    public var laneProvider: @Sendable (URL?) -> (any SyncLane)? { { [weak self] url in url.flatMap { self?.lane($0) } } }

    // MARK: BoxHome

    public static let scheme = "fakehome"

    public func availability() async -> HomeAvailability {
        lock.withLock {
            if account == .signedOut { return .unavailable(.notSignedIn) }
            if let refusal { return .unavailable(refusal) }
            return .available
        }
    }

    public func boxes() async throws -> [URL] {
        let (account, refusal, all) = lock.withLock { (account, refusal, stores[account] ?? [:]) }
        if account == .signedOut { throw LaneError.accountUnavailable("no iCloud account") }
        if let refusal { throw Self.error(for: refusal) }
        return all.filter { !$0.value.records().isEmpty }.keys.sorted().map(Self.address(zone:))
    }

    public func newAddress() -> URL {
        lock.withLock { counter += 1; return Self.address(zone: "box-\(counter)-\(UUID().uuidString.prefix(8))") }
    }

    public func lane(_ address: URL) -> (any SyncLane)? {
        guard address.scheme == Self.scheme, address.host == "icloud" else { return nil }
        let zone = address.lastPathComponent
        return lock.withLock {
            if let route = routes[zone] { return route }
            let route = HomeLane(home: self, zone: zone)
            routes[zone] = route
            return route
        }
    }

    public func classify(_ error: any Error) -> HomeUnavailable? {
        if case LaneError.accountUnavailable = error { return .notSignedIn }
        if let refused = error as? Refused { return refused.reason }
        return nil
    }

    static func address(zone: String) -> URL { URL(string: "\(scheme)://icloud/\(zone)")! }

    struct Refused: Error { let reason: HomeUnavailable }
    static func error(for reason: HomeUnavailable) -> any Error { Refused(reason: reason) }

    /// The storage of `zone` as this Mac reaches it right now: the signed-in account's, or an error.
    fileprivate func current(_ zone: String) throws -> (lane: FakeLane, account: Account, full: Bool) {
        try lock.withLock {
            if account == .signedOut { throw LaneError.accountUnavailable("no iCloud account") }
            if let refusal { throw Self.error(for: refusal) }
            return (store(zone, account), account, full)
        }
    }
}

/// One box's address in a `FakeHome`: whatever is behind it belongs to the account signed in now, as with a CloudKit zone.
final class HomeLane: SyncLane, @unchecked Sendable {
    private weak var home: FakeHome?
    let zone: String

    init(home: FakeHome, zone: String) { self.home = home; self.zone = zone }

    private func current() throws -> (lane: FakeLane, account: FakeHome.Account, full: Bool) {
        guard let home else { throw LaneError.storeMissing }
        return try home.current(zone)
    }

    var id: LaneID { LaneID("fakehome:\(zone)") }
    var capabilities: LaneCapabilities { .init(atomicBatch: 1000, enforcesExpect: true, repairs: true) }
    func identity() async throws -> LaneIdentity { LaneIdentity("\(try current().account)") }
    func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges { try await current().lane.fetch(since: since, limit: limit) }
    func read(_ refs: [LaneRecordRef]) async throws -> [LaneRecord?] { try await current().lane.read(refs) }
    func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] {
        let c = try current()
        if c.full { return batch.map { _ in .rejected(.quota) } }
        return try await c.lane.write(batch)
    }
    func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult] {
        let c = try current()
        if c.full { return atomic.map { _ in .rejected(.quota) } }
        return try await c.lane.commit(atomic)
    }
    func erase(confirmed: LaneEraseToken) async throws { try await current().lane.erase(confirmed: confirmed) }
    func prepare() async throws { try await current().lane.prepare() }
    func remove(_ refs: [LaneRecordRef]) async throws { try await current().lane.remove(refs) }
}
