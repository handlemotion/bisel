#if BISEL_SOFTWARE_KEYS
import Foundation
import SQLite3
import BiselCore
import BiselTestSupport

/// Where a contract flow runs: the real server (`wrangler dev`, local D1), or a lane that is only storage, wrapped in a
/// `RecordBox` the way the app wraps it.
public enum ContractLane: Sendable {
    case server
    /// Made fresh for each flow and closed after it.
    case storage(@Sendable () async throws -> StorageUnderTest)

    public static var fake: ContractLane { .storage { .fake() } }
}

/// A lane that is only storage, plus the one way of losing a record it can be made to do.
public struct StorageUnderTest: Sendable {
    public let name: String
    public let lane: any SyncLane
    /// Set when the storage is the in-memory fake: the hostile flows drive it directly.
    public let fake: FakeLane?
    /// The store loses a record (the fake: silently; CloudKit: a hard delete, which it then reports).
    public let lose: @Sendable (_ id: String) async throws -> Void
    /// Tears the storage down after the flow (CloudKit: deletes the zone).
    public let close: @Sendable () async throws -> Void
    /// Another, independent store of the same kind (CloudKit: another zone), for flows that need a second one: the storage of a
    /// different account, the target of a migration. Closed with this one.
    public let sibling: @Sendable (_ suffix: String) async throws -> StorageUnderTest

    public init(name: String, lane: any SyncLane, fake: FakeLane? = nil, lose: @escaping @Sendable (String) async throws -> Void,
                close: @escaping @Sendable () async throws -> Void = {},
                sibling: @escaping @Sendable (String) async throws -> StorageUnderTest) {
        self.name = name; self.lane = lane; self.fake = fake; self.lose = lose; self.close = close; self.sibling = sibling
    }

    public static func fake(_ name: String = "fake") -> StorageUnderTest {
        let fake = FakeLane(name: name)
        return StorageUnderTest(name: name, lane: fake, fake: fake, lose: { fake.dropSilently($0) }, sibling: { .fake("\(name)-\($0)") })
    }
}

/// One box on one lane, plus what a hostile or failing store can do to it.
public final class Rig: @unchecked Sendable {
    public let server: TestServer?
    public let storage: StorageUnderTest?
    public var fake: FakeLane? { storage?.fake }
    public var address: URL { server?.url ?? Self.address(of: storage?.name ?? "box") }
    /// The storage as the devices reach it: behind the account a Mac is signed in to (`AccountLane`), so a flow can sign out or
    /// switch accounts on any storage.
    public let account: AccountLane?
    /// Whether a flow that moves a box may start the real server as where the box comes from (the flow tests can, the signed
    /// CloudKit run cannot: there the box comes from another store instead).
    let serverForMoves: Bool

    private let lock = NSLock()
    /// Storage the devices can reach, by the host of its `lane://` address.
    private var lanes: [String: any SyncLane] = [:]
    /// Further stores made during the flow, closed with it.
    private let extra = Stores()

    init(server: TestServer?, storage: StorageUnderTest?, serverForMoves: Bool = false) {
        self.server = server; self.storage = storage; self.serverForMoves = serverForMoves
        guard let storage else { account = nil; return }
        let extra = extra
        let account = AccountLane(storage.lane, second: {
            let other = try await storage.sibling("acct2")
            extra.keep(other)
            return other.lane
        })
        self.account = account
        lanes[Self.host(storage.name)] = account
    }

    static func address(of name: String) -> URL { URL(string: "lane://\(host(name))")! }
    static func host(_ name: String) -> String { name.lowercased().replacingOccurrences(of: "_", with: "-") }

    /// Another store the devices can reach at the returned address (the source or target of a move).
    public func addStorage(_ suffix: String) async throws -> URL {
        guard let storage else { throw TestServer.Failure.didNotStart("this rig has no storage") }
        let made = try await storage.sibling(suffix)
        extra.keep(made)
        lock.withLock { lanes[Self.host(made.name)] = made.lane }
        return Self.address(of: made.name)
    }

    static func with<T>(_ lane: ContractLane, serverForMoves: Bool = false, _ body: (Rig) async throws -> T) async throws -> T {
        switch lane {
        case .server: return try await TestServer.with { try await body(Rig(server: $0, storage: nil)) }
        case .storage(let make):
            let storage = try await make()
            let rig = Rig(server: nil, storage: storage, serverForMoves: serverForMoves)
            func closeAll() async throws {
                for s in rig.extra.all { try? await s.close() }
                try await storage.close()
            }
            do {
                let out = try await body(rig)
                try await closeAll()
                return out
            } catch {
                try? await closeAll()
                throw error
            }
        }
    }

    public func device(_ name: String) throws -> Device {
        guard storage != nil else { return try Device(name) }
        // A device syncs through whichever of the rig's stores its address names, and with the server otherwise.
        return try Device(name, laneProvider: { [self] id, _ in
            guard let url = id.serverURL, url.scheme == "lane", let host = url.host else { return nil }
            return lock.withLock { lanes[host] }
        })
    }

    /// Where a box comes from in a move: the real server when this run can start one, another store otherwise.
    public func withMoveSource(_ body: (MoveSource) async throws -> Void) async throws {
        if serverForMoves {
            try await TestServer.with { server in try await body(MoveSource(address: server.url, server: server)) }
        } else {
            try await body(MoveSource(address: try await addStorage("source"), server: nil))
        }
    }

    public func bootstrap(_ d: Device) async throws -> RecoveryPhrase {
        if let server { return try await d.bootstrap(server) }
        return try await d.vault.bootstrap(lane: address, deviceName: d.name)
    }

    public func enroll(_ d: Device, through approver: Device) async throws { try await d.enroll(through: approver, address: address) }

    public func recover(_ d: Device, phrase: RecoveryPhrase) async throws {
        if let server { try await d.vault.recover(server: server.url, phrase: phrase, deviceName: d.name, boxID: try server.onlyBoxID()) }
        else if let account { try await d.vault.recover(lane: RecordBox(storage: account, deviceID: nil), address: address, phrase: phrase, deviceName: d.name) }
    }

    /// Everything the lane holds, as `d` sees it.
    public func records(as d: Device, _ c: Checks) async throws -> [StoredRecord] {
        if let storage {
            var out: [LaneRecord] = []
            var cursor: LaneCursor?
            while true {
                let page = try await (account ?? storage.lane).fetch(since: cursor, limit: 200)
                out += page.upserts
                cursor = page.cursor
                if !page.hasMore { break }
            }
            return out.filter(\.isItemLike).sorted { $0.order < $1.order }
                .map { StoredRecord(id: $0.id, rev: $0.rev, seq: $0.order, deleted: $0.kind == .tombstone, blob: $0.blob, updatedAt: $0.updatedAt) }
        }
        let id = try c.require(try await d.vault.identity()?.deviceID)
        return try await d.signedClientFactory(address, id).pull(since: 0).records
    }

    /// The lane forgets its newest write (a restore from a slightly older point). Returns the id it lost.
    @discardableResult
    public func loseNewestWrite(as d: Device, _ c: Checks) async throws -> String {
        if let storage {
            let newest = try c.require(try await records(as: d, c).last, "the lane holds records")
            try await storage.lose(newest.id)
            return newest.id
        }
        let server = try c.require(server)
        let id = try c.require(try server.value("SELECT id FROM items ORDER BY seq DESC LIMIT 1"))
        try server.sql("DELETE FROM items WHERE id = '\(id)'")
        try server.sql("UPDATE boxes SET head_seq = head_seq - 1")
        return id
    }

    /// What the person (and the app) does once a lane has lost a write: the server is noticed by its position going backwards
    /// and healed after the owner has looked; storage that numbers nothing is noticed by a full read.
    /// Storage that admits the loss (CloudKit reports a hard delete even to a read from the start) shows it as `.removed`.
    public func noticeAndHeal(_ d: Device, lost id: String, _ c: Checks) async throws {
        if storage != nil {
            let report = try await d.vault.sync(audit: true)
            let noticed = report.incidents.contains(.lost(count: 1)) || report.incidents.contains(.removed(.init(kind: .item, id: id)))
            c.expect(noticed, "the full read finds the record the lane lost (\(report.incidents))")
            c.expect(report.repaired == 1, "the lost record is uploaded again (repaired \(report.repaired))")
        } else {
            do { _ = try await d.vault.sync(); c.fail("a rolled-back lane must be refused") }
            catch IntegrityError.serverRolledBack {}
            try await d.vault.acknowledgeServerReset()
            c.expect(try await d.vault.sync().pushed >= 1, "the healed lane takes the lost write again")
        }
    }

    /// Someone without the vault key deletes `id`: whatever they write as the marker, it cannot be a sealed one.
    public func forgeDelete(_ id: String, as d: Device, _ c: Checks) async throws {
        if let fake { fake.forgeDelete(id: id); return }
        if let storage {
            let current = try c.require(try await storage.lane.read([LaneRecordRef(kind: .item, id: id)]).first ?? nil, "the item is on the lane")
            let forged = LaneRecord(kind: .tombstone, id: id, rev: current.rev + 1, epoch: current.epoch, blob: Data(repeating: 1, count: 32))
            guard case .accepted = try await storage.lane.write([LaneWrite(record: forged, expect: .any)])[0] else {
                c.fail("the storage refused the forged delete"); return
            }
            return
        }
        let deviceID = try c.require(try await d.vault.identity()?.deviceID)
        let client = d.signedClientFactory(address, deviceID)
        let rev = try c.require(try await client.pull(since: 0).records.first { $0.id == id }).rev
        guard case .accepted = try await client.delete(id: id, baseRev: rev, marker: Data(repeating: 1, count: 32), epoch: 1) else {
            c.fail("the forged delete was refused"); return
        }
    }

    /// Rewrites the device's database as the app before lanes left it: the sync position in `meta`, no lane tables, the
    /// lane migration not yet applied.
    /// A box on a lane that is only storage never had a pre-lane position to keep: it starts reading from the beginning.
    func downgradeToBeforeLanes(_ location: StoreLocation) throws {
        let keepingPosition = server != nil
        var db: OpaquePointer?
        guard sqlite3_open(location.databaseURL.path, &db) == SQLITE_OK else { throw TestServer.Failure.didNotStart("cannot open the database") }
        defer { sqlite3_close(db) }
        let sql = """
            INSERT OR REPLACE INTO meta(key, value) SELECT 'cursor', CAST(\(keepingPosition ? "cursor" : "'0'") AS BLOB) FROM lane_state LIMIT 1;
            INSERT OR REPLACE INTO meta(key, value) SELECT 'head_seq', CAST(\(keepingPosition ? "known_head" : "0") AS BLOB) FROM lane_state LIMIT 1;
            INSERT OR REPLACE INTO meta(key, value) SELECT 'event_cursor', CAST(\(keepingPosition ? "event_cursor" : "0") AS BLOB) FROM lane_state LIMIT 1;
            DROP TABLE lane_ack;
            DROP TABLE lane_state;
            DROP TABLE quarantine;
            DELETE FROM grdb_migrations WHERE identifier IN ('v3-lanes', 'v4-lane-witness');
            """
        var message: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(db, sql, nil, nil, &message) == SQLITE_OK else {
            throw TestServer.Failure.didNotStart("downgrade failed: \(message.map { String(cString: $0) } ?? "?")")
        }
    }
}

/// The lane a box starts on before a flow moves it.
public struct MoveSource: Sendable {
    public let address: URL
    public let server: TestServer?

    public func bootstrap(_ d: Device) async throws -> RecoveryPhrase {
        if let server { return try await d.bootstrap(server) }
        return try await d.vault.bootstrap(lane: address, deviceName: d.name)
    }

    public func enroll(_ d: Device, through approver: Device) async throws { try await d.enroll(through: approver, address: address) }
}

final class Stores: @unchecked Sendable {
    private let lock = NSLock()
    private var list: [StorageUnderTest] = []
    func keep(_ s: StorageUnderTest) { lock.withLock { list.append(s) } }
    var all: [StorageUnderTest] { lock.withLock { list } }
}

/// What a flow found wrong. `expect` records and carries on, `require` records and stops the flow.
public final class Checks: @unchecked Sendable {
    public struct Failure: Sendable, CustomStringConvertible {
        public let message: String
        public let fileID: String
        public let filePath: String
        public let line: Int
        public var description: String { "\(fileID):\(line): \(message)" }
    }
    struct Stop: Error {}

    private let lock = NSLock()
    private var list: [Failure] = []
    public var failures: [Failure] { lock.withLock { list } }

    public func fail(_ message: String, fileID: String = #fileID, filePath: String = #filePath, line: Int = #line) {
        lock.withLock { list.append(Failure(message: message, fileID: fileID, filePath: filePath, line: line)) }
    }

    public func expect(_ ok: Bool, _ message: @autoclosure () -> String, fileID: String = #fileID, filePath: String = #filePath, line: Int = #line) {
        if !ok { fail(message(), fileID: fileID, filePath: filePath, line: line) }
    }

    public func require<T>(_ value: T?, _ message: @autoclosure () -> String = "required value missing",
                           fileID: String = #fileID, filePath: String = #filePath, line: Int = #line) throws -> T {
        guard let value else { fail(message(), fileID: fileID, filePath: filePath, line: line); throw Stop() }
        return value
    }

    public func require(_ ok: Bool, _ message: @autoclosure () -> String, fileID: String = #fileID, filePath: String = #filePath, line: Int = #line) throws {
        if !ok { fail(message(), fileID: fileID, filePath: filePath, line: line); throw Stop() }
    }

    public func expectThrows(_ message: @autoclosure () -> String, fileID: String = #fileID, filePath: String = #filePath, line: Int = #line,
                             _ body: () async throws -> Void) async {
        do { try await body(); fail(message(), fileID: fileID, filePath: filePath, line: line) } catch {}
    }
}
#endif
