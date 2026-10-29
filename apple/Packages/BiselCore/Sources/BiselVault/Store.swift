import Foundation
import GRDB
import BiselCrypto

/// Where the local SQLite store lives. Inject any directory for flows; use `appGroup` in apps and
/// extensions so they all open the same file (§7).
public struct StoreLocation: Sendable {
    public let directory: URL
    public init(directory: URL) { self.directory = directory }
    public var databaseURL: URL { directory.appendingPathComponent("bisel.sqlite") }

    /// App Group container (`<TEAMID>.app.bisel` on macOS, `group.app.bisel` on iOS).
    public static func appGroup(identifier: String) throws -> StoreLocation {
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier) else {
            throw StoreError.noAppGroupContainer(identifier)
        }
        return StoreLocation(directory: url.appendingPathComponent("Library/Application Support/bisel", isDirectory: true))
    }
}

public enum StoreError: Error, Sendable, Equatable { case noAppGroupContainer(String) }

/// Ciphertext record exactly as the server holds it, plus local pending state.
public struct StoredRecord: Sendable, Equatable {
    public enum Pending: Int, Sendable { case none = 0, put = 1, delete = 2 }
    public var id: String
    public var rev: Int          // for pending records: baseRev + 1, the revision the blob was sealed for
    public var seq: Int
    public var deleted: Bool
    public var blob: Data
    public var updatedAt: Int    // unix seconds
    public var pending: Pending
    public var baseRev: Int      // revision the server last confirmed (0 = never pushed)

    public init(id: String, rev: Int, seq: Int, deleted: Bool, blob: Data, updatedAt: Int,
                pending: Pending = .none, baseRev: Int = 0) {
        self.id = id; self.rev = rev; self.seq = seq; self.deleted = deleted; self.blob = blob
        self.updatedAt = updatedAt; self.pending = pending; self.baseRev = baseRev
    }

    init(row: Row) {
        self.init(id: row["id"], rev: row["rev"], seq: row["seq"], deleted: row["deleted"], blob: row["blob"],
                  updatedAt: row["updated_at"], pending: Pending(rawValue: row["pending"]) ?? .none, baseRev: row["base_rev"])
    }
}

/// Everything this device persists about itself besides keys.
public struct LocalIdentity: Codable, Sendable, Equatable {
    public var deviceID: String
    public var deviceName: String
    public var serverURL: URL
    public var keyStore: String
    /// nil while an enrollment is waiting for approval.
    public var envelope: Data?
    public var recoveryPublicKey: Data?
    public var recoveryEnvelope: Data?
    public init(deviceID: String, deviceName: String, serverURL: URL, keyStore: String, envelope: Data? = nil,
                recoveryPublicKey: Data? = nil, recoveryEnvelope: Data? = nil) {
        self.deviceID = deviceID; self.deviceName = deviceName; self.serverURL = serverURL; self.keyStore = keyStore
        self.envelope = envelope; self.recoveryPublicKey = recoveryPublicKey; self.recoveryEnvelope = recoveryEnvelope
    }
}

/// SQLite (GRDB) store of ciphertext records and the sync cursor. Holds no key material.
public final class LocalStore: Sendable {
    private let pool: DatabasePool

    public init(location: StoreLocation) throws {
        try FileManager.default.createDirectory(at: location.directory, withIntermediateDirectories: true)
        var config = Configuration()
        config.busyMode = .timeout(5)       // the app and its extensions share this file
        pool = try DatabasePool(path: location.databaseURL.path, configuration: config)
        var migrator = DatabaseMigrator()
        migrator.registerMigration("v1") { db in
            try db.create(table: "records") { t in
                t.primaryKey("id", .text)
                t.column("rev", .integer).notNull()
                t.column("seq", .integer).notNull()
                t.column("deleted", .boolean).notNull()
                t.column("blob", .blob).notNull()
                t.column("updated_at", .integer).notNull()
                t.column("pending", .integer).notNull().defaults(to: 0)
                t.column("base_rev", .integer).notNull().defaults(to: 0)
            }
            try db.create(table: "meta") { t in
                t.primaryKey("key", .text)
                t.column("value", .blob).notNull()
            }
        }
        try migrator.migrate(pool)
    }

    // MARK: meta

    private func getMeta(_ key: String) throws -> Data? {
        try pool.read { try Data.fetchOne($0, sql: "SELECT value FROM meta WHERE key = ?", arguments: [key]) }
    }

    private func setMeta(_ key: String, _ value: Data) throws {
        try pool.write { try $0.execute(sql: "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", arguments: [key, value]) }
    }

    public func identity() throws -> LocalIdentity? {
        try getMeta("identity").map { try JSONDecoder().decode(LocalIdentity.self, from: $0) }
    }

    public func setIdentity(_ identity: LocalIdentity) throws {
        try setMeta("identity", try JSONEncoder().encode(identity))
    }

    public func cursor() throws -> Int {
        try getMeta("cursor").flatMap { Int(String(decoding: $0, as: UTF8.self)) } ?? 0
    }

    public func setCursor(_ seq: Int) throws { try setMeta("cursor", Data(String(seq).utf8)) }

    public func deviceListJSON() throws -> Data? { try getMeta("devices") }
    public func setDeviceListJSON(_ json: Data) throws { try setMeta("devices", json) }

    // MARK: records

    public func record(_ id: String) throws -> StoredRecord? {
        try pool.read { db in try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [id]).map(StoredRecord.init(row:)) }
    }

    /// Live (not deleted) records, newest edit first.
    public func liveRecords() throws -> [StoredRecord] {
        try pool.read { db in
            try Row.fetchAll(db, sql: "SELECT * FROM records WHERE deleted = 0 ORDER BY updated_at DESC").map(StoredRecord.init(row:))
        }
    }

    /// All records including tombstones, ordered by seq (what a backup contains).
    public func allRecords() throws -> [StoredRecord] {
        try pool.read { db in try Row.fetchAll(db, sql: "SELECT * FROM records ORDER BY seq, id").map(StoredRecord.init(row:)) }
    }

    public func pendingRecords() throws -> [StoredRecord] {
        try pool.read { db in try Row.fetchAll(db, sql: "SELECT * FROM records WHERE pending != 0 ORDER BY updated_at").map(StoredRecord.init(row:)) }
    }

    /// Records a local edit. `seal` receives the revision the blob will have on the server
    /// (`baseRev + 1`) so the AAD binds the right one. Atomic with the base-revision lookup.
    @discardableResult
    public func commitLocal(id: String, deleted: Bool, now: Date = Date(),
                            seal: (_ rev: Int) throws -> Data) throws -> StoredRecord {
        try pool.write { db in
            let existing = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [id]).map(StoredRecord.init(row:))
            let baseRev = existing.map { $0.pending == .none ? $0.rev : $0.baseRev } ?? 0
            let rev = baseRev + 1
            let record = StoredRecord(id: id, rev: rev, seq: existing?.seq ?? 0, deleted: deleted,
                                      blob: deleted ? Data() : try seal(rev), updatedAt: Int(now.timeIntervalSince1970),
                                      pending: deleted ? .delete : .put, baseRev: baseRev)
            try write(record, db)
            return record
        }
    }

    /// Applies a record received from the server. Pending local edits are never overwritten
    /// (they are resolved at push time). Returns false when the record was stale or skipped.
    @discardableResult
    public func applyRemote(_ r: StoredRecord) throws -> Bool {
        try pool.write { db in
            if let existing = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [r.id]).map(StoredRecord.init(row:)) {
                if existing.pending != .none { return false }
                if existing.rev > r.rev || (existing.rev == r.rev && existing.seq >= r.seq) { return false }
            }
            try write(r, db)
            return true
        }
    }

    /// Marks a pending record as accepted by the server, unless it changed again in the meantime.
    public func confirmPushed(pushed: StoredRecord, server: StoredRecord) throws {
        try pool.write { db in
            guard let cur = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [pushed.id]).map(StoredRecord.init(row:)),
                  cur.pending != .none, cur.blob == pushed.blob, cur.rev == pushed.rev else { return }
            try write(server, db)
        }
    }

    /// Replaces local state with the server's current record (conflict resolution: remote wins).
    public func overwrite(with r: StoredRecord) throws { try pool.write { try write(r, $0) } }

    /// Drops a record that never reached the server (local create followed by local delete).
    public func forget(_ id: String) throws {
        try pool.write { try $0.execute(sql: "DELETE FROM records WHERE id = ?", arguments: [id]) }
    }

    /// Keeps the latest recovery public key / envelope the server reported (needed for backup files).
    public func updateRecovery(_ pubkeyB64: String, _ envelopeB64: String) throws {
        guard var identity = try identity(),
              let pub = Data(base64URLEncoded: pubkeyB64), let env = Data(base64URLEncoded: envelopeB64) else { return }
        if identity.recoveryPublicKey == pub && identity.recoveryEnvelope == env { return }
        identity.recoveryPublicKey = pub
        identity.recoveryEnvelope = env
        try setIdentity(identity)
    }

    public func removeAll() throws {
        try pool.write { db in
            try db.execute(sql: "DELETE FROM records")
            try db.execute(sql: "DELETE FROM meta")
        }
    }

    private func write(_ r: StoredRecord, _ db: Database) throws {
        try db.execute(sql: """
            INSERT OR REPLACE INTO records(id, rev, seq, deleted, blob, updated_at, pending, base_rev)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, arguments: [r.id, r.rev, r.seq, r.deleted, r.blob, r.updatedAt, r.pending.rawValue, r.baseRev])
    }
}
