import Foundation
import GRDB
import BiselCrypto
import BiselKeyStore

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

public enum StoreError: Error, Sendable, Equatable { case noAppGroupContainer(String), serverAddressMissing }

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
    /// A tombstone from the server counts only once its sealed marker verified under VK (`.unverified` until then).
    public var tombstone: TombstoneState

    public enum TombstoneState: Int, Sendable { case verified = 1, unverified = 0, rejected = 2 }

    public init(id: String, rev: Int, seq: Int, deleted: Bool, blob: Data, updatedAt: Int,
                pending: Pending = .none, baseRev: Int = 0, tombstone: TombstoneState = .verified) {
        self.id = id; self.rev = rev; self.seq = seq; self.deleted = deleted; self.blob = blob
        self.updatedAt = updatedAt; self.pending = pending; self.baseRev = baseRev; self.tombstone = tombstone
    }

    init(row: Row) {
        self.init(id: row["id"], rev: row["rev"], seq: row["seq"], deleted: row["deleted"], blob: row["blob"],
                  updatedAt: row["updated_at"], pending: Pending(rawValue: row["pending"]) ?? .none, baseRev: row["base_rev"],
                  tombstone: TombstoneState(rawValue: row["tomb_ok"]) ?? .verified)
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
    /// Recovery material as last reported by the server (needed for backup files and for re-sealing VK on rotation).
    public var recoveryPublicKey: Data?
    public var recoveryEnvelope: Data?
    /// X25519 key the recovery envelope is sealed to (derived from the phrase; public).
    public var recoveryEncryptionPublicKey: Data?
    /// Epoch of the vault key `envelope` holds. Moves when any device rotates VK.
    public var epoch: Int
    /// The envelope that held the previous vault key, kept only while local edits made under it still await
    /// re-wrapping (it needs the same biometric unlock as `envelope`, so it protects nothing extra).
    public var previousEnvelope: Data?
    /// Devices this one knows to be the owner's, with their public keys. Written only by bootstrap, approval, recovery,
    /// an explicit `trustDevice`, and the VK-sealed vault manifest. Rotation seals the new vault key only to these.
    public var roster: [RosterEntry] = []
    /// Generation of the recovery keys recorded in `recoveryPublicKey`/`recoveryEncryptionPublicKey`.
    public var recoveryGeneration: Int = 1
    /// True once the recovery keys are pinned (set by this device or taken from the vault manifest). From then on the server cannot change them.
    public var recoveryPinned: Bool = false
    /// The server reported recovery keys that differ from the pinned ones.
    public var recoveryMismatch: Bool = false
    /// The phrase was shown but the user has not proved they wrote it down.
    public var recoveryUnconfirmed: Bool = false
    /// This device was enrolled through another device and the verification code has not been confirmed yet.
    public var enrollmentUnconfirmed: Bool = false
    /// Recovery-registered device: unix time before which the server refuses its requests.
    public var activatesAt: Int?

    public init(deviceID: String, deviceName: String, serverURL: URL, keyStore: String, envelope: Data? = nil,
                recoveryPublicKey: Data? = nil, recoveryEnvelope: Data? = nil,
                recoveryEncryptionPublicKey: Data? = nil, epoch: Int = 1, previousEnvelope: Data? = nil) {
        self.deviceID = deviceID; self.deviceName = deviceName; self.serverURL = serverURL; self.keyStore = keyStore
        self.envelope = envelope; self.recoveryPublicKey = recoveryPublicKey; self.recoveryEnvelope = recoveryEnvelope
        self.recoveryEncryptionPublicKey = recoveryEncryptionPublicKey; self.epoch = epoch
        self.previousEnvelope = previousEnvelope
    }

    // Identities written before rotation existed lack the new keys: decode them with defaults.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        deviceID = try c.decode(String.self, forKey: .deviceID)
        deviceName = try c.decode(String.self, forKey: .deviceName)
        serverURL = try c.decode(URL.self, forKey: .serverURL)
        keyStore = try c.decode(String.self, forKey: .keyStore)
        envelope = try c.decodeIfPresent(Data.self, forKey: .envelope)
        recoveryPublicKey = try c.decodeIfPresent(Data.self, forKey: .recoveryPublicKey)
        recoveryEnvelope = try c.decodeIfPresent(Data.self, forKey: .recoveryEnvelope)
        recoveryEncryptionPublicKey = try c.decodeIfPresent(Data.self, forKey: .recoveryEncryptionPublicKey)
        epoch = try c.decodeIfPresent(Int.self, forKey: .epoch) ?? 1
        previousEnvelope = try c.decodeIfPresent(Data.self, forKey: .previousEnvelope)
        roster = try c.decodeIfPresent([RosterEntry].self, forKey: .roster) ?? []
        recoveryGeneration = try c.decodeIfPresent(Int.self, forKey: .recoveryGeneration) ?? 1
        recoveryPinned = try c.decodeIfPresent(Bool.self, forKey: .recoveryPinned) ?? false
        recoveryMismatch = try c.decodeIfPresent(Bool.self, forKey: .recoveryMismatch) ?? false
        recoveryUnconfirmed = try c.decodeIfPresent(Bool.self, forKey: .recoveryUnconfirmed) ?? false
        enrollmentUnconfirmed = try c.decodeIfPresent(Bool.self, forKey: .enrollmentUnconfirmed) ?? false
        activatesAt = try c.decodeIfPresent(Int.self, forKey: .activatesAt)
    }
}

/// SQLite (GRDB) store of ciphertext records and the sync cursor. Holds no key material.
public final class LocalStore: Sendable {
    private let pool: DatabasePool
    private let secrets: (any SecretStore)?
    private static let serverURLKey = "server-url"
    /// In the database, the server's address is replaced by this marker when a `SecretStore` holds the real one.
    private static let serverURLPlaceholder = URL(string: "bisel-secret://server-url")!

    public init(location: StoreLocation, secrets: (any SecretStore)? = nil) throws {
        self.secrets = secrets
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
        migrator.registerMigration("v2-trash-and-tombstones") { db in
            try db.alter(table: "records") { t in t.add(column: "tomb_ok", .integer).notNull().defaults(to: 1) }
            // Previous contents of records the server overwrote or deleted, kept for 30 days (a forged or mistaken delete is undoable).
            try db.create(table: "trash") { t in
                t.autoIncrementedPrimaryKey("key")
                t.column("id", .text).notNull()
                t.column("rev", .integer).notNull()
                t.column("seq", .integer).notNull()
                t.column("deleted", .boolean).notNull()
                t.column("blob", .blob).notNull()
                t.column("updated_at", .integer).notNull()
                t.column("replaced_at", .integer).notNull()
                t.column("reason", .text).notNull()
            }
            try db.create(index: "trash_id", on: "trash", columns: ["id"])
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
        guard var id = try getMeta("identity").map({ try JSONDecoder().decode(LocalIdentity.self, from: $0) }) else { return nil }
        guard let secrets else { return id }
        if id.serverURL == Self.serverURLPlaceholder {
            guard let data = try secrets.get(Self.serverURLKey), let url = URL(string: String(decoding: data, as: UTF8.self)) else {
                throw StoreError.serverAddressMissing
            }
            id.serverURL = url
        } else {
            try setIdentity(id)   // written before secrets existed: move the address out of the database now
        }
        return id
    }

    public func setIdentity(_ identity: LocalIdentity) throws {
        var stored = identity
        if let secrets {
            try secrets.set(Self.serverURLKey, Data(identity.serverURL.absoluteString.utf8))
            stored.serverURL = Self.serverURLPlaceholder
        }
        try setMeta("identity", try JSONEncoder().encode(stored))
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
    /// (`baseRev + 1`) so the AAD binds the right one (for a delete: the sealed tombstone marker).
    /// Atomic with the base-revision lookup.
    @discardableResult
    public func commitLocal(id: String, deleted: Bool, now: Date = Date(),
                            seal: (_ rev: Int) throws -> Data) throws -> StoredRecord {
        try pool.write { db in
            let existing = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [id]).map(StoredRecord.init(row:))
            let baseRev = existing.map { $0.pending == .none ? $0.rev : $0.baseRev } ?? 0
            let rev = baseRev + 1
            let record = StoredRecord(id: id, rev: rev, seq: existing?.seq ?? 0, deleted: deleted,
                                      blob: try seal(rev), updatedAt: Int(now.timeIntervalSince1970),
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
                // A new revision (or a delete) replaces content this device holds: keep the old ciphertext for 30 days.
                // (Same revision, new seq = a key rotation re-wrapping the item: nothing to keep.)
                if existing.rev != r.rev, !existing.deleted {
                    try trash(existing, reason: r.deleted ? "remote-delete" : "remote-overwrite", db)
                }
            }
            var incoming = r
            incoming.tombstone = r.deleted ? .unverified : .verified   // a delete is honoured only after its marker verified
            try write(incoming, db)
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

    // MARK: trash, tombstone verification, integrity state

    public struct TrashedRecord: Sendable, Equatable {
        public var key: Int
        public var record: StoredRecord
        public var replacedAt: Date
        public var reason: String
    }

    /// Ciphertext the server replaced or deleted, newest first (30 days).
    public func trashedRecords(id: String? = nil) throws -> [TrashedRecord] {
        try pool.read { db in
            let cutoff = Int(Date().timeIntervalSince1970) - Self.trashRetention
            let rows = try Row.fetchAll(db, sql: "SELECT * FROM trash WHERE replaced_at >= ? AND (? IS NULL OR id = ?) ORDER BY key DESC",
                                        arguments: [cutoff, id, id])
            return rows.map { row in
                TrashedRecord(key: row["key"],
                              record: StoredRecord(id: row["id"], rev: row["rev"], seq: row["seq"], deleted: row["deleted"], blob: row["blob"], updatedAt: row["updated_at"]),
                              replacedAt: Date(timeIntervalSince1970: TimeInterval(row["replaced_at"] as Int)), reason: row["reason"])
            }
        }
    }

    public func removeFromTrash(key: Int) throws { try pool.write { try $0.execute(sql: "DELETE FROM trash WHERE key = ?", arguments: [key]) } }

    /// Tombstones that came from the server and have not been checked against their sealed marker yet.
    public func unverifiedTombstones() throws -> [StoredRecord] {
        try pool.read { db in
            try Row.fetchAll(db, sql: "SELECT * FROM records WHERE deleted = 1 AND pending = 0 AND tomb_ok = 0").map(StoredRecord.init(row:))
        }
    }

    public func setTombstoneState(id: String, rev: Int, _ state: StoredRecord.TombstoneState) throws {
        try pool.write { db in
            try db.execute(sql: "UPDATE records SET tomb_ok = ? WHERE id = ? AND rev = ? AND deleted = 1 AND pending = 0", arguments: [state.rawValue, id, rev])
        }
    }

    /// Highest `head_seq` this device has ever seen from the server (rollback detection).
    public func knownHeadSeq() throws -> Int { try getMeta("head_seq").flatMap { Int(String(decoding: $0, as: UTF8.self)) } ?? 0 }
    public func setKnownHeadSeq(_ seq: Int) throws { try setMeta("head_seq", Data(String(seq).utf8)) }

    public func eventCursor() throws -> Int { try getMeta("event_cursor").flatMap { Int(String(decoding: $0, as: UTF8.self)) } ?? 0 }
    public func setEventCursor(_ id: Int) throws { try setMeta("event_cursor", Data(String(id).utf8)) }
    public func recentEventsJSON() throws -> Data? { try getMeta("events") }
    public func setRecentEventsJSON(_ json: Data) throws { try setMeta("events", json) }

    /// Drops a record that never reached the server (local create followed by local delete).
    public func forget(_ id: String) throws {
        try pool.write { try $0.execute(sql: "DELETE FROM records WHERE id = ?", arguments: [id]) }
    }

    /// Keeps the latest recovery public keys / envelope the server reported (needed for backup files and rotation).
    public func updateRecovery(pubkey pubkeyB64: String, encryptionPubkey encB64: String?, envelope envelopeB64: String) throws {
        guard var identity = try identity(),
              let pub = Data(base64URLEncoded: pubkeyB64), let env = Data(base64URLEncoded: envelopeB64) else { return }
        let enc = encB64.flatMap { $0.isEmpty ? nil : Data(base64URLEncoded: $0) }
        if identity.recoveryPinned {
            // The keys were recorded by this vault's own devices: the server may not change them. A different pubkey is
            // reported, not adopted (the envelope is only taken when it belongs to the pinned keys).
            let sameKeys = identity.recoveryPublicKey == pub && (enc == nil || identity.recoveryEncryptionPublicKey == enc)
            if !sameKeys {
                if !identity.recoveryMismatch { identity.recoveryMismatch = true; try setIdentity(identity) }
                return
            }
            if identity.recoveryMismatch { identity.recoveryMismatch = false }
        }
        if identity.recoveryPublicKey == pub && identity.recoveryEnvelope == env
            && (enc == nil || identity.recoveryEncryptionPublicKey == enc) && !identity.recoveryMismatch { return }
        identity.recoveryPublicKey = pub
        identity.recoveryEnvelope = env
        if let enc { identity.recoveryEncryptionPublicKey = enc }
        try setIdentity(identity)
    }

    /// Replaces the sealed blob (item blob, or tombstone marker) of a record that is still pending, used to re-seal local
    /// edits and deletes after a key rotation.
    public func replacePendingBlob(id: String, expectedRev: Int, with blob: Data) throws {
        try pool.write { db in
            try db.execute(sql: "UPDATE records SET blob = ? WHERE id = ? AND rev = ? AND pending != 0",
                           arguments: [blob, id, expectedRev])
        }
    }

    /// Applies a rotation this device performed itself: new blobs and seqs for the rotated records, and the new cursor.
    public func applyRotation(_ records: [StoredRecord], cursor: Int) throws {
        try pool.write { db in
            for r in records { try write(r, db) }
            try db.execute(sql: "INSERT OR REPLACE INTO meta(key, value) VALUES ('cursor', ?)", arguments: [Data(String(cursor).utf8)])
        }
    }

    public func removeAll() throws {
        try? secrets?.delete(Self.serverURLKey)
        try pool.write { db in
            try db.execute(sql: "DELETE FROM records")
            try db.execute(sql: "DELETE FROM trash")
            try db.execute(sql: "DELETE FROM meta")
        }
    }

    private func write(_ r: StoredRecord, _ db: Database) throws {
        try db.execute(sql: """
            INSERT OR REPLACE INTO records(id, rev, seq, deleted, blob, updated_at, pending, base_rev, tomb_ok)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, arguments: [r.id, r.rev, r.seq, r.deleted, r.blob, r.updatedAt, r.pending.rawValue, r.baseRev, r.tombstone.rawValue])
    }

    private func trash(_ r: StoredRecord, reason: String, _ db: Database) throws {
        let now = Int(Date().timeIntervalSince1970)
        try db.execute(sql: """
            INSERT INTO trash(id, rev, seq, deleted, blob, updated_at, replaced_at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, arguments: [r.id, r.rev, r.seq, r.deleted, r.blob, r.updatedAt, now, reason])
        try db.execute(sql: "DELETE FROM trash WHERE replaced_at < ?", arguments: [now - Self.trashRetention])
    }

    static let trashRetention = 30 * 86_400
}
