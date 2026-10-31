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
    /// nil for a vault that lives on this Mac only; a server can be connected later.
    public var serverURL: URL?
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
    /// The vault key this device holds came through the server (recovery phrase, or another device's rotation) and has not yet been
    /// checked against the box's own manifest. Until it is, nothing is uploaded under it.
    public var keyUnconfirmed: Bool = false
    /// Recovery-registered device: unix time before which the server refuses its requests.
    public var activatesAt: Int?
    /// The box on the server this device belongs to (`/v1/bootstrap` returns it). nil for identities from before accounts
    /// existed: the server resolves a recovery request without a box to its pre-accounts box.
    public var boxID: String?

    public init(deviceID: String, deviceName: String, serverURL: URL?, keyStore: String, envelope: Data? = nil,
                recoveryPublicKey: Data? = nil, recoveryEnvelope: Data? = nil,
                recoveryEncryptionPublicKey: Data? = nil, epoch: Int = 1, previousEnvelope: Data? = nil, boxID: String? = nil) {
        self.deviceID = deviceID; self.deviceName = deviceName; self.serverURL = serverURL; self.keyStore = keyStore
        self.envelope = envelope; self.recoveryPublicKey = recoveryPublicKey; self.recoveryEnvelope = recoveryEnvelope
        self.recoveryEncryptionPublicKey = recoveryEncryptionPublicKey; self.epoch = epoch
        self.previousEnvelope = previousEnvelope
        self.boxID = boxID
    }

    // Identities written before rotation existed lack the new keys: decode them with defaults.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        deviceID = try c.decode(String.self, forKey: .deviceID)
        deviceName = try c.decode(String.self, forKey: .deviceName)
        serverURL = try c.decodeIfPresent(URL.self, forKey: .serverURL)
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
        keyUnconfirmed = try c.decodeIfPresent(Bool.self, forKey: .keyUnconfirmed) ?? false
        activatesAt = try c.decodeIfPresent(Int.self, forKey: .activatesAt)
        boxID = try c.decodeIfPresent(String.self, forKey: .boxID)
    }
}

/// What this device remembers about one lane: where its pull stopped, the highest position it ever reported, the identity of
/// the storage it was enabled against.
public struct LaneState: Sendable, Equatable {
    /// Key of the state a box had before it had lanes.
    public static let primary = "primary"
    public var cursor: String?
    public var knownHead = 0
    public var eventCursor = 0
    public var identity: String?
    public var state = "active"
    /// What the verifier has established about the lane's control records (opaque here; `LaneWitness`).
    public var witness: Data?
    public init() {}
}

/// What a lane last held for a record: the revision and the lane's own concurrency tag.
public struct LaneAck: Sendable, Equatable {
    public var rev: Int
    public var tag: String
    public init(rev: Int, tag: String) { self.rev = rev; self.tag = tag }
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
        migrator.registerMigration("v3-lanes") { db in
            // Per-lane sync position and per-lane acknowledgement (docs/SYNC-LANES.md §1). Everything a box synced before lanes
            // existed belongs to its one remote, stored under `LaneState.primary` until the first lane that syncs adopts it.
            try db.create(table: "lane_state") { t in
                t.primaryKey("lane", .text)
                t.column("cursor", .text)
                t.column("known_head", .integer).notNull().defaults(to: 0)
                t.column("event_cursor", .integer).notNull().defaults(to: 0)
                t.column("identity", .text)
                t.column("state", .text).notNull().defaults(to: "active")
            }
            try db.create(table: "lane_ack") { t in
                t.column("lane", .text).notNull()
                t.column("id", .text).notNull()
                t.column("rev", .integer).notNull()
                t.column("tag", .text).notNull()
                t.primaryKey(["lane", "id"])
            }
            func meta(_ key: String) throws -> Int {
                try Data.fetchOne(db, sql: "SELECT value FROM meta WHERE key = ?", arguments: [key])
                    .flatMap { Int(String(decoding: $0, as: UTF8.self)) } ?? 0
            }
            let hasRemote = try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM records") ?? 0 > 0 || meta("head_seq") > 0
            if hasRemote {
                try db.execute(sql: "INSERT INTO lane_state(lane, cursor, known_head, event_cursor) VALUES (?, ?, ?, ?)",
                               arguments: [LaneState.primary, String(try meta("cursor")), try meta("head_seq"), try meta("event_cursor")])
                // What the remote last confirmed: `base_rev` while an edit is pending, the record's own revision otherwise.
                try db.execute(sql: """
                    INSERT INTO lane_ack(lane, id, rev, tag)
                    SELECT ?, id, CASE WHEN pending != 0 THEN base_rev ELSE rev END,
                           (CASE WHEN pending != 0 THEN base_rev ELSE rev END) || '.' || seq
                    FROM records WHERE (CASE WHEN pending != 0 THEN base_rev ELSE rev END) > 0
                    """, arguments: [LaneState.primary])
            }
        }
        migrator.registerMigration("v4-lane-witness") { db in
            try db.alter(table: "lane_state") { t in t.add(column: "witness", .blob) }
            // Records a lane sent that the verifier refused to apply. Kept for diagnostics, newest 200 per lane.
            try db.create(table: "quarantine") { t in
                t.autoIncrementedPrimaryKey("key")
                t.column("lane", .text).notNull()
                t.column("kind", .text).notNull()
                t.column("id", .text).notNull()
                t.column("rev", .integer).notNull()
                t.column("reason", .text).notNull()
                t.column("blob", .blob).notNull()
                t.column("at", .integer).notNull()
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
        guard var id = try getMeta("identity").map({ try JSONDecoder().decode(LocalIdentity.self, from: $0) }) else { return nil }
        guard let secrets else { return id }
        if id.serverURL == Self.serverURLPlaceholder {
            guard let data = try secrets.get(Self.serverURLKey), let url = URL(string: String(decoding: data, as: UTF8.self)) else {
                throw StoreError.serverAddressMissing
            }
            id.serverURL = url
        } else if id.serverURL != nil {
            try setIdentity(id)   // written before secrets existed: move the address out of the database now
        }
        return id
    }

    public func setIdentity(_ identity: LocalIdentity) throws {
        var stored = identity
        if let secrets {
            if let url = identity.serverURL {
                try secrets.set(Self.serverURLKey, Data(url.absoluteString.utf8))
                stored.serverURL = Self.serverURLPlaceholder
            } else {
                try secrets.delete(Self.serverURLKey)
            }
        }
        try setMeta("identity", try JSONEncoder().encode(stored))
    }

    // MARK: lanes

    /// State for `lane`. The first lane to ask when the box has none yet adopts what the box synced before lanes existed.
    public func laneState(_ lane: String) throws -> LaneState {
        try pool.write { db in
            if try Row.fetchOne(db, sql: "SELECT 1 FROM lane_state WHERE lane = ?", arguments: [lane]) == nil,
               try Row.fetchOne(db, sql: "SELECT 1 FROM lane_state WHERE lane = ?", arguments: [LaneState.primary]) != nil {
                try db.execute(sql: "UPDATE lane_state SET lane = ? WHERE lane = ?", arguments: [lane, LaneState.primary])
                try db.execute(sql: "UPDATE lane_ack SET lane = ? WHERE lane = ?", arguments: [lane, LaneState.primary])
            }
            guard let row = try Row.fetchOne(db, sql: "SELECT * FROM lane_state WHERE lane = ?", arguments: [lane]) else { return LaneState() }
            var out = LaneState()
            out.cursor = row["cursor"]; out.knownHead = row["known_head"]; out.eventCursor = row["event_cursor"]
            out.identity = row["identity"]; out.state = row["state"]; out.witness = row["witness"]
            return out
        }
    }

    public func setLaneState(_ lane: String, _ state: LaneState) throws {
        try pool.write { db in
            try db.execute(sql: """
                INSERT OR REPLACE INTO lane_state(lane, cursor, known_head, event_cursor, identity, state, witness) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, arguments: [lane, state.cursor, state.knownHead, state.eventCursor, state.identity, state.state, state.witness])
        }
    }

    /// Forgets where the pull stopped and the highest position seen, so the next pull starts again (a lane that was reset).
    /// What was verified about the lane's control records goes too, except the pinned admin keys' continuity, which the caller keeps.
    public func resetLanePosition(_ lane: String, keepingWitness: Data? = nil) throws {
        var state = try laneState(lane)
        state.cursor = nil; state.knownHead = 0; state.eventCursor = 0; state.witness = keepingWitness
        try setLaneState(lane, state)
    }

    /// Forgets that the lane holds these records (it lost them): they count as missing there and are uploaded again.
    public func forgetAcks(_ lane: String, ids: [String]) throws {
        try pool.write { db in for id in ids { try db.execute(sql: "DELETE FROM lane_ack WHERE lane = ? AND id = ?", arguments: [lane, id]) } }
    }

    public func ackedIDs(_ lane: String) throws -> Set<String> {
        try pool.read { db in Set(try String.fetchAll(db, sql: "SELECT id FROM lane_ack WHERE lane = ?", arguments: [lane])) }
    }

    /// Records the lane holds in an older revision than this device, or not at all, that are not waiting for a push of their own:
    /// the lane lost them, replayed an old version, or has never seen them (a lane that was just enabled).
    public func recordsBehind(_ lane: String) throws -> [(record: StoredRecord, ack: LaneAck?)] {
        try pool.read { db in
            let rows = try Row.fetchAll(db, sql: """
                SELECT r.*, a.rev AS ack_rev, a.tag AS ack_tag FROM records r LEFT JOIN lane_ack a ON a.lane = ? AND a.id = r.id
                WHERE r.pending = 0 AND r.tomb_ok = 1 AND (a.rev IS NULL OR a.rev < r.rev) ORDER BY r.updated_at
                """, arguments: [lane])
            return rows.map { row in
                (StoredRecord(row: row), (row["ack_rev"] as Int?).map { LaneAck(rev: $0, tag: row["ack_tag"]) })
            }
        }
    }

    /// The lane now holds `record` (a repair upload was accepted).
    public func acknowledge(_ lane: String, _ record: StoredRecord, tag: String) throws {
        try pool.write { try setAck(lane, record, tag: tag, $0) }
    }

    // MARK: quarantine

    public struct QuarantinedRecord: Sendable, Equatable {
        public var kind: String, id: String, rev: Int, reason: String, blob: Data, at: Date
    }

    public func quarantine(_ lane: String, _ entries: [(kind: String, id: String, rev: Int, reason: String, blob: Data)]) throws {
        guard !entries.isEmpty else { return }
        let now = Int(Date().timeIntervalSince1970)
        try pool.write { db in
            for e in entries {
                try db.execute(sql: "INSERT INTO quarantine(lane, kind, id, rev, reason, blob, at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                               arguments: [lane, e.kind, e.id, e.rev, e.reason, e.blob, now])
            }
            try db.execute(sql: "DELETE FROM quarantine WHERE lane = ? AND key NOT IN (SELECT key FROM quarantine WHERE lane = ? ORDER BY key DESC LIMIT 200)",
                           arguments: [lane, lane])
        }
    }

    public func quarantined(_ lane: String) throws -> [QuarantinedRecord] {
        try pool.read { db in
            try Row.fetchAll(db, sql: "SELECT * FROM quarantine WHERE lane = ? ORDER BY key DESC", arguments: [lane]).map {
                QuarantinedRecord(kind: $0["kind"], id: $0["id"], rev: $0["rev"], reason: $0["reason"], blob: $0["blob"],
                                  at: Date(timeIntervalSince1970: TimeInterval($0["at"] as Int)))
            }
        }
    }

    public func laneAck(_ lane: String, id: String) throws -> LaneAck? {
        try pool.read { db in
            try Row.fetchOne(db, sql: "SELECT rev, tag FROM lane_ack WHERE lane = ? AND id = ?", arguments: [lane, id]).map { LaneAck(rev: $0["rev"], tag: $0["tag"]) }
        }
    }

    private func setAck(_ lane: String?, _ r: StoredRecord, tag: String?, _ db: Database) throws {
        guard let lane, let tag else { return }
        try db.execute(sql: "INSERT OR REPLACE INTO lane_ack(lane, id, rev, tag) VALUES (?, ?, ?, ?)", arguments: [lane, r.id, r.rev, tag])
    }

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

    /// How many records wait to be pushed, without loading their blobs (`pendingRecords().count` read every blob: 13 ms at 5,000).
    public func pendingCount() throws -> Int {
        try pool.read { db in try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM records WHERE pending != 0") ?? 0 }
    }

    public func pendingRecords() throws -> [StoredRecord] {
        try pool.read { db in try Row.fetchAll(db, sql: "SELECT * FROM records WHERE pending != 0 ORDER BY updated_at").map(StoredRecord.init(row:)) }
    }

    /// Records a local edit. `seal` receives the revision the blob will have on the server
    /// (`baseRev + 1`) so the AAD binds the right one (for a delete: the sealed tombstone marker).
    /// Atomic with the base-revision lookup.
    @discardableResult
    public func commitLocal(id: String, deleted: Bool, now: Date = Date(), keepPrevious: Bool = false,
                            seal: (_ rev: Int) throws -> Data) throws -> StoredRecord {
        try pool.write { db in try commit(db, id: id, deleted: deleted, now: now, keepPrevious: keepPrevious, seal: seal) }
    }

    /// `keepPrevious`: the version this edit replaces goes to the local trash (a vault without a server has no other history).
    private func commit(_ db: Database, id: String, deleted: Bool, now: Date = Date(), keepPrevious: Bool = false,
                        seal: (_ rev: Int) throws -> Data) throws -> StoredRecord {
        let existing = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [id]).map(StoredRecord.init(row:))
        let baseRev = existing.map { $0.pending == .none ? $0.rev : $0.baseRev } ?? 0
        let rev = baseRev + 1
        let record = StoredRecord(id: id, rev: rev, seq: existing?.seq ?? 0, deleted: deleted,
                                  blob: try seal(rev), updatedAt: Int(now.timeIntervalSince1970),
                                  pending: deleted ? .delete : .put, baseRev: baseRev)
        if keepPrevious, let existing, !existing.deleted { try trash(existing, reason: deleted ? "local-delete" : "local-edit", db) }
        try write(record, db)
        return record
    }

    /// Conflict on the shared manifest: take the server's record and write the merged manifest on top of it, as one step.
    public func resolveManifestConflict(current: StoredRecord, id: String, lane: String? = nil, tag: String? = nil,
                                        seal: (_ rev: Int) throws -> Data) throws {
        try pool.write { db in
            try write(current, db)
            try setAck(lane, current, tag: tag, db)
            _ = try commit(db, id: id, deleted: false, seal: seal)
        }
    }

    /// A remote delete whose marker did not verify: mark it rejected and, if `restore` is given, write the kept version back
    /// as a new revision on top of it, in one transaction (a crash between the two would leave the forged delete honoured).
    public func rejectTombstone(id: String, rev: Int, restore seal: ((_ rev: Int) throws -> Data)?) throws {
        try pool.write { db in
            try db.execute(sql: "UPDATE records SET tomb_ok = ? WHERE id = ? AND rev = ? AND deleted = 1 AND pending = 0",
                           arguments: [StoredRecord.TombstoneState.rejected.rawValue, id, rev])
            if let seal { _ = try commit(db, id: id, deleted: false, seal: seal) }
        }
    }

    /// Applies a record received from the server. Pending local edits are never overwritten
    /// (they are resolved at push time). Returns false when the record was stale or skipped.
    @discardableResult
    public func applyRemote(_ r: StoredRecord, lane: String? = nil, tag: String? = nil) throws -> Bool {
        try pool.write { db in
            if let existing = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [r.id]).map(StoredRecord.init(row:)) {
                // A pending edit keeps the lane's old tag, so its push still collides with what the lane now holds.
                if existing.pending != .none { return false }
                if existing.rev > r.rev || (existing.rev == r.rev && existing.seq >= r.seq) {
                    try setAck(lane, r, tag: tag, db)
                    return false
                }
                // A new revision (or a delete) replaces content this device holds: keep the old ciphertext for 30 days.
                // (Same revision, new seq = a key rotation re-wrapping the item: nothing to keep.)
                if existing.rev != r.rev, !existing.deleted {
                    try trash(existing, reason: r.deleted ? "remote-delete" : "remote-overwrite", db)
                }
            }
            var incoming = r
            incoming.tombstone = r.deleted ? .unverified : .verified   // a delete is honoured only after its marker verified
            try write(incoming, db)
            try setAck(lane, r, tag: tag, db)
            return true
        }
    }

    /// Re-bases a record on top of what the server holds (`serverRev`, 0 = nothing): it becomes a pending edit sealed for
    /// `serverRev + 1`. Used when the server lost or rolled back state this device still has. Skipped (false) if the record
    /// changed since `record` was read.
    @discardableResult
    public func rebase(_ record: StoredRecord, serverRev: Int, seal: (_ rev: Int) throws -> Data) throws -> Bool {
        try pool.write { db in
            guard let cur = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [record.id]).map(StoredRecord.init(row:)),
                  cur.rev == record.rev, cur.pending == record.pending, cur.blob == record.blob else { return false }
            var next = cur
            next.rev = serverRev + 1
            next.baseRev = serverRev
            next.pending = cur.deleted ? .delete : .put
            next.tombstone = .verified
            next.blob = try seal(next.rev)
            try write(next, db)
            return true
        }
    }

    /// Like `rebase`, for a record that is pending *now*: read and re-based in one transaction, so an edit saved a moment ago
    /// is the one that gets re-sealed (`seal` receives that current record).
    @discardableResult
    public func rebasePending(id: String, serverRev: Int, seal: (_ current: StoredRecord, _ rev: Int) throws -> Data) throws -> Bool {
        try pool.write { db in
            guard let cur = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [id]).map(StoredRecord.init(row:)),
                  cur.pending != .none, cur.baseRev != serverRev else { return false }
            var next = cur
            next.rev = serverRev + 1
            next.baseRev = serverRev
            next.blob = try seal(cur, next.rev)
            try write(next, db)
            return true
        }
    }

    /// Set by `Vault.acknowledgeServerReset`: the next complete pull re-uploads whatever the server no longer has.
    public func reseedPending() throws -> Bool { try getMeta("reseed") != nil }
    public func setReseedPending(_ on: Bool) throws {
        if on { try setMeta("reseed", Data("1".utf8)) }
        else { try pool.write { try $0.execute(sql: "DELETE FROM meta WHERE key = 'reseed'") } }
    }

    /// Marks a pending record as accepted by the server, unless it changed again in the meantime.
    /// Returns false when it did change: the caller must then re-base the newer edit on `server`.
    @discardableResult
    public func confirmPushed(pushed: StoredRecord, server: StoredRecord, lane: String? = nil, tag: String? = nil) throws -> Bool {
        try pool.write { db in
            // The lane holds the pushed revision now, whether or not the record was edited again meanwhile.
            try setAck(lane, server, tag: tag, db)
            guard let cur = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [pushed.id]).map(StoredRecord.init(row:)),
                  cur.pending != .none, cur.blob == pushed.blob, cur.rev == pushed.rev else { return false }
            try write(server, db)
            return true
        }
    }

    /// Replaces local state with the server's current record (conflict resolution: remote wins).
    /// A delete taken over this way still has to pass the marker check like one received by a pull.
    public func overwrite(with r: StoredRecord, lane: String? = nil, tag: String? = nil) throws {
        var incoming = r
        incoming.tombstone = r.deleted ? .unverified : .verified
        try pool.write { db in
            try write(incoming, db)
            try setAck(lane, r, tag: tag, db)
        }
    }

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

    /// Replaces the sealed blob of a trash entry (key rotation re-wraps the item key so the version stays readable).
    public func replaceTrashBlob(key: Int, with blob: Data) throws {
        try pool.write { try $0.execute(sql: "UPDATE trash SET blob = ? WHERE key = ?", arguments: [blob, key]) }
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

    public func recentEventsJSON() throws -> Data? { try getMeta("events") }
    public func setRecentEventsJSON(_ json: Data) throws { try setMeta("events", json) }

    /// Drops a record that never reached the server (local create followed by local delete).
    public func forget(_ id: String, keepInTrash: Bool = false) throws {
        try pool.write { db in
            if keepInTrash, let cur = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [id]).map(StoredRecord.init(row:)),
               !cur.deleted {
                try trash(cur, reason: "local-delete", db)
            }
            try db.execute(sql: "DELETE FROM records WHERE id = ?", arguments: [id])
        }
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
    /// `records` are snapshots from before the request: one that was edited (or replaced by a pull) while the request was in
    /// flight no longer matches its row and is left alone; the caller re-wraps pending edits afterwards.
    public func applyRotation(_ records: [StoredRecord], lane: String, cursor: String?, headSeq: Int?, tags: [String: String] = [:]) throws {
        try pool.write { db in
            for r in records {
                guard let cur = try Row.fetchOne(db, sql: "SELECT * FROM records WHERE id = ?", arguments: [r.id]).map(StoredRecord.init(row:)),
                      cur.rev == r.rev, cur.pending == .none else { continue }
                try write(r, db)
                try setAck(lane, r, tag: tags[r.id] ?? "\(r.rev).\(r.seq)", db)
            }
            // A lane that numbers its history (the server) moved to the position the rotation left it at; one that does not
            // keeps its cursor, so nothing written by others in the meantime is skipped.
            if let cursor, let headSeq {
                try db.execute(sql: """
                    INSERT INTO lane_state(lane, cursor, known_head) VALUES (?, ?, ?)
                    ON CONFLICT(lane) DO UPDATE SET cursor = excluded.cursor, known_head = MAX(known_head, excluded.known_head)
                    """, arguments: [lane, cursor, headSeq])
            }
        }
    }

    public func removeAll() throws {
        try? secrets?.delete(Self.serverURLKey)
        try pool.write { db in
            try db.execute(sql: "DELETE FROM records")
            try db.execute(sql: "DELETE FROM trash")
            try db.execute(sql: "DELETE FROM lane_state")
            try db.execute(sql: "DELETE FROM lane_ack")
            try db.execute(sql: "DELETE FROM quarantine")
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
