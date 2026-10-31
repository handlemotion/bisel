import CloudKit
import CryptoKit
import Foundation
import BiselLane
import BiselVault

/// A box's ciphertext in the owner's CloudKit private database (docs/SYNC-LANES.md §3): one custom zone per box, one record
/// type `R`, raw `CKDatabase` async calls (no `CKSyncEngine`, see §3 "CKSyncEngine vs raw operations").
///
/// Storage only, like `FakeLane`: wrap it in a `RecordBox`. It decides nothing. The engine persists the change token it
/// returns only after `LaneVerifier` has accepted the page, so a page that is refused is fetched again.
///
/// Needs a signed app with the iCloud entitlement (container `iCloud.app.bisel`); a process without it fails on the first call.
public final class CloudKitLane: SyncLane, @unchecked Sendable {
    public static let recordType = "R"
    public static let defaultContainer = "iCloud.app.bisel"
    /// One subscription for the whole private database; a push only says "fetch now" (the 60 s poll stays the floor).
    public static let subscriptionID = "bisel-private-db"
    /// The commonly reported ceiling for one modify request is 400 records; it is undocumented, so atomic commits stop below it
    /// and per-record writes go in chunks.
    static let atomicLimit = 350
    static let chunkRecords = 100
    static let chunkBytes = 1_500_000

    public let container: CKContainer
    public let zoneID: CKRecordZone.ID
    private let database: CKDatabase
    private let pinned: LaneIdentity?

    private struct Known { var tag: String?; var systemFields: Data }
    private let lock = NSLock()
    /// The last server copy seen of each record, by record name: its change tag and the system fields a compare-and-set save needs.
    private var known: [String: Known] = [:]
    private var zoneReady = false
    private var account: LaneIdentity?
    private var observer: (any NSObjectProtocol)?

    /// `pinnedIdentity`: the account the lane was enabled on. A different account pauses the lane (`LaneError.accountChanged`).
    public init(container identifier: String = CloudKitLane.defaultContainer, zoneName: String, pinnedIdentity: LaneIdentity? = nil) {
        container = CKContainer(identifier: identifier)
        database = container.privateCloudDatabase
        zoneID = CKRecordZone.ID(zoneName: zoneName, ownerName: CKCurrentUserDefaultName)
        pinned = pinnedIdentity
        observer = NotificationCenter.default.addObserver(forName: .CKAccountChanged, object: nil, queue: nil) { [weak self] _ in
            self?.lock.withLock { self?.account = nil; self?.zoneReady = false }
            CloudKitSignals.shared.send()
        }
    }

    deinit { if let observer { NotificationCenter.default.removeObserver(observer) } }

    /// The zone of a box: `box-<boxID>`.
    public static func zoneName(box: String) -> String { "box-\(box)" }

    public var id: LaneID { LaneID("cloudkit:\(container.containerIdentifier ?? "?"):\(zoneID.zoneName)") }
    public var capabilities: LaneCapabilities {
        .init(atomicBatch: Self.atomicLimit, enforcesExpect: true, pushNotifications: true, repairs: true)
    }

    // MARK: account

    /// SHA-256 of the container and the iCloud user record name: who owns this storage, without naming the account.
    public func identity() async throws -> LaneIdentity {
        if let account = lock.withLock({ account }) { return account }
        let status = try await container.accountStatus()
        guard status == .available else { throw LaneError.accountUnavailable(Self.describe(status)) }
        let user = try await container.userRecordID()
        let digest = SHA256.hash(data: Data("\(container.containerIdentifier ?? "")|\(user.recordName)".utf8))
        let identity = LaneIdentity(digest.map { String(format: "%02x", $0) }.joined())
        lock.withLock { account = identity }
        return identity
    }

    private func ready() async throws {
        let current = try await identity()
        if let pinned, pinned != current { throw LaneError.accountChanged }
    }

    static func describe(_ status: CKAccountStatus) -> String {
        switch status {
        case .available: "available"
        case .noAccount: "no iCloud account"
        case .restricted: "iCloud restricted"
        case .couldNotDetermine: "iCloud status unknown"
        case .temporarilyUnavailable: "iCloud temporarily unavailable"
        @unknown default: "iCloud status \(status.rawValue)"
        }
    }

    // MARK: zone and subscription

    /// Creates the zone if it does not exist (saving an existing zone is a no-op). Writes never do this themselves: a zone the
    /// person deleted (iCloud settings) stays deleted, and every call reports `LaneError.storeMissing`, until they chose to upload
    /// the box again (`Vault.enableLane`).
    public func prepare() async throws {
        if lock.withLock({ zoneReady }) { return }
        let (saved, _) = try await retrying { try await self.database.modifyRecordZones(saving: [CKRecordZone(zoneID: self.zoneID)], deleting: []) }
        if case .failure(let error) = saved[zoneID] { throw error }
        lock.withLock { zoneReady = true }
    }

    /// One `CKDatabaseSubscription` with a silent push. Idempotent: saving it again replaces it.
    public func subscribe() async throws {
        let subscription = CKDatabaseSubscription(subscriptionID: Self.subscriptionID)
        let info = CKSubscription.NotificationInfo()
        info.shouldSendContentAvailable = true
        subscription.notificationInfo = info
        let (saved, _) = try await retrying { try await self.database.modifySubscriptions(saving: [subscription], deleting: []) }
        if case .failure(let error) = saved[Self.subscriptionID] { throw error }
    }

    /// Hand every remote notification the app receives to this; true if it was ours (the lanes are told to fetch).
    @discardableResult
    public static func handleRemoteNotification(_ userInfo: [AnyHashable: Any]) -> Bool {
        guard let note = CKNotification(fromRemoteNotificationDictionary: userInfo), note.subscriptionID == subscriptionID else { return false }
        CloudKitSignals.shared.send()
        return true
    }

    public func changes() -> AsyncStream<LaneSignal> { CloudKitSignals.shared.stream() }

    /// Hard-deletes `enroll.*` / `stage*` records once they served (the verifier does not count those as incidents).
    public func remove(_ refs: [LaneRecordRef]) async throws {
        try await ready()
        for chunk in refs.chunked(Self.chunkRecords) where !chunk.isEmpty {
            let ids = chunk.map { CKRecord.ID(recordName: Self.recordName($0.id), zoneID: zoneID) }
            let (_, deleted) = try await retrying {
                try await self.database.modifyRecords(saving: [], deleting: ids, savePolicy: .changedKeys, atomically: false)
            }
            for (id, result) in deleted {
                if case .failure(let error) = result, (error as? CKError)?.code != .unknownItem { _ = try outcome(of: error) }
                lock.withLock { known[id.recordName] = nil }
            }
        }
    }

    /// Deletes the zone and everything in it.
    public func erase(confirmed: LaneEraseToken) async throws {
        let (_, deleted) = try await retrying { try await self.database.modifyRecordZones(saving: [], deleting: [self.zoneID]) }
        if case .failure(let error) = deleted[zoneID], (error as? CKError)?.code != .zoneNotFound { throw error }
        lock.withLock { zoneReady = false; known = [:] }
    }

    // MARK: read

    public func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges {
        try await ready()
        var token = since.flatMap { Self.token($0) }
        var reset: LaneReset?
        if since != nil, token == nil { reset = .cursorExpired }
        let page: (modificationResultsByID: [CKRecord.ID: Result<CKDatabase.RecordZoneChange.Modification, any Error>],
                   deletions: [CKDatabase.RecordZoneChange.Deletion], changeToken: CKServerChangeToken, moreComing: Bool)
        do {
            page = try await changes(since: token, limit: limit)
        } catch let error as CKError where error.code == .changeTokenExpired {
            // Start over from the beginning: the engine applies only what is newer than its replica, and the verifier
            // re-reads the control records it already knows.
            token = nil
            reset = .cursorExpired
            page = try await changes(since: nil, limit: limit)
        }
        var upserts: [LaneRecord] = []
        for (_, result) in page.modificationResultsByID {
            guard case .success(let modification) = result else { continue }
            remember(modification.record)
            if let record = Self.laneRecord(modification.record) { upserts.append(record) }
        }
        upserts.sort { ($0.order, $0.id) < ($1.order, $1.id) }
        let removed = page.deletions.map { deletion in
            let id = Self.laneID(deletion.recordID.recordName)
            lock.withLock { known[deletion.recordID.recordName] = nil }
            return LaneRecordRef(kind: Self.kind(ofRecordNamed: id), id: id)
        }
        return LaneChanges(upserts: upserts, removed: removed, cursor: try Self.cursor(page.changeToken), hasMore: page.moreComing, reset: reset)
    }

    private func changes(since token: CKServerChangeToken?, limit: Int) async throws
        -> (modificationResultsByID: [CKRecord.ID: Result<CKDatabase.RecordZoneChange.Modification, any Error>],
            deletions: [CKDatabase.RecordZoneChange.Deletion], changeToken: CKServerChangeToken, moreComing: Bool) {
        do {
            return try await retrying {
                try await self.database.recordZoneChanges(inZoneWith: self.zoneID, since: token, desiredKeys: nil, resultsLimit: max(1, limit))
            }
        } catch let error as CKError where error.code == .zoneNotFound || error.code == .userDeletedZone {
            lock.withLock { zoneReady = false }
            throw LaneError.storeMissing
        }
    }

    public func read(_ refs: [LaneRecordRef]) async throws -> [LaneRecord?] {
        try await ready()
        let current = try await serverCopies(refs.map { Self.recordName($0.id) })
        return refs.map { ref in current[Self.recordName(ref.id)].flatMap(Self.laneRecord).flatMap { $0.kind == ref.kind ? $0 : nil } }
    }

    /// The server's current copy of each named record; absent names are missing on the server.
    private func serverCopies(_ names: [String]) async throws -> [String: CKRecord] {
        var out: [String: CKRecord] = [:]
        for chunk in Array(Set(names)).chunked(200) where !chunk.isEmpty {
            let ids = chunk.map { CKRecord.ID(recordName: $0, zoneID: zoneID) }
            let results = try await retrying { try await self.database.records(for: ids, desiredKeys: nil) }
            for (id, result) in results {
                switch result {
                case .success(let record):
                    remember(record)
                    out[id.recordName] = record
                case .failure(let error as CKError) where error.code == .unknownItem || error.code == .zoneNotFound:
                    lock.withLock { known[id.recordName] = nil }
                case .failure(let error):
                    throw error
                }
            }
        }
        return out
    }

    // MARK: write

    /// Per record, in chunks. `expect` maps onto CloudKit's own compare-and-set: every save is `.ifServerRecordUnchanged`
    /// against the change tag the write expects (`.absent`: a new record; `.any`: whatever the server holds right now).
    public func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] {
        try await ready()
        var results = [LaneWriteResult?](repeating: nil, count: batch.count)
        var pending = try await resolve(batch, into: &results)
        for _ in 0..<3 where !pending.isEmpty {
            var retry: [(index: Int, record: CKRecord)] = []
            for chunk in Self.chunks(pending) {
                let saved = try await save(chunk.map(\.record), atomically: false)
                for (index, record) in chunk {
                    switch saved[record.recordID] {
                    case .success(let accepted)?:
                        remember(accepted)
                        results[index] = Self.laneRecord(accepted).map { .accepted($0) } ?? .rejected(.forbidden)
                    case .failure(let error)?:
                        let ck = error as? CKError
                        // `.any` means "whatever is there": another device got in between, so try again on top of its copy.
                        if case .any = batch[index].expect, ck?.code == .serverRecordChanged, let server = ck?.serverRecord {
                            remember(server)
                            retry.append((index, Self.filled(server, with: batch[index].record)))
                        } else {
                            results[index] = try outcome(of: error)
                        }
                    case nil:
                        results[index] = .rejected(.forbidden)
                    }
                }
            }
            pending = retry
        }
        return results.map { $0 ?? .conflict(current: nil) }
    }

    /// All or nothing, within the zone. Refused above `atomicLimit` (the staged rotation of §5 is milestone L4).
    public func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult] {
        guard atomic.count <= Self.atomicLimit else { throw LaneError.unsupported }
        try await ready()
        var results = [LaneWriteResult?](repeating: nil, count: atomic.count)
        let pending = try await resolve(atomic, into: &results)
        if results.contains(where: { $0 != nil }) { return results.map { $0 ?? .rejected(.forbidden) } }
        let saved = try await save(pending.map(\.record), atomically: true)
        var out: [LaneWriteResult] = []
        var failed = false
        for (_, record) in pending {
            switch saved[record.recordID] {
            case .success(let accepted)?:
                remember(accepted)
                out.append(Self.laneRecord(accepted).map { .accepted($0) } ?? .rejected(.forbidden))
            case .failure(let error)?:
                failed = true
                let code = (error as? CKError)?.code
                out.append(code == .batchRequestFailed ? .rejected(.forbidden) : try outcome(of: error))
            case nil:
                failed = true
                out.append(.rejected(.forbidden))
            }
        }
        // Nothing was saved if anything failed; do not report an acceptance the server rolled back.
        return failed ? out.map { if case .accepted = $0 { return .rejected(.forbidden) } else { return $0 } } : out
    }

    /// Builds the record to save for each write, or settles it right away (the expected tag is not the server's: a conflict).
    private func resolve(_ batch: [LaneWrite], into results: inout [LaneWriteResult?]) async throws -> [(index: Int, record: CKRecord)] {
        var need: [String] = []
        for w in batch {
            let name = Self.recordName(w.record.id)
            let cached = lock.withLock { known[name] }
            switch w.expect {
            case .absent: continue
            case .tag(let tag): if cached?.tag != tag.rawValue { need.append(name) }
            case .any: if cached == nil { need.append(name) }
            }
        }
        let server = need.isEmpty ? [:] : try await serverCopies(need)
        var out: [(Int, CKRecord)] = []
        for (i, w) in batch.enumerated() {
            let name = Self.recordName(w.record.id)
            switch w.expect {
            case .absent:
                out.append((i, Self.filled(CKRecord(recordType: Self.recordType, recordID: CKRecord.ID(recordName: name, zoneID: zoneID)), with: w.record)))
            case .tag(let tag):
                if let base = cachedRecord(name, tag: tag.rawValue) { out.append((i, Self.filled(base, with: w.record))) }
                else { results[i] = .conflict(current: server[name].flatMap(Self.laneRecord)) }
            case .any:
                let base = server[name] ?? cachedRecord(name, tag: nil)
                    ?? CKRecord(recordType: Self.recordType, recordID: CKRecord.ID(recordName: name, zoneID: zoneID))
                out.append((i, Self.filled(base, with: w.record)))
            }
        }
        return out
    }

    /// Saves with `.ifServerRecordUnchanged`, halving the request when CloudKit says it is too big.
    private func save(_ records: [CKRecord], atomically: Bool) async throws -> [CKRecord.ID: Result<CKRecord, any Error>] {
        if records.isEmpty { return [:] }
        do {
            let (saved, _) = try await retrying {
                try await self.database.modifyRecords(saving: records, deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: atomically)
            }
            return saved
        } catch let error as CKError where error.code == .partialFailure {
            var out: [CKRecord.ID: Result<CKRecord, any Error>] = [:]
            for r in records { out[r.recordID] = .failure(error.partialErrorsByItemID?[r.recordID] ?? CKError(.batchRequestFailed)) }
            return out
        } catch let error as CKError where error.code == .limitExceeded && !atomically && records.count > 1 {
            let half = records.count / 2
            return try await save(Array(records[..<half]), atomically: false).merging(try await save(Array(records[half...]), atomically: false)) { a, _ in a }
        } catch let error as CKError where error.code == .zoneNotFound || error.code == .userDeletedZone {
            lock.withLock { zoneReady = false }
            throw LaneError.storeMissing
        }
    }

    private func outcome(of error: any Error) throws -> LaneWriteResult {
        guard let ck = error as? CKError else { throw error }
        switch ck.code {
        case .serverRecordChanged:
            if let server = ck.serverRecord { remember(server) }
            return .conflict(current: ck.serverRecord.flatMap(Self.laneRecord))
        case .unknownItem: return .conflict(current: nil)
        case .quotaExceeded: return .rejected(.quota)
        case .limitExceeded: return .rejected(.tooLarge)
        case .permissionFailure: return .rejected(.forbidden)
        case .zoneNotFound, .userDeletedZone:
            lock.withLock { zoneReady = false }
            throw LaneError.storeMissing
        default: throw error
        }
    }

    // MARK: plumbing

    /// Retries what CloudKit asks to be retried (rate limits, a busy zone, a service hiccup), honouring `retryAfterSeconds`.
    private func retrying<T>(_ operation: () async throws -> T) async throws -> T {
        var attempt = 0
        while true {
            do { return try await operation() }
            catch let error as CKError where attempt < 4 && [.requestRateLimited, .zoneBusy, .serviceUnavailable].contains(error.code) {
                attempt += 1
                try await Task.sleep(for: .seconds(error.retryAfterSeconds ?? Double(attempt)))
            }
        }
    }

    private func remember(_ record: CKRecord) {
        let archiver = NSKeyedArchiver(requiringSecureCoding: true)
        record.encodeSystemFields(with: archiver)
        archiver.finishEncoding()
        let entry = Known(tag: record.recordChangeTag, systemFields: archiver.encodedData)
        lock.withLock { known[record.recordID.recordName] = entry }
    }

    /// A record carrying only the system fields of the last server copy seen (with that change tag, if one is given).
    private func cachedRecord(_ name: String, tag: String?) -> CKRecord? {
        guard let entry = lock.withLock({ known[name] }), tag == nil || entry.tag == tag,
              let coder = try? NSKeyedUnarchiver(forReadingFrom: entry.systemFields) else { return nil }
        coder.requiresSecureCoding = true
        defer { coder.finishDecoding() }
        return CKRecord(coder: coder)
    }

    static func filled(_ base: CKRecord, with r: LaneRecord) -> CKRecord {
        base["k"] = r.kind.rawValue
        base["rev"] = r.rev
        base["ep"] = r.epoch
        base["w"] = r.writer
        base["sig"] = r.sig
        base["d"] = r.blob
        return base
    }

    static func laneRecord(_ r: CKRecord) -> LaneRecord? {
        guard r.recordType == recordType, let k = r["k"] as? String, let kind = LaneKind(rawValue: k), let blob = r["d"] as? Data else { return nil }
        let modified = r.modificationDate ?? r.creationDate ?? Date(timeIntervalSince1970: 0)
        return LaneRecord(kind: kind, id: laneID(r.recordID.recordName), rev: (r["rev"] as? NSNumber)?.intValue ?? 0,
                          epoch: (r["ep"] as? NSNumber)?.intValue ?? 0, blob: blob, writer: r["w"] as? String, sig: r["sig"] as? Data,
                          tag: r.recordChangeTag.map(LaneTag.init), order: Int(modified.timeIntervalSince1970 * 1000),
                          updatedAt: Int(modified.timeIntervalSince1970))
    }

    /// Record names may not start with an underscore; item ids are base64url and sometimes do.
    public static func recordName(_ id: String) -> String { id.hasPrefix("_") || id.hasPrefix("~") ? "~" + id : id }
    static func laneID(_ name: String) -> String { name.hasPrefix("~") ? String(name.dropFirst()) : name }

    /// A hard delete names only the record: its kind follows from the fixed control names.
    static func kind(ofRecordNamed id: String) -> LaneKind {
        if id == ControlRecords.headID || ControlRecords.deviceOfHead(id) != nil { return .head }
        if id == ControlRecords.recoveryID { return .recovery }
        if ControlRecords.logNumber(id) != nil { return .log }
        if id.hasPrefix("enroll.") { return .enroll }
        if id == "stage" || id.hasPrefix("stage.") { return .stage }
        if ControlRecords.envelopeParts(id) != nil { return .envelope }
        if id == ReservedRecord.manifestID { return .manifest }
        return .item
    }

    static func cursor(_ token: CKServerChangeToken) throws -> LaneCursor {
        LaneCursor(try NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: true).base64EncodedString())
    }

    static func token(_ cursor: LaneCursor) -> CKServerChangeToken? {
        guard let data = Data(base64Encoded: cursor.rawValue) else { return nil }
        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: CKServerChangeToken.self, from: data)
    }

    static func chunks(_ records: [(index: Int, record: CKRecord)]) -> [[(index: Int, record: CKRecord)]] {
        var out: [[(index: Int, record: CKRecord)]] = [[]]
        var bytes = 0
        for entry in records {
            let size = (entry.record["d"] as? Data)?.count ?? 0
            if out[out.count - 1].count >= chunkRecords || (bytes + size > chunkBytes && !out[out.count - 1].isEmpty) { out.append([]); bytes = 0 }
            out[out.count - 1].append(entry)
            bytes += size
        }
        return out
    }
}

/// Fans "fetch now" out to every lane's `changes()` stream: CloudKit pushes and account changes.
final class CloudKitSignals: @unchecked Sendable {
    static let shared = CloudKitSignals()
    private let lock = NSLock()
    private var continuations: [UUID: AsyncStream<LaneSignal>.Continuation] = [:]

    func stream() -> AsyncStream<LaneSignal> {
        AsyncStream { continuation in
            let key = UUID()
            lock.withLock { continuations[key] = continuation }
            continuation.onTermination = { [weak self] _ in self?.lock.withLock { self?.continuations[key] = nil } }
        }
    }

    func send() { for c in lock.withLock({ Array(continuations.values) }) { c.yield(.maybeChanged) } }
}

private extension Array {
    func chunked(_ size: Int) -> [[Element]] {
        stride(from: 0, to: count, by: size).map { Array(self[$0..<Swift.min($0 + size, count)]) }
    }
}
