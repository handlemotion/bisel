import Foundation
import BiselCrypto
import BiselLane
import BiselVault

public struct SyncReport: Sendable, Equatable {
    public struct Conflict: Sendable, Equatable {
        public let itemID: String       // the item whose remote version was kept
        public let copyID: String       // new item holding the local edit, titled "<title> (conflict)"
    }
    public var pushed = 0
    public var pulled = 0
    public var conflicts: [Conflict] = []
    /// Items with local edits that conflict with remote changes but could not be resolved because the vault is locked.
    public var deferredConflicts: [String] = []
    public var headSeq = 0
    /// Another device rotated the vault key. This device fetched its new envelope and must be unlocked again
    /// (the vault facade has already locked itself). Local edits made under the old key are re-wrapped at unlock.
    public var rotationAdopted = false
    /// Things that happened on the server since this device last synced (device added/revoked, key rotated, recovery used).
    /// Empty on a device's very first sync. Show them: "a device was added with the recovery phrase" is the alarm.
    public var events: [ServerEvent] = []
    /// Deletes that arrived from the server without a valid sealed marker (forged, or made by a key that is not this vault's).
    /// The item was restored from the local trash as a new revision.
    public var rejectedTombstones: [String] = []
    /// Records the lane sent that the verifier refused to apply (malformed, mis-signed, replayed). They are kept aside, not applied.
    public var quarantined = 0
    /// Records uploaded again because the lane lost them, replayed an older version, or had never seen them.
    public var repaired = 0
    /// Things the lane did that are not legitimate updates (hard deletes, a position that went backwards).
    public var incidents: [LaneIncident] = []
    public init() {}
}

/// Pull/push engine over one lane (SPEC §6, docs/SYNC-LANES.md §1): push pending local edits, resolve conflicts, then
/// page through the lane's changes, verifying every page before it reaches the local store.
public struct LaneEngine: Sendable {
    let store: LocalStore
    let lane: any BoxLane
    /// Needed only to build "(conflict)" copies; nil while locked.
    let vaultKey: @Sendable () -> LockedKey?
    let verifier = LaneVerifier()

    public init(store: LocalStore, lane: any BoxLane, vaultKey: @escaping @Sendable () -> LockedKey?) {
        self.store = store; self.lane = lane; self.vaultKey = vaultKey
    }

    private var laneKey: String { lane.id.rawValue }

    private func stored(_ r: LaneRecord) -> StoredRecord {
        StoredRecord(id: r.id, rev: r.rev, seq: r.order, deleted: r.kind == .tombstone, blob: r.blob, updatedAt: r.updatedAt)
    }

    private func laneRecord(_ r: StoredRecord, epoch: Int) -> LaneRecord {
        let kind: LaneKind = r.deleted ? .tombstone : (r.id == ReservedRecord.manifestID ? .manifest : .item)
        return LaneRecord(kind: kind, id: r.id, rev: r.rev, epoch: epoch, blob: r.blob, order: r.seq, updatedAt: r.updatedAt)
    }

    /// `pushing: false` only pulls: used while the vault key this device holds is not yet confirmed against the box.
    /// `audit: true` reads the lane from the start and checks it against what this device knows: a lane that rolled back to an
    /// older snapshot, or silently lost records, cannot be told apart from a quiet one by reading only what is new.
    public func run(pushing: Bool = true, audit: Bool = false) async throws -> SyncReport {
        var report = SyncReport()
        _ = try store.laneState(laneKey)   // adopts what the box synced before lanes existed, before anything is acknowledged
        let epoch = try store.identity()?.epoch ?? 1
        var staleEpoch = false
        if pushing { try await push(&report, epoch: epoch, staleEpoch: &staleEpoch) }
        var serverRevs: [String: Int] = [:]
        let reseeding = try store.reseedPending()
        let serverEpoch = try await pull(&report, serverRevs: &serverRevs, fromStart: reseeding || audit, auditing: audit)
        if staleEpoch || serverEpoch > epoch {
            try await adoptRotation(&report)
        } else if pushing, let vk = vaultKey() {
            if reseeding {
                // The server was reset (restored from an older state, or rebuilt): put back what only this device still has.
                try reseed(serverRevs: serverRevs, vk)
                try await push(&report, epoch: epoch, staleEpoch: &staleEpoch)
            }
            // Honour a remote delete only if its sealed marker verifies; a forged one is undone from the local trash.
            if try verifyTombstones(vk, &report) {
                var again = false
                try await push(&report, epoch: epoch, staleEpoch: &again)   // push the restored items right away
            }
            try await repair(&report, epoch: epoch)
            try await attest(report, epoch: epoch)
        }
        return report
    }

    /// Another device rotated VK: take this device's new envelope. If edits sealed under the old key are still
    /// pending, remember the old envelope so the next unlock can re-wrap them.
    private func adoptRotation(_ report: inout SyncReport) async throws {
        let (envelope, epoch) = try await lane.ownEnvelope()
        guard var identity = try store.identity() else { return }
        // The old key is needed at the next unlock for edits sealed under it and for the trash (versions this device kept).
        if identity.previousEnvelope == nil,
           try store.pendingRecords().contains(where: { $0.pending == .put }) || !store.trashedRecords().isEmpty {
            identity.previousEnvelope = identity.envelope
        }
        identity.envelope = envelope
        identity.epoch = epoch
        // The server chose this key for us: check it against the box's own records before anything is uploaded under it.
        identity.keyUnconfirmed = true
        try store.setIdentity(identity)
        report.rotationAdopted = true
    }

    // MARK: push

    private func push(_ report: inout SyncReport, epoch: Int, staleEpoch: inout Bool) async throws {
        var skipped = Set<String>()
        // Resolving a conflict creates a new pending item, so loop until nothing new is pending.
        for _ in 0..<8 {
            let pending = try store.pendingRecords().filter { !skipped.contains($0.id) }
            if pending.isEmpty { return }
            for rec in pending {
                // The manifest needs the vault-admin signature. Locked, or signing with a key the server has since rotated
                // away, it stays pending: the next unlocked sync (after pulling the new envelope) pushes it.
                let reserved = ReservedRecord.isReserved(rec.id)
                if reserved, vaultKey() == nil { skipped.insert(rec.id); continue }
                let expect: LaneExpect = rec.baseRev == 0 ? .absent
                    : .tag(LaneTag(try store.laneAck(laneKey, id: rec.id)?.tag ?? "\(rec.baseRev).0"))
                var outcome: LaneWriteResult
                do {
                    outcome = try await lane.write([LaneWrite(record: laneRecord(rec, epoch: epoch), expect: expect)])[0]
                    // The lane still holds the revision this edit was made on; only its tag was not known here (the
                    // acknowledgement was lost, and the lane's tags, like CloudKit's, cannot be rebuilt from the revision).
                    // Nobody else's edit landed in between, so write on top of it instead of making a "(conflict)" copy.
                    if case .conflict(let current?) = outcome, rec.baseRev > 0, current.rev == rec.baseRev,
                       let tag = current.tag, expect != .tag(tag) {
                        outcome = try await lane.write([LaneWrite(record: laneRecord(rec, epoch: epoch), expect: .tag(tag))])[0]
                    }
                } catch SyncError.server(_, let code) where reserved && code == "admin_signature_required" {
                    skipped.insert(rec.id)
                    continue
                }
                switch outcome {
                case .accepted(let accepted):
                    let server = stored(accepted)
                    report.pushed += 1
                    if !(try store.confirmPushed(pushed: rec, server: server, lane: laneKey, tag: accepted.tag?.rawValue)) {
                        // The item was edited again while this push was in flight: that newer edit continues from the
                        // revision the server just took, instead of colliding with this device's own earlier write.
                        if let vk = vaultKey() {
                            _ = try? store.rebasePending(id: rec.id, serverRev: server.rev) { cur, rev in
                                try vk.withKey { key in
                                    if cur.pending == .delete { return try ItemSealer.sealTombstone(id: cur.id, rev: rev, vaultKey: key) }
                                    let payload = try ItemSealer.open(blob: cur.blob, id: cur.id, rev: cur.rev, vaultKey: key)
                                    return try ItemSealer.seal(payload: payload, id: cur.id, rev: rev, vaultKey: key)
                                }
                            }
                        }
                    }
                case .conflict(let current):
                    if !(try resolveConflict(local: rec, current: current, &report)) { skipped.insert(rec.id) }
                case .rejected(.staleEpoch):
                    // The edit is sealed under a rotated-away key. Keep it pending; pull, adopt the new envelope,
                    // and let the next unlock re-wrap it.
                    staleEpoch = true
                    return
                case .rejected(.tooLarge):
                    throw SyncError.tooLarge
                case .rejected(let why):
                    throw SyncError.server(status: 409, code: "\(why)")
                }
            }
        }
    }

    /// Remote wins; a conflicting local edit survives as a new item. Returns false if it had to be deferred.
    private func resolveConflict(local: StoredRecord, current currentLane: LaneRecord?, _ report: inout SyncReport) throws -> Bool {
        let tag = currentLane?.tag?.rawValue
        guard let current = currentLane.map(stored) else {
            // Server has no such record (e.g. wiped): nothing to keep or merge with; upload it again as a new item.
            if local.pending == .delete { try store.forget(local.id); return true }
            guard let vk = vaultKey(), (try? rebase(local, onto: 0, vk)) == true else {
                report.deferredConflicts.append(local.id)
                return false
            }
            return true
        }
        // The server already holds exactly what this device pushed (the answer was lost): the push counts as accepted.
        if current.rev == local.rev, current.blob == local.blob, current.deleted == (local.pending == .delete) {
            try store.confirmPushed(pushed: local, server: current, lane: laneKey, tag: tag)
            report.pushed += 1
            return true
        }
        // The manifest is shared by every device and edited by several: merge instead of choosing a side.
        if local.id == ReservedRecord.manifestID, local.pending == .put, !current.deleted, let vk = vaultKey() {
            let merged = try vk.withKey { key -> VaultManifest in
                let mine = try ManifestCodec.open(local, vaultKey: key)
                let theirs = try ManifestCodec.open(current, vaultKey: key)
                return mine.merged(with: theirs)
            }
            try store.resolveManifestConflict(current: current, id: local.id, lane: laneKey, tag: tag) { rev in try vk.withKey { try ManifestCodec.seal(merged, rev: rev, vaultKey: $0) } }
            return true
        }
        if local.pending == .put {
            guard let vk = vaultKey() else {
                report.deferredConflicts.append(local.id)
                return false
            }
            let copyID = BiselRandom.identifier()
            try store.commitLocal(id: copyID, deleted: false) { rev in
                let payload = try vk.withKey { key in try ItemSealer.open(blob: local.blob, id: local.id, rev: local.rev, vaultKey: key) }
                var item = try ItemCodec.decode(payload, id: copyID)
                item.title += " (conflict)"
                item.updatedAt = Date()
                return try vk.withKey { key in try ItemSealer.seal(payload: try ItemCodec.encode(item), id: copyID, rev: rev, vaultKey: key) }
            }
            report.conflicts.append(.init(itemID: local.id, copyID: copyID))
        }
        // A pending local delete against a changed remote simply loses: the remote version stays.
        try store.overwrite(with: current, lane: laneKey, tag: tag)
        return true
    }

    // MARK: reseed

    /// Re-seals `record` for `serverRev + 1` (its payload is unchanged) so it can be pushed on top of what the server holds.
    private func rebase(_ record: StoredRecord, onto serverRev: Int, _ vk: LockedKey) throws -> Bool {
        try store.rebase(record, serverRev: serverRev) { rev in
            try vk.withKey { key in
                if record.deleted { return try ItemSealer.sealTombstone(id: record.id, rev: rev, vaultKey: key) }
                let payload = try ItemSealer.open(blob: record.blob, id: record.id, rev: record.rev, vaultKey: key)
                return try ItemSealer.seal(payload: payload, id: record.id, rev: rev, vaultKey: key)
            }
        }
    }

    /// After a complete pull from the start: every record this device holds in a newer revision than the server (or that the
    /// server lacks) becomes a pending edit on top of the server's revision. Records the server has at the same revision
    /// or newer were already taken by the pull.
    private func reseed(serverRevs: [String: Int], _ vk: LockedKey) throws {
        for rec in try store.allRecords() where rec.pending == .none {
            let serverRev = serverRevs[rec.id] ?? 0
            guard rec.rev > serverRev, !(rec.deleted && serverRev == 0) else { continue }
            _ = try rebase(rec, onto: serverRev, vk)
        }
        try store.setReseedPending(false)
    }

    // MARK: pull

    private func verifyTombstones(_ vk: LockedKey, _ report: inout SyncReport) throws -> Bool {
        var restored = false
        for tomb in try store.unverifiedTombstones() where !ReservedRecord.isReserved(tomb.id) {
            let ok = vk.withKeyOrFalse { ItemSealer.verifyTombstone(tomb.blob, id: tomb.id, rev: tomb.rev, vaultKey: $0) }
            if ok { try store.setTombstoneState(id: tomb.id, rev: tomb.rev, .verified); continue }
            report.rejectedTombstones.append(tomb.id)
            // Bring back the newest live version this device held, as a new revision on top of the (forged) tombstone.
            guard let kept = try store.trashedRecords(id: tomb.id).first(where: { !$0.record.deleted }),
                  let payload = try? vk.withKey({ try ItemSealer.open(blob: kept.record.blob, id: kept.record.id, rev: kept.record.rev, vaultKey: $0) })
            else { try store.rejectTombstone(id: tomb.id, rev: tomb.rev, restore: nil); continue }
            try store.rejectTombstone(id: tomb.id, rev: tomb.rev) { rev in
                try vk.withKey { try ItemSealer.seal(payload: payload, id: tomb.id, rev: rev, vaultKey: $0) }
            }
            restored = true
        }
        return restored
    }

    private func adminKey() -> Data? {
        guard let vk = vaultKey() else { return nil }
        return try? vk.withKey { try VaultAdmin.signingKey(vaultKey: $0).publicKey.rawRepresentation }
    }

    private func witness(_ state: LaneState) -> LaneWitness {
        state.witness.flatMap { try? JSONDecoder().decode(LaneWitness.self, from: $0) } ?? LaneWitness()
    }

    /// Returns the lane's epoch as of the last page.
    private func pull(_ report: inout SyncReport, serverRevs: inout [String: Int], fromStart: Bool, auditing: Bool) async throws -> Int {
        var state = try store.laneState(laneKey)
        var known = witness(state)
        var cursor = fromStart ? nil : state.cursor.map(LaneCursor.init)
        let eventCursor = state.eventCursor
        var newEvents: [ServerEvent] = []
        var seenRecords = Set<String>(), seenControl = Set<String>()
        while true {
            let changes = try await lane.fetch(since: cursor, limit: 200)
            // A lane that reports less than it already told us is rolling us back or lying.
            let verdict = try verifier.verify(changes, since: cursor, knownHead: state.knownHead, witness: &known, adminKey: adminKey())
            report.quarantined += verdict.quarantined.count
            report.incidents += verdict.incidents
            try store.quarantine(laneKey, verdict.quarantined.map { (kind: $0.record.kind.rawValue, id: $0.record.id, rev: $0.record.rev,
                                                                     reason: $0.reason.rawValue, blob: $0.record.blob) })
            // Records the lane says it deleted for good are never honoured: forget that it holds them, and they go back up.
            try store.forgetAcks(laneKey, ids: changes.removed.filter { $0.kind == .item || $0.kind == .tombstone || $0.kind == .manifest }.map(\.id))
            try noteEnrollments(changes, members: known.members)
            let localEpoch = try store.identity()?.epoch ?? 1
            let meta = verdict.meta ?? changes.meta ?? LaneMeta(epoch: localEpoch, headSeq: state.knownHead)
            for rec in changes.upserts {
                if rec.isItemLike { seenRecords.insert(rec.id) } else { seenControl.insert("\(rec.kind.rawValue)/\(rec.id)") }
            }
            for rec in verdict.accepted {
                serverRevs[rec.id] = rec.rev
                if try store.applyRemote(stored(rec), lane: laneKey, tag: rec.tag?.rawValue) { report.pulled += 1 }
            }
            cursor = changes.cursor
            state.cursor = changes.cursor.rawValue
            state.knownHead = max(state.knownHead, meta.headSeq)
            state.witness = try JSONEncoder().encode(known)
            try store.setLaneState(laneKey, state)
            report.headSeq = meta.headSeq
            if let devices = try? JSONEncoder().encode(meta.members) { try store.setDeviceListJSON(devices) }
            newEvents = meta.events
            if !changes.hasMore {
                if let top = meta.events.last?.id {
                    // The first sync of a device only learns the current position; nothing in it is news.
                    if eventCursor != 0 { report.events = meta.events.filter { $0.id > eventCursor } }
                    state.eventCursor = top
                    try store.setLaneState(laneKey, state)
                }
                if let json = try? JSONEncoder().encode(newEvents) { try store.setRecentEventsJSON(json) }
                // Recovery material is only recorded from a complete pull, so a backup never pairs a rotated
                // recovery envelope with half-rotated items.
                if let recovery = meta.recovery {
                    try store.updateRecovery(pubkey: recovery.pubkey, encryptionPubkey: recovery.encPubkey, envelope: recovery.envelope)
                }
                if auditing { try audit(known, seenRecords: seenRecords, seenControl: seenControl, &report) }
                return meta.epoch
            }
        }
    }

    /// Requests to join that are newest on this device: the approver lists them (`Vault.pendingEnrollments`) and the person
    /// approves one with the pairing secret. Only requests signed by the key they carry are kept, stamped with this device's
    /// clock when first seen (a rewrite of the same request keeps that time, so nobody can keep one fresh), and dropped once the
    /// lane deletes them or the device is a member. Anyone with the storage account can write requests: the newest few only.
    private func noteEnrollments(_ changes: LaneChanges, members: [DeviceInfo]) throws {
        let requests = changes.upserts.filter { $0.kind == .enroll }.compactMap(ControlRecords.verifiedEnrollRequest)
        let gone = Set(changes.removed.filter { $0.kind == .enroll }.compactMap { ControlRecords.deviceOfEnrollRequest($0.id) })
        guard !requests.isEmpty || !gone.isEmpty else { return }
        var list = try store.receivedEnrollmentsJSON().flatMap { try? JSONDecoder().decode([ReceivedEnrollment].self, from: $0) } ?? []
        let identity = try store.identity()
        let joined = Set(members.map(\.id) + (identity?.roster.map(\.deviceID) ?? []) + (identity.map { [$0.deviceID] } ?? []))
        let now = Int(Date().timeIntervalSince1970)
        for request in requests {
            let first = list.first { $0.request.deviceID == request.deviceID }?.receivedAt ?? now
            list.removeAll { $0.request.deviceID == request.deviceID }
            list.append(ReceivedEnrollment(request: request, receivedAt: first))
        }
        list.removeAll { gone.contains($0.request.deviceID) || joined.contains($0.request.deviceID) }
        list = Array(list.sorted { $0.receivedAt < $1.receivedAt }.suffix(Self.keptEnrollments))
        try store.setReceivedEnrollmentsJSON(try JSONEncoder().encode(list))
    }

    static let keptEnrollments = 8

    /// A complete reading of the lane against what this device knows: control records it has seen must still be there, and so
    /// must every record it was told the lane holds (the missing ones go back up).
    private func audit(_ known: LaneWitness, seenRecords: Set<String>, seenControl: Set<String>, _ report: inout SyncReport) throws {
        if known.logN > 0, !seenControl.contains("log/\(ControlRecords.logID(known.logN))") {
            throw IntegrityError.serverRolledBack(known: known.logN, reported: known.logN - 1)
        }
        for (device, counter) in known.counters where counter > 0 && !seenControl.contains("head/\(ControlRecords.deviceHeadID(device))") {
            throw IntegrityError.serverRolledBack(known: counter, reported: 0)
        }
        let lost = try store.ackedIDs(laneKey).subtracting(seenRecords)
        if !lost.isEmpty {
            report.incidents.append(.lost(count: lost.count))
            try store.forgetAcks(laneKey, ids: Array(lost))
        }
    }

    /// Uploads what the lane lacks or holds in an older version: after a hard delete, a replay, a restore, or when the lane
    /// has just been enabled. Only on lanes that take a write at any revision.
    private func repair(_ report: inout SyncReport, epoch: Int) async throws {
        guard lane.capabilities.repairs else { return }
        for (rec, ack) in try store.recordsBehind(laneKey) {
            if ReservedRecord.isReserved(rec.id), vaultKey() == nil { continue }
            let write = LaneWrite(record: laneRecord(rec, epoch: epoch), expect: ack.map { .tag(LaneTag($0.tag)) } ?? .absent)
            // A conflict means the lane holds something newer; the next pull shows it.
            if case .accepted(let accepted) = try await lane.write([write])[0] {
                try store.acknowledge(laneKey, rec, tag: accepted.tag?.rawValue ?? "")
                report.repaired += 1
            }
        }
    }

    /// Bumps this device's freshness counter after it wrote, on lanes that do not number their own history.
    private func attest(_ report: SyncReport, epoch: Int) async throws {
        guard !lane.capabilities.headIsCursor, report.pushed + report.repaired > 0, let me = try store.identity()?.deviceID else { return }
        var state = try store.laneState(laneKey)
        var known = witness(state)
        let counter = (known.counters[me] ?? 0) + 1
        try await lane.attest(counter: counter, epoch: epoch)
        known.counters[me] = counter
        state.witness = try JSONEncoder().encode(known)
        try store.setLaneState(laneKey, state)
    }
}
