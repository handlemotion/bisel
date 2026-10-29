import Foundation
import BiselCrypto
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
    public init() {}
}

/// Pull/push engine (SPEC §6): push pending local edits, resolve 409s, then page through `/v1/sync`.
public struct SyncEngine: Sendable {
    let store: LocalStore
    let client: SyncClient
    /// Needed only to build "(conflict)" copies; nil while locked.
    let vaultKey: @Sendable () -> LockedKey?

    public init(store: LocalStore, client: SyncClient, vaultKey: @escaping @Sendable () -> LockedKey?) {
        self.store = store; self.client = client; self.vaultKey = vaultKey
    }

    public func run() async throws -> SyncReport {
        var report = SyncReport()
        let epoch = try store.identity()?.epoch ?? 1
        var staleEpoch = false
        try await push(&report, epoch: epoch, staleEpoch: &staleEpoch)
        var serverRevs: [String: Int] = [:]
        let reseeding = try store.reseedPending()
        let serverEpoch = try await pull(&report, serverRevs: &serverRevs, fromStart: reseeding)
        if staleEpoch || serverEpoch > epoch {
            try await adoptRotation(&report)
        } else if let vk = vaultKey() {
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
        }
        return report
    }

    /// Another device rotated VK: take this device's new envelope. If edits sealed under the old key are still
    /// pending, remember the old envelope so the next unlock can re-wrap them.
    private func adoptRotation(_ report: inout SyncReport) async throws {
        let (envelope, epoch) = try await client.envelope()
        guard var identity = try store.identity() else { return }
        if identity.previousEnvelope == nil, try store.pendingRecords().contains(where: { $0.pending == .put }) {
            identity.previousEnvelope = identity.envelope
        }
        identity.envelope = envelope
        identity.epoch = epoch
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
                var admin: AdminSigner?
                if ReservedRecord.isReserved(rec.id) {
                    guard let vk = vaultKey() else { skipped.insert(rec.id); continue }
                    var raw = try vk.rawBytes()
                    defer { raw.zeroize() }
                    admin = try AdminSigner(vaultKey: raw)
                }
                let outcome: PutOutcome
                do {
                    outcome = rec.pending == .delete
                        ? try await client.delete(id: rec.id, baseRev: rec.baseRev, marker: rec.blob, epoch: epoch, admin: admin)
                        : try await client.put(id: rec.id, baseRev: rec.baseRev, blob: rec.blob, epoch: epoch, admin: admin)
                } catch SyncError.server(_, let code) where admin != nil && code == "admin_signature_required" {
                    skipped.insert(rec.id)
                    continue
                }
                switch outcome {
                case .accepted(let server):
                    report.pushed += 1
                    if !(try store.confirmPushed(pushed: rec, server: server)) {
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
                case .staleEpoch:
                    // The edit is sealed under a rotated-away key. Keep it pending; pull, adopt the new envelope,
                    // and let the next unlock re-wrap it.
                    staleEpoch = true
                    return
                }
            }
        }
    }

    /// Remote wins; a conflicting local edit survives as a new item. Returns false if it had to be deferred.
    private func resolveConflict(local: StoredRecord, current: StoredRecord?, _ report: inout SyncReport) throws -> Bool {
        guard let current else {
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
            try store.confirmPushed(pushed: local, server: current)
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
            try store.resolveManifestConflict(current: current, id: local.id) { rev in try vk.withKey { try ManifestCodec.seal(merged, rev: rev, vaultKey: $0) } }
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
        try store.overwrite(with: current)
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

    /// Returns the server's epoch as of the last page.
    private func pull(_ report: inout SyncReport, serverRevs: inout [String: Int], fromStart: Bool) async throws -> Int {
        var since = fromStart ? 0 : try store.cursor()
        let knownHead = try store.knownHeadSeq()
        let eventCursor = try store.eventCursor()
        var newEvents: [ServerEvent] = []
        while true {
            let page = try await client.pull(since: since, eventsSince: eventCursor == 0 ? nil : eventCursor)
            // A server that reports less than it already told us, or a cursor/records beyond its own head, is rolling us back or lying.
            if page.headSeq < knownHead { throw IntegrityError.serverRolledBack(known: knownHead, reported: page.headSeq) }
            if page.nextSince < since || page.nextSince > page.headSeq || (page.hasMore && page.nextSince == since)
                || page.records.contains(where: { $0.seq <= since || $0.seq > page.headSeq }) {
                throw IntegrityError.invalidCursor
            }
            for rec in page.records {
                serverRevs[rec.id] = rec.rev
                if try store.applyRemote(rec) { report.pulled += 1 }
            }
            since = page.nextSince
            try store.setCursor(since)
            try store.setKnownHeadSeq(page.headSeq)
            report.headSeq = page.headSeq
            if let devices = try? JSONEncoder().encode(page.devices) { try store.setDeviceListJSON(devices) }
            newEvents = page.events
            if !page.hasMore {
                if let top = page.events.last?.id {
                    // The first sync of a device only learns the current position; nothing in it is news.
                    if eventCursor != 0 { report.events = page.events.filter { $0.id > eventCursor } }
                    try store.setEventCursor(top)
                }
                if let json = try? JSONEncoder().encode(newEvents) { try store.setRecentEventsJSON(json) }
                // Recovery material is only recorded from a complete pull, so a backup never pairs a rotated
                // recovery envelope with half-rotated items.
                if let recovery = page.recovery {
                    try store.updateRecovery(pubkey: recovery.pubkey, encryptionPubkey: recovery.encPubkey, envelope: recovery.envelope)
                }
                return page.epoch
            }
        }
    }
}
