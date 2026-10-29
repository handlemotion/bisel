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
        try await push(&report)
        try await pull(&report)
        return report
    }

    // MARK: push

    private func push(_ report: inout SyncReport) async throws {
        var skipped = Set<String>()
        // Resolving a conflict creates a new pending item, so loop until nothing new is pending.
        for _ in 0..<8 {
            let pending = try store.pendingRecords().filter { !skipped.contains($0.id) }
            if pending.isEmpty { return }
            for rec in pending {
                let outcome = rec.pending == .delete
                    ? try await client.delete(id: rec.id, baseRev: rec.baseRev)
                    : try await client.put(id: rec.id, baseRev: rec.baseRev, blob: rec.blob)
                switch outcome {
                case .accepted(let server):
                    try store.confirmPushed(pushed: rec, server: server)
                    report.pushed += 1
                case .conflict(let current):
                    if !(try resolveConflict(local: rec, current: current, &report)) { skipped.insert(rec.id) }
                }
            }
        }
    }

    /// Remote wins; a conflicting local edit survives as a new item. Returns false if it had to be deferred.
    private func resolveConflict(local: StoredRecord, current: StoredRecord?, _ report: inout SyncReport) throws -> Bool {
        guard let current else {
            // Server has no such record (e.g. wiped): nothing to keep or merge with; re-push as a new item next time.
            if local.pending == .delete { try store.forget(local.id); return true }
            report.deferredConflicts.append(local.id)
            return false
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

    // MARK: pull

    private func pull(_ report: inout SyncReport) async throws {
        var since = try store.cursor()
        while true {
            let page = try await client.pull(since: since)
            for rec in page.records where try store.applyRemote(rec) { report.pulled += 1 }
            since = page.nextSince
            try store.setCursor(since)
            report.headSeq = page.headSeq
            if let devices = try? JSONEncoder().encode(page.devices) { try store.setDeviceListJSON(devices) }
            if let recovery = page.recovery { try store.updateRecovery(recovery.pubkey, recovery.envelope) }
            if !page.hasMore { return }
        }
    }
}
