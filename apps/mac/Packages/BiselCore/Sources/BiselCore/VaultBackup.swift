@_exported import BiselBackup
import Foundation
import CryptoKit

/// What `exportBackup` wrote.
public struct BackupExportReport: Sendable, Equatable {
    public var url: URL
    public var header: BackupHeader
    public var items: Int
    /// Past versions from the box's 30-day history that went into the file.
    public var historyVersions: Int
}

/// What a restore did. Nothing the box or the backup held is dropped without being listed here.
public struct BackupRestoreReport: Sendable, Equatable {
    public struct Copy: Sendable, Equatable {
        /// The item the box kept as it was.
        public let itemID: String
        /// New item holding the backup's version, titled "<title> (conflict)" like a sync conflict.
        public let copyID: String
    }
    public var header: BackupHeader
    /// Items the box did not have (for a fresh restore: every item).
    public var added = 0
    /// Items the box already had in this version, or in a newer one whose history holds this version.
    public var unchanged = 0
    /// Items both sides changed: the box keeps its version, the backup's becomes a copy.
    public var conflicts: [Copy] = []
    /// Items deleted in the box after the backup was made: left deleted.
    public var keptDeleted: [String] = []
    public var historyVersions = 0
    /// The backup came from a different box than this one (its items were added all the same).
    public var fromOtherBox = false
}

extension Vault {
    // MARK: export

    /// Writes an encrypted `.bisel-backup` (SPEC §12) of everything this device holds: items, the 30-day history, roster,
    /// recovery pins and the box key. Needs the box unlocked. Only the 24 words open the file. Syncs first when it can.
    ///
    /// A box made before backups v3 has no backup key yet: that throws `BackupError.needsPhrase`; call again with `phrase`.
    /// The file is written atomically (a temporary file renamed into place) and holds only ciphertext.
    @discardableResult
    public func exportBackup(to url: URL, phrase: RecoveryPhrase? = nil) async throws -> BackupExportReport {
        _ = try? await sync()
        if !isUnlocked { try await unlock(reason: "Export a backup") }   // a sync that adopted another device's rotation locks
        let k = try requireKey()
        let id = try requireIdentity()
        guard !id.recoveryMismatch else { throw IntegrityError.recoveryMaterialChanged }
        guard id.recoveryPinned, let encPub = id.recoveryEncryptionPublicKey, !encPub.isEmpty else { throw BackupError.recoveryKeysUnknown }
        if let phrase { try adoptBackupKey(phrase: phrase) }
        let manifest = try currentManifest(k)
        guard var psk = manifest.backupKey, manifest.backupKeyFor == encPub else { throw BackupError.needsPhrase }
        defer { psk.zeroize() }

        var items: [BackupEntry] = []
        var unreadable = 0
        for rec in try store.allRecords() where !rec.deleted && !ReservedRecord.isReserved(rec.id) {
            guard let payload = try? k.withKey({ try ItemSealer.open(blob: rec.blob, id: rec.id, rev: rec.rev, vaultKey: $0) }) else {
                unreadable += 1
                continue
            }
            items.append(BackupEntry(id: rec.id, rev: rec.rev, updatedAt: rec.updatedAt, payload: payload))
        }
        // A file that silently lacks items only fails on restore day.
        guard unreadable == 0 else { throw BackupError.unreadableItems(unreadable) }
        // Versions sealed under a key from before a rotation that was never re-wrapped cannot be read and stay out.
        let history = try store.trashedRecords().compactMap { t -> BackupHistoryEntry? in
            guard !t.record.deleted, !ReservedRecord.isReserved(t.record.id),
                  let payload = try? k.withKey({ try ItemSealer.open(blob: t.record.blob, id: t.record.id, rev: t.record.rev, vaultKey: $0) })
            else { return nil }
            return BackupHistoryEntry(id: t.record.id, rev: t.record.rev, updatedAt: t.record.updatedAt,
                                      replacedAt: Int(t.replacedAt.timeIntervalSince1970), reason: t.reason, payload: payload)
        }
        let revisions = try itemRevisions()
        var vk = try k.rawBytes()
        defer { vk.zeroize() }
        var contents = BackupContents(boxID: boxID(id, manifest), createdAt: Int(Date().timeIntervalSince1970), epoch: id.epoch,
                                      vaultKey: vk, manifest: manifest, items: items, history: history)
        defer { contents.zeroize() }
        let file = try BackupArchive.seal(contents, recoveryEncryptionPublicKey: encPub, backupKey: psk)
        try file.write(to: url, options: .atomic)
        // Read back what landed on disk: a file that does not even parse is caught now, not on restore day.
        let header = try BackupArchive.inspect(try Data(contentsOf: url))
        try saveBackupState(BackupState(lastBackupAt: header.createdAt, fileName: url.lastPathComponent, versions: revisions))
        return BackupExportReport(url: url, header: header, items: items.count, historyVersions: history.count)
    }

    /// The header of a backup file (format, box, date, size), checked for truncation and damage. Needs no phrase.
    public nonisolated static func inspectBackup(at url: URL) throws -> BackupHeader {
        try BackupArchive.inspect(try verifiableBackup(at: url))
    }

    // MARK: restore

    /// Rebuilds a box on a fresh install from a backup and its 24 words, with no other device, server or Apple ID. The box keeps
    /// its key, roster, recovery phrase and history; it lives on this Mac only until a lane or a server is connected. Every
    /// refusal (`BackupError`) happens before anything is written.
    @discardableResult
    public func restoreBackup(from url: URL, phrase: RecoveryPhrase, deviceName: String) throws -> BackupRestoreReport {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        let file = try Self.verifiableBackup(at: url)
        let header = try BackupArchive.inspect(file)
        var contents = try BackupArchive.open(file, phrase: phrase)
        defer { contents.zeroize() }

        let keys = try RecoveryKeys(phrase: phrase)
        let bundle = RecoveryBundle(phrase: phrase, publicKey: keys.publicKey, encryptionPublicKey: keys.encryptionPublicKey,
                                    envelope: try keys.seal(vaultKey: contents.vaultKey, epoch: 1))
        // The owner just proved they hold this phrase.
        try installLocalIdentity(vaultKey: contents.vaultKey, bundle: bundle, deviceName: deviceName, recoveryUnconfirmed: false)
        var id = try requireIdentity()
        for entry in contents.manifest.roster where !id.roster.contains(where: { $0.deviceID == entry.deviceID }) { id.roster.append(entry) }
        if contents.manifest.recoveryPublicKey == keys.publicKey { id.recoveryGeneration = max(id.recoveryGeneration, contents.manifest.recoveryGeneration) }
        try store.setIdentity(id)
        try writeManifest()
        try adoptBackupKey(phrase: phrase)

        let k = try requireKey()
        var report = BackupRestoreReport(header: header)
        for entry in contents.items where !ReservedRecord.isReserved(entry.id) {
            try commitRestored(entry.payload, id: entry.id, updatedAt: entry.updatedAt, k)
            report.added += 1
        }
        for h in contents.history where !ReservedRecord.isReserved(h.id) {
            let blob = try k.withKey { try ItemSealer.seal(payload: h.payload, id: h.id, rev: h.rev, vaultKey: $0) }
            try store.insertTrash(StoredRecord(id: h.id, rev: h.rev, seq: 0, deleted: false, blob: blob, updatedAt: h.updatedAt),
                                  replacedAt: Date(timeIntervalSince1970: TimeInterval(h.replacedAt)), reason: h.reason)
            report.historyVersions += 1
        }
        // The box as restored is exactly what the file holds: that file is its latest backup.
        try saveBackupState(BackupState(lastBackupAt: header.createdAt, fileName: url.lastPathComponent, versions: try itemRevisions()))
        return report
    }

    /// Restores a backup into this (unlocked) box without losing anything on either side: items the box lacks are added, items
    /// it holds in the same or a newer version stay, and where both changed the box keeps its version and the backup's
    /// becomes a "(conflict)" copy, as a sync conflict would. Items deleted here after the backup was made stay deleted and
    /// are listed. Running it again with the same file changes nothing. Fresh biometric check; `sync()` uploads the result.
    @discardableResult
    public func mergeBackup(from url: URL, phrase: RecoveryPhrase) async throws -> BackupRestoreReport {
        let k = try requireKey()
        let file = try Self.verifiableBackup(at: url)
        let header = try BackupArchive.inspect(file)
        var contents = try BackupArchive.open(file, phrase: phrase)
        defer { contents.zeroize() }
        try await config.gate.authenticate(reason: "Restore items from a backup")

        let id = try requireIdentity()
        var report = BackupRestoreReport(header: header)
        report.fromOtherBox = contents.boxID != boxID(id, try currentManifest(k))
        // Contents of every live item, so a copy an earlier merge of this same file made is recognised and not made twice.
        var known = Set(try store.liveRecords().compactMap { rec -> Data? in
            ReservedRecord.isReserved(rec.id) ? nil : (try? decrypt(rec, k)).flatMap { try? ItemCodec.encode($0) }
        })
        for entry in contents.items where !ReservedRecord.isReserved(entry.id) {
            guard let local = try store.record(entry.id) else {
                // An item that never reached a lane leaves no tombstone when deleted, only its last version in the history.
                if try store.trashedRecords(id: entry.id).contains(where: { $0.reason == "local-delete" && Int($0.replacedAt.timeIntervalSince1970) >= entry.updatedAt }) {
                    report.keptDeleted.append(entry.id)
                    continue
                }
                try commitRestored(entry.payload, id: entry.id, updatedAt: entry.updatedAt, k)
                report.added += 1
                continue
            }
            if local.deleted {
                if local.updatedAt >= entry.updatedAt { report.keptDeleted.append(entry.id); continue }
                try commitRestored(entry.payload, id: entry.id, updatedAt: entry.updatedAt, k)   // changed after the delete
                report.added += 1
                continue
            }
            let theirs = try? ItemCodec.decode(entry.payload, id: entry.id)
            let theirsEncoded = theirs.flatMap { try? ItemCodec.encode($0) }
            if let theirsEncoded {
                let mine = (try? decrypt(local, k)).flatMap { try? ItemCodec.encode($0) }
                if try mine == theirsEncoded || isPastVersion(theirsEncoded, of: entry.id, k) { report.unchanged += 1; continue }
            }
            var copyPayload = entry.payload
            if var copy = theirs {
                copy.title += " (conflict)"
                copyPayload = try ItemCodec.encode(copy)
            }
            if known.contains(copyPayload) { report.unchanged += 1; continue }
            let copyID = BiselRandom.identifier()
            try commitRestored(copyPayload, id: copyID, updatedAt: entry.updatedAt, k)
            known.insert(copyPayload)
            report.conflicts.append(.init(itemID: entry.id, copyID: copyID))
        }
        return report
    }

    // MARK: reminder

    /// Whether the app must remind the owner to export a backup now (D4), and what to say. Works while locked.
    public func backupStatus(policy: BackupReminderPolicy = .standard, now: Date = Date()) throws -> BackupStatus {
        let id = try requireIdentity()
        let copies: BoxCopies
        switch id.serverURL?.scheme?.lowercased() {
        case nil: copies = .thisDeviceOnly
        case "http", "https": copies = .server
        default: copies = .cloudKitOnly   // a storage-only lane
        }
        let state = try store.backupStateJSON().flatMap { try? JSONDecoder().decode(BackupState.self, from: $0) }
        let revisions = try itemRevisions()
        let changes = state?.changes(since: revisions) ?? revisions.count
        return BackupStatus(copies: copies, lastBackupAt: state?.lastBackupAt, lastFileName: state?.fileName, changesSinceBackup: changes,
                            reminder: policy.evaluate(copies: copies, state: state, changes: changes, now: now))
    }

    // MARK: backup key

    /// Puts the backup key derived from `phrase` into the box's manifest (needs the box unlocked). Called wherever the phrase is
    /// in hand: bootstrap, a new phrase, confirming the phrase, recovery, restore, and `exportBackup(phrase:)`.
    func adoptBackupKey(phrase: RecoveryPhrase) throws {
        let k = try requireKey()
        let id = try requireIdentity()
        // A manifest written before the box key is confirmed would stand in for the box's own one (see `confirmBoxKey`).
        guard !id.keyUnconfirmed else { throw IntegrityError.boxKeyUnconfirmed }
        let keys = try RecoveryKeys(phrase: phrase)
        guard let encPub = id.recoveryEncryptionPublicKey, keys.encryptionPublicKey == encPub else { throw BackupError.wrongPhrase }
        var psk = try BackupArchive.backupKey(phrase: phrase)
        defer { psk.zeroize() }
        var manifest = try currentManifest(k)
        if manifest.backupKeyFor == encPub, let held = manifest.backupKey, held.constantTimeEquals(psk) { return }
        manifest.backupKey = psk
        manifest.backupKeyFor = encPub
        try store.commitLocal(id: ReservedRecord.manifestID, deleted: false) { rev in
            try k.withKey { try ManifestCodec.seal(manifest, rev: rev, vaultKey: $0) }
        }
    }

    // MARK: other entry points

    /// Disaster recovery onto a fresh (un-bootstrapped) server: opens the backup with the phrase, bootstraps
    /// this device with the same recovery key, and re-uploads every item (re-sealed for its new revision).
    public func importBackup(from url: URL, phrase: RecoveryPhrase, server: URL, bootstrapToken: String,
                             deviceName: String) async throws {
        try await importBackup(from: url, phrase: phrase, server: server, credential: .token(bootstrapToken), deviceName: deviceName)
    }

    public func importBackup(from url: URL, phrase: RecoveryPhrase, server: URL, credential: SyncClient.BootstrapCredential,
                             deviceName: String) async throws {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        let data = try Self.verifiableBackup(at: url)
        _ = try BackupArchive.inspect(data)
        var contents = try BackupArchive.open(data, phrase: phrase)
        defer { contents.zeroize() }
        // A fresh server starts at epoch 1, and the recovery envelope is bound to the epoch: seal it again for this server.
        let keys = try RecoveryKeys(phrase: phrase)
        let bundle = RecoveryBundle(phrase: phrase, publicKey: keys.publicKey, encryptionPublicKey: keys.encryptionPublicKey,
                                    envelope: try keys.seal(vaultKey: contents.vaultKey, epoch: 1))
        try await register(server: server, credential: credential, deviceName: deviceName, vaultKey: contents.vaultKey, recovery: bundle)
        let k = try requireKey()
        for entry in contents.items where !ReservedRecord.isReserved(entry.id) {
            try commitRestored(entry.payload, id: entry.id, updatedAt: entry.updatedAt, k)
        }
        _ = try await sync()
    }

    /// Disaster recovery without any server: `restoreBackup`, for callers of the older name. Always returns 0 (a format 3 file
    /// restores whole or not at all).
    @discardableResult
    public func importBackupLocal(from url: URL, phrase: RecoveryPhrase, deviceName: String) throws -> Int {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        _ = try Self.verifiableBackup(at: url)
        try restoreBackup(from: url, phrase: phrase, deviceName: deviceName)
        return 0
    }

    /// The file's bytes, refusing a format 2 (JSON) file by name rather than as "not a backup".
    private static func verifiableBackup(at url: URL) throws -> Data {
        let data = try Data(contentsOf: url)
        if !data.starts(with: Data("BISELBAK".utf8)), let legacy = try? BackupFile.decode(data) {
            throw BackupError.unverifiableFormat(legacy.version)
        }
        return data
    }

    // MARK: helpers

    func canOpen(_ record: StoredRecord, with key: LockedKey) -> Bool {
        key.withKeyOrFalse { (try? ItemSealer.open(blob: record.blob, id: record.id, rev: record.rev, vaultKey: $0)) != nil }
    }

    /// This device's view of the manifest merged with the stored one (which is where the backup key lives).
    private func currentManifest(_ k: LockedKey) throws -> VaultManifest {
        var manifest = manifestFromIdentity(try requireIdentity())
        if let existing = try store.record(ReservedRecord.manifestID), !existing.deleted,
           let stored = try? k.withKey({ try ManifestCodec.open(existing, vaultKey: $0) }) {
            manifest = manifest.merged(with: stored)
        }
        return manifest
    }

    /// The box id a server or lane gave the box; a box that never had one is named by the device that created it.
    private func boxID(_ id: LocalIdentity, _ manifest: VaultManifest) -> String {
        id.boxID ?? "device-" + (manifest.roster.first(where: { $0.via == "bootstrap" })?.deviceID ?? id.deviceID)
    }

    private func commitRestored(_ payload: Data, id: String, updatedAt: Int, _ k: LockedKey) throws {
        try store.commitLocal(id: id, deleted: false, now: Date(timeIntervalSince1970: TimeInterval(updatedAt)), keepPrevious: keepsLocalHistory()) { rev in
            try k.withKey { try ItemSealer.seal(payload: payload, id: id, rev: rev, vaultKey: $0) }
        }
    }

    private func isPastVersion(_ encoded: Data, of id: String, _ k: LockedKey) throws -> Bool {
        try store.trashedRecords(id: id).contains { t in
            !t.record.deleted && (try? decrypt(t.record, k)).flatMap { try? ItemCodec.encode($0) } == encoded
        }
    }

    private func itemRevisions() throws -> [String: String] {
        try store.versionMarkers().filter { !ReservedRecord.isReserved($0.key) }
    }

    private func saveBackupState(_ state: BackupState) throws {
        try store.setBackupStateJSON(try JSONEncoder().encode(state))
    }
}
