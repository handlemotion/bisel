import Foundation
import CryptoKit
import BiselCrypto
import BiselLane
import BiselVault

/// A box that exists already, for `RecordBox.adopt`: the epoch it is at, the admin-key chain to carry (its first key is what the
/// recovery anchor signs; it ends at `admin`), and every device that keeps the box, this device first, each with the vault key
/// sealed to it in `envelope`.
public struct ExistingBox: Sendable {
    public var epoch: Int
    public var chain: [ControlRecords.AKLink]
    public var admin: AdminSigner
    public var devices: [WireDevice]
    public var recovery: ControlRecords.Recovery
    public init(epoch: Int, chain: [ControlRecords.AKLink], admin: AdminSigner, devices: [WireDevice], recovery: ControlRecords.Recovery) {
        self.epoch = epoch; self.chain = chain; self.admin = admin; self.devices = devices; self.recovery = recovery
    }
}

/// A box on a lane that is only storage: the control operations of `BoxLane` as signed records (docs/SYNC-LANES.md §2, §4, §5).
///
/// Nothing here trusts the storage. What it writes is signed by the vault-admin key (derived from the vault key, so only a
/// holder can) or by the device's own signing key, and `LaneVerifier` checks all of it on the way back in. Revocation is
/// the key rotation itself, which `rotate` stages next to the items and switches with one small atomic commit (§5), so a box
/// of any size rotates on a lane whose atomic batch is a few records; `finishRotation` completes one a rotator left half-folded.
public struct RecordBox: BoxLane {
    let storage: any SyncLane
    let deviceID: String?
    let signDevice: (@Sendable (Data) throws -> Data)?
    let memberList: @Sendable () -> [DeviceInfo]
    /// Where to start looking for the end of the log; any number at or below the real one works.
    let logHint: @Sendable () -> Int
    /// The admin-key chain this device already verified (`LaneWitness.aks`). A head read from the lane counts only if it still holds it.
    let pinned: @Sendable () -> [ControlRecords.AKLink]

    /// `deviceID` and `sign` are this device's identity and DK-sig (nil while recovering, before the device exists).
    public init(storage: any SyncLane, deviceID: String?, sign: (@Sendable (Data) throws -> Data)? = nil,
                members: @escaping @Sendable () -> [DeviceInfo] = { [] }, logHint: @escaping @Sendable () -> Int = { 0 },
                pinned: @escaping @Sendable () -> [ControlRecords.AKLink] = { [] }) {
        self.storage = storage; self.deviceID = deviceID; signDevice = sign; memberList = members; self.logHint = logHint; self.pinned = pinned
    }

    public var id: LaneID { storage.id }
    public var capabilities: LaneCapabilities { var c = storage.capabilities; c.headIsCursor = false; return c }
    public func identity() async throws -> LaneIdentity { try await storage.identity() }
    public func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges { try await storage.fetch(since: since, limit: limit) }
    public func read(_ refs: [LaneRecordRef]) async throws -> [LaneRecord?] { try await storage.read(refs) }
    public func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult] { try await storage.commit(atomic) }
    public func changes() -> AsyncStream<LaneSignal> { storage.changes() }
    public func erase(confirmed: LaneEraseToken) async throws { try await storage.erase(confirmed: confirmed) }
    public func prepare() async throws { try await storage.prepare() }
    public func remove(_ refs: [LaneRecordRef]) async throws { try await storage.remove(refs) }

    /// An item written for an epoch the box has left is refused up front; one that slips through a race is quarantined on read.
    /// While another device stages a rotation on the current epoch, items are refused too (`.rotationInProgress`, the engine keeps
    /// the edit pending): the keys it staged would miss the new revision. Head and journal come in one read, no extra round trip.
    public func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] {
        let (found, journal) = try await headAndJournal()
        let epoch = found?.head.epoch
        let staging = found.map { blockingJournal(journal, head: $0.head) != nil } ?? false
        var results = [LaneWriteResult?](repeating: nil, count: batch.count)
        var forwarded: [LaneWrite] = []
        for (i, w) in batch.enumerated() {
            if w.record.isItemLike, let epoch, w.record.epoch != epoch { results[i] = .rejected(.staleEpoch(serverEpoch: epoch)) }
            else if w.record.isItemLike, staging { results[i] = .rejected(.rotationInProgress) }
            else { forwarded.append(w) }
        }
        var answers = try await storage.write(forwarded).makeIterator()
        return results.map { $0 ?? answers.next() ?? .rejected(.forbidden) }
    }

    // MARK: control

    public func members() async throws -> [DeviceInfo] { memberList() }

    public func admit(_ device: WireDevice, admin: AdminSigner) async throws {
        guard let (head, _) = try await headOutsideRotation() else { throw SyncError.notAuthorized }
        if let epoch = device.epoch, epoch != head.epoch { throw RotationError.staleEpoch(serverEpoch: head.epoch) }
        guard let envelope = device.envelope.flatMap({ Data(base64URLEncoded: $0) }) else { throw SyncError.malformedResponse }
        try await put(try envelopeRecord(device: device.id, epoch: head.epoch, envelope: envelope, admin: admin))
        try await appendLog(type: "approve", subject: device.id, member: Self.member(device), epoch: head.epoch, admin: admin)
    }

    public func revokeDevice(id: String, admin: AdminSigner) async throws {
        // Nothing on a storage lane can cut a device off; only the key rotation makes a revoke real.
        throw LaneError.unsupported
    }

    public func ownEnvelope() async throws -> (envelope: Data, epoch: Int) {
        // Both records are checked here: an envelope holding a key someone picked, under a head announcing a rotation, is what an
        // attacker with write access would plant, and whoever picked the key could also seal a manifest that "confirms" it.
        guard let deviceID, let (head, _) = try await currentHead(),
              let record = try await readOne(.envelope, ControlRecords.envelopeID(epoch: head.epoch, device: deviceID)),
              let key = ControlRecords.key(at: head.epoch, in: head.aks), ControlRecords.adminSignatureValid(record, key: key) else { throw SyncError.notFound }
        return (record.blob, head.epoch)
    }

    public func rotateRecovery(publicKey: Data, encryptionPublicKey: Data, envelope: Data, epoch: Int, admin: AdminSigner,
                               anchor: @Sendable (Data) throws -> Data) async throws {
        guard let (head, _) = try await headOutsideRotation(), let root = head.aks.first?.ak else { throw SyncError.notAuthorized }
        if epoch != head.epoch { throw RotationError.staleEpoch(serverEpoch: head.epoch) }
        let current = try await readOne(.recovery, ControlRecords.recoveryID)
        let seq = (current.flatMap { ControlRecords.decode(ControlRecords.Recovery.self, $0.blob) }?.seq ?? 0) + 1
        let rec = ControlRecords.Recovery(seq: seq, epoch: epoch, pubkey: publicKey.base64URLEncoded(),
                                          encPubkey: encryptionPublicKey.base64URLEncoded(), envelope: envelope.base64URLEncoded(),
                                          anchor: try anchor(root).base64URLEncoded())
        let write = LaneWrite(record: try signed(LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: epoch,
                                                            blob: try ControlRecords.encode(rec), writer: deviceID), by: admin),
                              expect: current?.tag.map { .tag($0) } ?? .absent)
        guard case .accepted = try await storage.write([write])[0] else { throw SyncError.conflict(current: nil) }
        try await appendLog(type: "recovery_rotate", subject: nil, member: nil, epoch: epoch, admin: admin)
    }

    /// The staged rotation of docs/SYNC-LANES.md §5, one code path for every lane that is only storage:
    ///
    /// 1. the verified head must still be at `baseEpoch`, and every item at the revision the caller re-wrapped;
    /// 2. the journal (`stage`, signed by the current admin key) claims the rotation: a fresh one by another device refuses
    ///    (`RotationError.inProgress`), and a concurrent rotator loses the compare-and-set on its slot;
    /// 3. the new wraps (`stage.<N+1>.<k>`) and envelopes are written next to what exists, signed by the new admin key. Items and
    ///    N-epoch records are untouched, so a crash anywhere before the commit leaves a box every device still reads;
    /// 4. all of it is read back: a lane that drops writes without a word never gets a commit (`.laneDroppedWrites`);
    /// 5. the items are read again: one that changed since the snapshot sends the caller back to sync (`behind`);
    /// 6. head, recovery and the log entry go in one atomic commit of three records, the switch;
    /// 7. the staged keys are folded into the items. A fold cut short still returns `.rotated` (the commit happened); `written`
    ///    then lacks the records not folded, and any device holding the new key finishes it (`finishRotation`).
    ///
    /// Anything that fails before the commit removes what this attempt staged (best effort; the next attempt overwrites the rest).
    public func rotate(baseEpoch: Int, baseSeq: Int, revoke: String?, newAdmin: AdminSigner,
                       items: [(id: String, rev: Int, wrappedKey: Data)], tombstones: [(id: String, rev: Int, marker: Data)],
                       devices: [(id: String, envelope: Data)], recoveryEnvelope: Data,
                       admin: AdminSigner) async throws -> (outcome: RotateOutcome, written: [LaneRecord]) {
        let behind = (outcome: RotateOutcome.conflict(epoch: baseEpoch, headSeq: nil), written: [LaneRecord]())
        let (found, journalRecord) = try await headAndJournal()
        guard let (head, headRecord) = found, head.epoch == baseEpoch else { return behind }
        guard storage.capabilities.atomicBatch >= 3 else { throw LaneError.unsupported }
        let newEpoch = baseEpoch + 1
        let staged = items.map { ControlRecords.StagedKey(id: $0.id, rev: $0.rev, key: $0.wrappedKey.base64URLEncoded(), tomb: false) }
            + tombstones.map { ControlRecords.StagedKey(id: $0.id, rev: $0.rev, key: $0.marker.base64URLEncoded(), tomb: true) }
        let snapshot = try await itemRecords(staged)
        guard staged.allSatisfy({ snapshot[$0.id]?.rev == $0.rev }) else { return behind }

        // 2. The journal.
        let previous = ControlRecords.verifiedJournal(journalRecord, chain: head.aks)
        if let previous, previous.from == baseEpoch, previous.isFresh(now: Self.now), previous.rotator != deviceID { throw RotationError.inProgress }
        let nonce = BiselRandom.nonce()
        let chunks = Self.pack(staged, epoch: newEpoch, nonce: nonce)
        let journal = ControlRecords.StageJournal(from: baseEpoch, to: newEpoch, nonce: nonce, rotator: deviceID,
                                                  newAK: newAdmin.publicKey.base64URLEncoded(), startedAt: Self.now, chunks: chunks.count)
        let journalWrite = LaneWrite(record: try signed(LaneRecord(kind: .stage, id: ControlRecords.stageID, rev: 0, epoch: baseEpoch,
                                                                   blob: try ControlRecords.encode(journal), writer: deviceID), by: admin),
                                     expect: journalRecord.map { $0.tag.map { .tag($0) } ?? .any } ?? .absent)
        guard case .accepted = try await storage.write([journalWrite])[0] else { throw RotationError.inProgress }

        let staging = try chunks.enumerated().map { n, chunk in
            try signed(LaneRecord(kind: .stage, id: ControlRecords.stageChunkID(epoch: newEpoch, n: n), rev: 0, epoch: newEpoch,
                                  blob: try ControlRecords.encode(chunk), writer: deviceID), by: newAdmin)
        } + devices.map { d in
            try signed(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: newEpoch, device: d.id), rev: 0, epoch: newEpoch,
                                  blob: d.envelope, writer: deviceID), by: newAdmin)
        }
        let stageRefs = [LaneRecordRef(kind: .stage, id: ControlRecords.stageID)] + staging.filter { $0.kind == .stage }.map { LaneRecordRef(kind: $0.kind, id: $0.id) }
        // Removing them on abort is safe: an envelope for an epoch the box never reached is no part of it (`LaneVerifier`).
        let attempt = stageRefs + staging.filter { $0.kind == .envelope }.map { LaneRecordRef(kind: $0.kind, id: $0.id) }
        if let previous, previous.to == newEpoch, previous.chunks > chunks.count {
            // Chunks of an earlier attempt of the same rotation that this one does not overwrite.
            await abandon((chunks.count..<previous.chunks).map { LaneRecordRef(kind: .stage, id: ControlRecords.stageChunkID(epoch: newEpoch, n: $0)) })
        }

        let current: [String: LaneRecord]
        var batch: [LaneWrite] = []
        do {
            // 3. Stage, 4. read it back.
            try Self.requireAccepted(try await storage.write(staging.map { LaneWrite(record: $0, expect: .any) }), count: staging.count)
            let sent = [journalWrite.record] + staging
            let back = try await storage.read(sent.map { LaneRecordRef(kind: $0.kind, id: $0.id) })
            guard back.count == sent.count, zip(back, sent).allSatisfy({ $0?.blob == $1.blob && $0?.sig == $1.sig }) else {
                throw RotationError.laneDroppedWrites
            }
            // 5. Nothing moved since the snapshot (the journal holds other devices' item writes off from here on).
            let now = try await itemRecords(staged)
            guard staged.allSatisfy({ s in now[s.id].map { $0.rev == s.rev && $0.tag == snapshot[s.id]?.tag } ?? false }) else {
                await abandon(attempt)
                return behind
            }
            current = now

            // 6. The switch: log entry, recovery, head.
            let (n, prev, replacing) = try await logTail(keys: head.aks)
            let entry = ControlRecords.LogEntry(n: n, prev: prev, type: "rotate", by: deviceID, subject: revoke, epoch: newEpoch, ts: Self.now)
            batch.append(LaneWrite(record: try signed(LaneRecord(kind: .log, id: ControlRecords.logID(n), rev: 0, epoch: newEpoch,
                                                                 blob: try ControlRecords.encode(entry), writer: deviceID), by: newAdmin),
                                   expect: replacing.map { .tag($0) } ?? .absent))
            if let currentRecovery = try await readOne(.recovery, ControlRecords.recoveryID),
               let rec = ControlRecords.decode(ControlRecords.Recovery.self, currentRecovery.blob) {
                let next = ControlRecords.Recovery(seq: rec.seq + 1, epoch: newEpoch, pubkey: rec.pubkey, encPubkey: rec.encPubkey,
                                                   envelope: recoveryEnvelope.base64URLEncoded(), anchor: rec.anchor)
                batch.append(LaneWrite(record: try signed(LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: newEpoch,
                                                                     blob: try ControlRecords.encode(next), writer: deviceID), by: newAdmin),
                                       expect: currentRecovery.tag.map { .tag($0) } ?? .any))
            }
            let link = ControlRecords.AKLink(epoch: newEpoch, ak: newAdmin.publicKey, sig: try admin.sign(ControlRecords.chainMessage(newKey: newAdmin.publicKey)))
            batch.append(LaneWrite(record: try signed(LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: newEpoch,
                                                                 blob: try ControlRecords.encode(ControlRecords.Head(epoch: newEpoch, aks: head.aks + [link])),
                                                                 writer: deviceID), by: newAdmin),
                                   expect: headRecord.tag.map { .tag($0) } ?? .any))
        } catch {
            await abandon(attempt)
            throw error
        }

        let results: [LaneWriteResult]
        do { results = try await storage.commit(batch) } catch {
            // The answer was lost, not necessarily the commit: clean up only if the head is still the one this started from.
            if let (h, r) = try? await currentHead(), h.epoch == baseEpoch, r.tag == headRecord.tag { await abandon(attempt) }
            throw error
        }
        guard results.count == batch.count, results.allSatisfy({ if case .accepted = $0 { return true } else { return false } }) else {
            await abandon(attempt)
            return behind
        }
        // A lane that drops writes without a word could have dropped the commit too: the head must be there before anything is folded.
        let newHead = batch[batch.count - 1].record
        let stored = try await readOne(.head, ControlRecords.headID)
        guard stored?.blob == newHead.blob, stored?.sig == newHead.sig else {
            await abandon(attempt)
            throw RotationError.laneDroppedWrites
        }

        // 7. Fold. The N-epoch envelopes stay: removing them would read as an incident to every device (`LaneVerifier`).
        let (written, left) = await fold(staged, over: current, to: newEpoch)
        if left == 0 { await abandon(stageRefs) }
        return (.rotated(epoch: newEpoch, headSeq: 0), written)
    }

    /// Finishes a rotation whose head is committed but whose items are not all folded yet (its rotator stopped part-way): every
    /// staged key whose item is still at the staged revision and an older epoch is folded in (compare-and-set on the item's tag; a
    /// conflict means someone else folded or edited it, and it is skipped), and the journal and chunks go once nothing is left.
    /// A journal that never committed and went stale is cleaned up. Returns the records this device folded.
    public func finishRotation() async throws -> Int { try await settleRotation(folding: true).folded }

    /// `folding: false` (locked, or holding a key not yet confirmed) folds and removes nothing and only says whether a committed
    /// rotation is still open on this lane (`pending`), from the journal alone: it goes when the last record is folded. One read
    /// when there is no journal, so every sync can ask.
    public func settleRotation(folding: Bool) async throws -> (folded: Int, pending: Bool) {
        let (found, journalRecord) = try await headAndJournal()
        guard let (head, _) = found, let journal = ControlRecords.verifiedJournal(journalRecord, chain: head.aks) else { return (0, false) }
        let journalRef = LaneRecordRef(kind: .stage, id: ControlRecords.stageID)
        let chunkRefs = (0..<journal.chunks).map { LaneRecordRef(kind: .stage, id: ControlRecords.stageChunkID(epoch: journal.to, n: $0)) }
        if journal.to > head.epoch {
            // Never committed. Its rotator may still be at it; after the time-out anyone holding the current key cleans up.
            if folding, !journal.isFresh(now: Self.now) { await abandon([journalRef] + chunkRefs) }
            return (0, false)
        }
        // Older than the head: superseded (or written by a revoked device with an old admin key). Nothing to fold.
        guard journal.to == head.epoch else { return (0, false) }
        guard folding else { return (0, true) }
        // The chunks must be the committed key's own: a revoked device can sign a journal for this epoch with the key it kept, but
        // not chunks. A journal they do not match folds nothing and goes (the chunks it names may be a genuine attempt's: they stay).
        guard let ak = head.aks.last?.ak, Data(base64URLEncoded: journal.newAK) == ak else { await abandon([journalRef]); return (0, false) }
        var staged: [ControlRecords.StagedKey] = []
        for r in try await storage.read(chunkRefs) {
            guard let r, r.epoch == journal.to, ControlRecords.adminSignatureValid(r, key: ak),
                  let chunk = ControlRecords.decode(ControlRecords.StageChunk.self, r.blob), chunk.nonce == journal.nonce, chunk.epoch == journal.to else {
                await abandon([journalRef])
                return (0, false)
            }
            staged += chunk.items
        }
        let (written, left) = await fold(staged, over: try await itemRecords(staged), to: journal.to)
        if left == 0 { await abandon([journalRef] + chunkRefs) }
        return (written.count, left > 0)
    }

    public func recoveryEnvelope() async throws -> (envelope: Data, epoch: Int) {
        guard let (head, _) = try await currentHead(), let (rec, envelope) = try await recovery(under: head) else { throw SyncError.notAuthorized }
        return (envelope, rec.epoch)
    }

    /// The recovery record, if signed in the head's own epoch: an older one still carries a signature by an older admin key, and
    /// a revoked device that kept that key could otherwise hand a fresh device the key it was cut off from.
    private func recovery(under head: ControlRecords.Head) async throws -> (ControlRecords.Recovery, envelope: Data)? {
        guard let record = try await readOne(.recovery, ControlRecords.recoveryID),
              let rec = ControlRecords.decode(ControlRecords.Recovery.self, record.blob), rec.epoch == head.epoch,
              let key = ControlRecords.key(at: rec.epoch, in: head.aks), ControlRecords.adminSignatureValid(record, key: key),
              let envelope = Data(base64URLEncoded: rec.envelope) else { return nil }
        return (rec, envelope)
    }

    /// Recovery on storage anyone with the account can write: the box must be the one the phrase vouched for. Its head has to
    /// descend from the admin key the recovery signing key `recoverySigningKey` signed (`ControlRecords.Recovery.anchor`), and the
    /// envelope then has to open to the key that head ends in: `adminKey` is that key's public half, for the caller to compare.
    /// `chain` is the head's admin-key chain, from the same read, for the freshness witness to be checked against.
    public func anchoredRecoveryEnvelope(recoverySigningKey: Data) async throws -> (envelope: Data, epoch: Int, adminKey: Data, chain: [ControlRecords.AKLink]) {
        guard let (head, _) = try await currentHead(), let root = head.aks.first?.ak, let current = head.aks.last?.ak,
              let (rec, envelope) = try await recovery(under: head),
              let anchor = rec.anchor.flatMap({ Data(base64URLEncoded: $0) }),
              let signer = try? Curve25519.Signing.PublicKey(rawRepresentation: recoverySigningKey),
              signer.isValidSignature(anchor, for: ControlRecords.anchorMessage(root: root)) else { throw SyncError.notAuthorized }
        return (envelope, rec.epoch, current, head.aks)
    }

    public func recoveryRegister(device: WireDevice, epoch: Int, admin: AdminSigner) async throws -> Date? {
        guard let (head, _) = try await headOutsideRotation() else { throw SyncError.notAuthorized }
        if epoch != head.epoch { throw RotationError.staleEpoch(serverEpoch: head.epoch) }
        guard let envelope = device.envelope.flatMap({ Data(base64URLEncoded: $0) }) else { throw SyncError.malformedResponse }
        try await put(try envelopeRecord(device: device.id, epoch: epoch, envelope: envelope, admin: admin))
        try await appendLog(type: "recovery", subject: device.id, member: Self.member(device), epoch: epoch, admin: admin, by: device.id)
        return nil
    }

    public func create(_ box: NewBox) async throws -> SyncClient.BootstrapResult {
        guard box.device.envelope != nil else { throw SyncError.malformedResponse }
        let recovery = ControlRecords.Recovery(seq: 1, epoch: 1, pubkey: box.recoveryPublicKey.base64URLEncoded(),
                                               encPubkey: box.recoveryEncryptionPublicKey.base64URLEncoded(), envelope: box.recoveryEnvelope.base64URLEncoded(),
                                               anchor: box.recoveryAnchor?.base64URLEncoded())
        let existing = ExistingBox(epoch: 1, chain: [.init(epoch: 1, ak: box.admin.publicKey, sig: nil)], admin: box.admin,
                                   devices: [box.device], recovery: recovery)
        guard try await adopt(existing) else { throw SyncError.conflict(current: nil) }
        return SyncClient.BootstrapResult(deviceID: box.device.id, boxID: nil, headSeq: 0, epoch: 1)
    }

    /// Puts a box that already exists (on another lane, on this Mac only, on storage that was deleted or belongs to another
    /// account) on this storage at its current epoch: the recovery record, an envelope for every device that keeps the box, a
    /// fresh membership log, and the head last. Items are not written here; the engine uploads them from the replica.
    ///
    /// Returns false when the storage already holds this box (its head verifies against `box.chain` and ends in `box.admin`):
    /// an earlier attempt got through, or another device put it there first. Storage that holds a different box is refused
    /// (`LaneError.occupied`), never written over.
    public func adopt(_ box: ExistingBox) async throws -> Bool {
        guard let me = box.devices.first, ControlRecords.chainValid(box.chain, epoch: box.epoch),
              box.chain.last?.ak == box.admin.publicKey else { throw SyncError.malformedResponse }
        try await storage.prepare()
        if let record = try await readOne(.head, ControlRecords.headID) {
            guard let head = ControlRecords.verifiedHead(record, pinned: box.chain), head.aks.last?.ak == box.admin.publicKey else { throw LaneError.occupied }
            return false
        }
        var recovery = box.recovery
        recovery.epoch = box.epoch
        try await put(try signed(LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: box.epoch,
                                            blob: try ControlRecords.encode(recovery), writer: me.id), by: box.admin))
        for device in box.devices {
            guard let envelope = device.envelope.flatMap({ Data(base64URLEncoded: $0) }) else { throw SyncError.malformedResponse }
            try await put(try envelopeRecord(device: device.id, epoch: box.epoch, envelope: envelope, admin: box.admin))
        }
        try await appendLog(type: "bootstrap", subject: me.id, member: Self.member(me), epoch: box.epoch, admin: box.admin, by: me.id, keys: box.chain)
        for device in box.devices.dropFirst() {
            try await appendLog(type: "approve", subject: device.id, member: Self.member(device), epoch: box.epoch, admin: box.admin, by: me.id, keys: box.chain)
        }
        let head = ControlRecords.Head(epoch: box.epoch, aks: box.chain)
        let record = try signed(LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: box.epoch, blob: try ControlRecords.encode(head), writer: me.id), by: box.admin)
        // The head goes last and only once: its existence is what makes this lane a box.
        guard case .accepted = try await storage.write([LaneWrite(record: record, expect: .absent)])[0] else { throw SyncError.conflict(current: nil) }
        return true
    }

    /// The admin key the box's genuine head ends in, nil when the storage holds no head (or a forged one).
    public func headAdminKey() async throws -> Data? { try await currentHead()?.head.aks.last?.ak }

    /// The recovery anchor of the record signed in the head's epoch, nil if there is none.
    public func recoveryAnchor() async throws -> (anchor: Data, root: Data)? {
        guard let (head, _) = try await currentHead(), let root = head.aks.first?.ak,
              let (rec, _) = try await recovery(under: head), let anchor = rec.anchor.flatMap({ Data(base64URLEncoded: $0) }) else { return nil }
        return (anchor, root)
    }

    public func attest(counter: Int, epoch: Int) async throws {
        guard let deviceID, let signDevice else { return }
        var record = LaneRecord(kind: .head, id: ControlRecords.deviceHeadID(deviceID), rev: 0, epoch: epoch,
                                blob: try ControlRecords.encode(ControlRecords.DeviceHead(device: deviceID, counter: counter, epoch: epoch)), writer: deviceID)
        record.sig = try signDevice(record.canonical)
        try await put(record)
    }

    // MARK: enrollment (§4)

    /// New device: puts its request on the lane (`enroll.<device>`), signed with its own DK-sig. The proof inside is what makes
    /// it worth anything; the signature only keeps the record whole.
    public func requestEnrollment(_ request: ControlRecords.EnrollRequest) async throws {
        guard let deviceID, deviceID == request.deviceID, let signDevice else { throw SyncError.notAuthorized }
        var record = LaneRecord(kind: .enroll, id: ControlRecords.enrollID(deviceID), rev: 0, epoch: 0,
                                blob: try ControlRecords.encode(request), writer: deviceID)
        record.sig = try signDevice(record.canonical)
        try await put(record)
    }

    /// Approver, after `admit`: the approval the new device checks its envelope against. `mac` gets the root of the head's
    /// admin-key chain (the key the box is known by), so the approval also names the box.
    public func recordEnrollmentApproval(device: String, envelope: Data, epoch: Int, admin: AdminSigner,
                                         mac: @Sendable (_ envelopeHash: String, _ rootAdminKey: Data) throws -> Data) async throws {
        guard let (head, _) = try await currentHead(), let root = head.aks.first?.ak else { throw SyncError.notAuthorized }
        if epoch != head.epoch { throw RotationError.staleEpoch(serverEpoch: head.epoch) }
        let hash = envelope.sha256Hex()
        let approval = ControlRecords.EnrollApproval(deviceID: device, epoch: epoch, envelopeHash: hash, mac: try mac(hash, root).base64URLEncoded())
        try await put(try signed(LaneRecord(kind: .enroll, id: ControlRecords.enrollApprovedID(device), rev: 0, epoch: epoch,
                                            blob: try ControlRecords.encode(approval), writer: deviceID), by: admin))
    }

    /// New device: its envelope (checked as `ownEnvelope` checks it), the root admin key of the head it hangs under, and the
    /// approval for it if one is signed by that head's key for its epoch (nil: none yet, or a forged one). Throws
    /// `SyncError.notFound` while there is no envelope. The pairing MAC is the caller's to check: it holds the secret.
    public func enrollmentGrant() async throws -> (envelope: Data, epoch: Int, rootAdminKey: Data, approval: ControlRecords.EnrollApproval?) {
        guard let deviceID, let (head, _) = try await currentHead(), let root = head.aks.first?.ak,
              let key = ControlRecords.key(at: head.epoch, in: head.aks),
              let record = try await readOne(.envelope, ControlRecords.envelopeID(epoch: head.epoch, device: deviceID)),
              ControlRecords.adminSignatureValid(record, key: key) else { throw SyncError.notFound }
        var approval: ControlRecords.EnrollApproval?
        if let a = try await readOne(.enroll, ControlRecords.enrollApprovedID(deviceID)), a.epoch == head.epoch,
           ControlRecords.adminSignatureValid(a, key: key),
           let decoded = ControlRecords.decode(ControlRecords.EnrollApproval.self, a.blob), decoded.deviceID == deviceID, decoded.epoch == head.epoch {
            approval = decoded
        }
        return (record.blob, head.epoch, root, approval)
    }

    /// New device, once it joined: the request and the approval served their purpose.
    public func endEnrollment() async throws {
        guard let deviceID else { return }
        try await storage.remove([LaneRecordRef(kind: .enroll, id: ControlRecords.enrollID(deviceID)),
                                  LaneRecordRef(kind: .enroll, id: ControlRecords.enrollApprovedID(deviceID))])
    }

    // MARK: plumbing

    private static var now: Int { Int(Date().timeIntervalSince1970) }

    private static func member(_ d: WireDevice) -> DeviceInfo {
        DeviceInfo(id: d.id, name: d.name, kind: d.kind, sigPubkey: d.sigPubkey, encPubkey: d.encPubkey, createdAt: now)
    }

    private func readOne(_ kind: LaneKind, _ id: String) async throws -> LaneRecord? {
        try await storage.read([LaneRecordRef(kind: kind, id: id)]).first ?? nil
    }

    /// The box's head as the lane serves it, if it is genuine (`ControlRecords.verifiedHead`). A forged one counts as no head.
    private func currentHead() async throws -> (head: ControlRecords.Head, record: LaneRecord)? {
        guard let record = try await readOne(.head, ControlRecords.headID),
              let head = ControlRecords.verifiedHead(record, pinned: pinned()) else { return nil }
        return (head, record)
    }

    /// The verified head and whatever sits in the rotation journal's slot, in one read.
    private func headAndJournal() async throws -> (head: (head: ControlRecords.Head, record: LaneRecord)?, journal: LaneRecord?) {
        let found = try await storage.read([LaneRecordRef(kind: .head, id: ControlRecords.headID), LaneRecordRef(kind: .stage, id: ControlRecords.stageID)])
        let journal = found.count > 1 ? found[1] : nil
        guard let record = found.first ?? nil, let head = ControlRecords.verifiedHead(record, pinned: pinned()) else { return (nil, journal) }
        return ((head, record), journal)
    }

    /// A rotation another device is staging on `head` right now: signed by the current admin key, from this epoch, fresh, not ours.
    private func blockingJournal(_ record: LaneRecord?, head: ControlRecords.Head) -> ControlRecords.StageJournal? {
        guard let j = ControlRecords.verifiedJournal(record, chain: head.aks), j.from == head.epoch, j.isFresh(now: Self.now),
              j.rotator != deviceID else { return nil }
        return j
    }

    /// The verified head, refusing while another device stages a rotation on it: a device admitted or a recovery key changed in
    /// the middle would be missing from the envelopes and recovery record it commits.
    private func headOutsideRotation() async throws -> (head: ControlRecords.Head, record: LaneRecord)? {
        let (found, journal) = try await headAndJournal()
        if let found, blockingJournal(journal, head: found.head) != nil { throw RotationError.inProgress }
        return found
    }

    private func signed(_ record: LaneRecord, by admin: AdminSigner) throws -> LaneRecord {
        var r = record
        r.sig = try admin.sign(r.canonical)
        return r
    }

    // MARK: staged rotation

    /// Staged keys per chunk record: well under what any lane takes in one record (CloudKit: 1 MB; items are capped at 256 KiB).
    static let chunkBytes = 128 * 1024

    private static func pack(_ staged: [ControlRecords.StagedKey], epoch: Int, nonce: String) -> [ControlRecords.StageChunk] {
        var chunks: [ControlRecords.StageChunk] = [], current: [ControlRecords.StagedKey] = [], size = 0
        for s in staged {
            let cost = s.id.utf8.count + s.key.utf8.count + 48   // the JSON around one entry
            if !current.isEmpty, size + cost > chunkBytes {
                chunks.append(.init(epoch: epoch, nonce: nonce, items: current))
                current = []; size = 0
            }
            current.append(s); size += cost
        }
        if !current.isEmpty || chunks.isEmpty { chunks.append(.init(epoch: epoch, nonce: nonce, items: current)) }
        return chunks
    }

    /// The lane's current copy of each staged record, under the kind the staged key was built for.
    private func itemRecords(_ staged: [ControlRecords.StagedKey]) async throws -> [String: LaneRecord] {
        let refs = staged.map { LaneRecordRef(kind: $0.tomb ? .tombstone : ($0.id == ReservedRecord.manifestID ? .manifest : .item), id: $0.id) }
        var out: [String: LaneRecord] = [:]
        for (ref, found) in zip(refs, try await storage.read(refs)) { if let found { out[ref.id] = found } }
        return out
    }

    /// Whether `record` still waits for staged key `s`: same revision, an epoch below the rotation's, the same kind.
    private static func unfolded(_ record: LaneRecord, _ s: ControlRecords.StagedKey, to epoch: Int) -> Bool {
        record.rev == s.rev && record.epoch < epoch && (record.kind == .tombstone) == s.tomb
            && (s.tomb || record.blob.count > ItemSealer.wrappedKeyLength)
    }

    /// Writes each staged key into its item record (the staged wrap plus the current blob after the old one; a tombstone takes
    /// the new marker whole), for `epoch`, compare-and-set on the tag in `current`. Never throws: a fold that fails part-way
    /// leaves the rest staged for the next device. Returns the records the lane took, and how many still wait for their key.
    private func fold(_ staged: [ControlRecords.StagedKey], over current: [String: LaneRecord], to epoch: Int) async -> (written: [LaneRecord], left: Int) {
        var writes: [LaneWrite] = [], keys: [ControlRecords.StagedKey] = []
        for s in staged {
            guard let cur = current[s.id], Self.unfolded(cur, s, to: epoch), let key = Data(base64URLEncoded: s.key),
                  s.tomb || key.count == ItemSealer.wrappedKeyLength else { continue }
            var r = cur
            r.blob = s.tomb ? key : key + cur.blob.dropFirst(ItemSealer.wrappedKeyLength)
            r.epoch = epoch
            r.writer = deviceID
            writes.append(LaneWrite(record: r, expect: cur.tag.map { .tag($0) } ?? .any))
            keys.append(s)
        }
        guard !writes.isEmpty else { return ([], 0) }
        guard let results = try? await storage.write(writes), results.count == writes.count else { return ([], writes.count) }
        var written: [LaneRecord] = [], left = 0
        for (s, result) in zip(keys, results) {
            switch result {
            case .accepted(let r): written.append(r)
            case .conflict(let now?): if Self.unfolded(now, s, to: epoch) { left += 1 }   // rewritten at the same revision: try again later
            case .conflict(nil): break   // gone: nothing to fold
            case .rejected: left += 1
            }
        }
        return (written, left)
    }

    private static func requireAccepted(_ results: [LaneWriteResult], count: Int) throws {
        guard results.count == count else { throw RotationError.laneDroppedWrites }
        for result in results {
            switch result {
            case .accepted: continue
            case .conflict: throw RotationError.laneDroppedWrites   // nothing else writes these ids with `.any`
            case .rejected(.tooLarge): throw SyncError.tooLarge
            case .rejected(let why): throw SyncError.server(status: 409, code: "\(why)")
            }
        }
    }

    /// Best effort: what is not removed now is overwritten by the next attempt, or removed by whoever finishes or times it out.
    private func abandon(_ refs: [LaneRecordRef]) async {
        guard !refs.isEmpty else { return }
        try? await storage.remove(refs)
    }

    private func envelopeRecord(device: String, epoch: Int, envelope: Data, admin: AdminSigner) throws -> LaneRecord {
        try signed(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: epoch, device: device), rev: 0, epoch: epoch, blob: envelope, writer: deviceID), by: admin)
    }

    /// Unconditional write of one record; anything but an acceptance is a failure of the lane.
    private func put(_ record: LaneRecord) async throws {
        switch try await storage.write([LaneWrite(record: record, expect: .any)])[0] {
        case .accepted: return
        // Why the storage refused (a full iCloud is `quota`) is what the person needs to hear, not "unexpected response".
        case .rejected(.tooLarge): throw SyncError.tooLarge
        case .rejected(let why): throw SyncError.server(status: 409, code: "\(why)")
        case .conflict: throw SyncError.malformedResponse
        }
    }

    /// The first log slot not held by a genuine entry, the hash of the entry before it, and the tag of whatever squats on the
    /// slot (a record that is not a valid entry for it: anyone with the account can plant one, and it would otherwise block the
    /// chain for good). `keys` are the admin keys of the box's epochs, to tell the two apart.
    private func logTail(keys: [ControlRecords.AKLink]) async throws -> (n: Int, prev: String, replacing: LaneTag?) {
        func genuine(_ r: LaneRecord, n: Int, prev: String) -> Bool {
            guard let e = ControlRecords.decode(ControlRecords.LogEntry.self, r.blob), e.n == n, e.prev == prev,
                  let key = ControlRecords.key(at: e.epoch, in: keys) else { return false }
            return ControlRecords.adminSignatureValid(r, key: key)
        }
        var n = 1
        var prev = ""
        // The hint saves walking the whole log: trust it only if the entry it names is there and genuine.
        let hint = max(logHint(), 0)
        if hint > 0, let at = try await readOne(.log, ControlRecords.logID(hint)),
           let e = ControlRecords.decode(ControlRecords.LogEntry.self, at.blob), e.n == hint, let key = ControlRecords.key(at: e.epoch, in: keys),
           ControlRecords.adminSignatureValid(at, key: key) {
            n = hint + 1
            prev = ControlRecords.logHash(at.blob)
        }
        while let existing = try await readOne(.log, ControlRecords.logID(n)) {
            guard genuine(existing, n: n, prev: prev) else { return (n, prev, existing.tag) }
            prev = ControlRecords.logHash(existing.blob)
            n += 1
        }
        return (n, prev, nil)
    }

    /// Appends to the membership log, moving on to the next slot if another device took this one first.
    private func appendLog(type: String, subject: String?, member: DeviceInfo?, epoch: Int, admin: AdminSigner, by: String? = nil,
                           keys: [ControlRecords.AKLink]? = nil) async throws {
        let chain: [ControlRecords.AKLink]
        if let keys { chain = keys } else { chain = try await currentHead()?.head.aks ?? [] }
        for _ in 0..<8 {
            let (n, prev, replacing) = try await logTail(keys: chain)
            let entry = ControlRecords.LogEntry(n: n, prev: prev, type: type, by: by ?? deviceID, subject: subject, epoch: epoch, ts: Self.now, member: member)
            let record = try signed(LaneRecord(kind: .log, id: ControlRecords.logID(n), rev: 0, epoch: epoch, blob: try ControlRecords.encode(entry), writer: by ?? deviceID), by: admin)
            if case .accepted = try await storage.write([LaneWrite(record: record, expect: replacing.map { .tag($0) } ?? .absent)])[0] { return }
        }
        throw SyncError.malformedResponse
    }
}
