import Foundation
import CryptoKit
import BiselCrypto
import BiselLane
import BiselVault

/// A box on a lane that is only storage: the control operations of `BoxLane` as signed records (docs/SYNC-LANES.md §2, §4, §5).
///
/// Nothing here trusts the storage. What it writes is signed by the vault-admin key (derived from the vault key, so only a
/// holder can) or by the device's own signing key, and `LaneVerifier` checks all of it on the way back in. Revocation is
/// the key rotation itself, which `rotate` writes as one atomic commit: lanes that cannot commit that many records need the
/// staged form (milestone L4) and refuse here.
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

    /// An item written for an epoch the box has left is refused up front; one that slips through a race is quarantined on read.
    public func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult] {
        let epoch = try await currentHead()?.head.epoch
        var results = [LaneWriteResult?](repeating: nil, count: batch.count)
        var forwarded: [LaneWrite] = []
        for (i, w) in batch.enumerated() {
            if w.record.isItemLike, let epoch, w.record.epoch != epoch { results[i] = .rejected(.staleEpoch(serverEpoch: epoch)) }
            else { forwarded.append(w) }
        }
        var answers = try await storage.write(forwarded).makeIterator()
        return results.map { $0 ?? answers.next() ?? .rejected(.forbidden) }
    }

    // MARK: control

    public func members() async throws -> [DeviceInfo] { memberList() }

    public func admit(_ device: WireDevice, admin: AdminSigner) async throws {
        guard let (head, _) = try await currentHead() else { throw SyncError.notAuthorized }
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
        guard let (head, _) = try await currentHead(), let root = head.aks.first?.ak else { throw SyncError.notAuthorized }
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

    public func rotate(baseEpoch: Int, baseSeq: Int, revoke: String?, newAdmin: AdminSigner,
                       items: [(id: String, rev: Int, wrappedKey: Data)], tombstones: [(id: String, rev: Int, marker: Data)],
                       devices: [(id: String, envelope: Data)], recoveryEnvelope: Data,
                       admin: AdminSigner) async throws -> (outcome: RotateOutcome, written: [LaneRecord]) {
        let behind = (outcome: RotateOutcome.conflict(epoch: baseEpoch, headSeq: nil), written: [LaneRecord]())
        guard let (head, headRecord) = try await currentHead(), head.epoch == baseEpoch else { return behind }
        let newEpoch = baseEpoch + 1
        let refs = (items.map(\.id) + tombstones.map(\.id)).map { LaneRecordRef(kind: .item, id: $0) }
        // The kind of a stored record is not known to the caller: look each one up under every item-like kind.
        var current: [String: LaneRecord] = [:]
        for kind in [LaneKind.item, .manifest, .tombstone] {
            for (ref, found) in zip(refs, try await storage.read(refs.map { LaneRecordRef(kind: kind, id: $0.id) })) {
                if let found, current[ref.id] == nil { current[ref.id] = found }
            }
        }
        var batch: [LaneWrite] = []
        var rewritten: [Int] = []
        for item in items {
            guard let cur = current[item.id], cur.rev == item.rev, cur.kind != .tombstone else { return behind }
            var r = cur
            r.blob = item.wrappedKey + cur.blob.dropFirst(ItemSealer.wrappedKeyLength)
            r.epoch = newEpoch
            r.writer = deviceID
            rewritten.append(batch.count)
            batch.append(LaneWrite(record: r, expect: cur.tag.map { .tag($0) } ?? .any))
        }
        for tomb in tombstones {
            guard let cur = current[tomb.id], cur.rev == tomb.rev, cur.kind == .tombstone else { return behind }
            var r = cur
            r.blob = tomb.marker
            r.epoch = newEpoch
            r.writer = deviceID
            rewritten.append(batch.count)
            batch.append(LaneWrite(record: r, expect: cur.tag.map { .tag($0) } ?? .any))
        }
        for d in devices {
            batch.append(LaneWrite(record: try signed(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: newEpoch, device: d.id), rev: 0,
                                                                 epoch: newEpoch, blob: d.envelope, writer: deviceID), by: newAdmin), expect: .any))
        }
        if let currentRecovery = try await readOne(.recovery, ControlRecords.recoveryID),
           let rec = ControlRecords.decode(ControlRecords.Recovery.self, currentRecovery.blob) {
            let next = ControlRecords.Recovery(seq: rec.seq + 1, epoch: newEpoch, pubkey: rec.pubkey, encPubkey: rec.encPubkey,
                                               envelope: recoveryEnvelope.base64URLEncoded(), anchor: rec.anchor)
            batch.append(LaneWrite(record: try signed(LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: newEpoch,
                                                                 blob: try ControlRecords.encode(next), writer: deviceID), by: newAdmin),
                                   expect: currentRecovery.tag.map { .tag($0) } ?? .any))
        }
        let (n, prev, replacing) = try await logTail(keys: head.aks)
        let entry = ControlRecords.LogEntry(n: n, prev: prev, type: "rotate", by: deviceID, subject: revoke, epoch: newEpoch, ts: Self.now)
        batch.append(LaneWrite(record: try signed(LaneRecord(kind: .log, id: ControlRecords.logID(n), rev: 0, epoch: newEpoch,
                                                             blob: try ControlRecords.encode(entry), writer: deviceID), by: newAdmin),
                               expect: replacing.map { .tag($0) } ?? .absent))
        let link = ControlRecords.AKLink(epoch: newEpoch, ak: newAdmin.publicKey, sig: try admin.sign(ControlRecords.chainMessage(newKey: newAdmin.publicKey)))
        let newHead = ControlRecords.Head(epoch: newEpoch, aks: head.aks + [link])
        batch.append(LaneWrite(record: try signed(LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: newEpoch,
                                                             blob: try ControlRecords.encode(newHead), writer: deviceID), by: newAdmin),
                               expect: headRecord.tag.map { .tag($0) } ?? .any))

        guard storage.capabilities.atomicBatch >= batch.count else { throw LaneError.unsupported }
        let results = try await storage.commit(batch)
        guard results.count == batch.count, results.allSatisfy({ if case .accepted = $0 { return true } else { return false } }) else { return behind }
        let written = rewritten.compactMap { i -> LaneRecord? in if case .accepted(let r) = results[i] { return r } else { return nil } }
        return (.rotated(epoch: newEpoch, headSeq: 0), written)
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
    public func anchoredRecoveryEnvelope(recoverySigningKey: Data) async throws -> (envelope: Data, epoch: Int, adminKey: Data) {
        guard let (head, _) = try await currentHead(), let root = head.aks.first?.ak, let current = head.aks.last?.ak,
              let (rec, envelope) = try await recovery(under: head),
              let anchor = rec.anchor.flatMap({ Data(base64URLEncoded: $0) }),
              let signer = try? Curve25519.Signing.PublicKey(rawRepresentation: recoverySigningKey),
              signer.isValidSignature(anchor, for: ControlRecords.anchorMessage(root: root)) else { throw SyncError.notAuthorized }
        return (envelope, rec.epoch, current)
    }

    public func recoveryRegister(device: WireDevice, epoch: Int, admin: AdminSigner) async throws -> Date? {
        guard let (head, _) = try await currentHead() else { throw SyncError.notAuthorized }
        if epoch != head.epoch { throw RotationError.staleEpoch(serverEpoch: head.epoch) }
        guard let envelope = device.envelope.flatMap({ Data(base64URLEncoded: $0) }) else { throw SyncError.malformedResponse }
        try await put(try envelopeRecord(device: device.id, epoch: epoch, envelope: envelope, admin: admin))
        try await appendLog(type: "recovery", subject: device.id, member: Self.member(device), epoch: epoch, admin: admin, by: device.id)
        return nil
    }

    public func create(_ box: NewBox) async throws -> SyncClient.BootstrapResult {
        guard let envelope = box.device.envelope.flatMap({ Data(base64URLEncoded: $0) }) else { throw SyncError.malformedResponse }
        let admin = box.admin
        let recovery = ControlRecords.Recovery(seq: 1, epoch: 1, pubkey: box.recoveryPublicKey.base64URLEncoded(),
                                               encPubkey: box.recoveryEncryptionPublicKey.base64URLEncoded(), envelope: box.recoveryEnvelope.base64URLEncoded(),
                                               anchor: box.recoveryAnchor?.base64URLEncoded())
        try await put(try signed(LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: 1,
                                            blob: try ControlRecords.encode(recovery), writer: box.device.id), by: admin))
        try await put(try envelopeRecord(device: box.device.id, epoch: 1, envelope: envelope, admin: admin))
        try await appendLog(type: "bootstrap", subject: box.device.id, member: Self.member(box.device), epoch: 1, admin: admin, by: box.device.id,
                            keys: [.init(epoch: 1, ak: admin.publicKey, sig: nil)])
        let head = ControlRecords.Head(epoch: 1, aks: [.init(epoch: 1, ak: admin.publicKey, sig: nil)])
        let record = try signed(LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: 1, blob: try ControlRecords.encode(head), writer: box.device.id), by: admin)
        // The head goes last and only once: its existence is what makes this lane a box.
        guard case .accepted = try await storage.write([LaneWrite(record: record, expect: .absent)])[0] else { throw SyncError.conflict(current: nil) }
        return SyncClient.BootstrapResult(deviceID: box.device.id, boxID: nil, headSeq: 0, epoch: 1)
    }

    public func attest(counter: Int, epoch: Int) async throws {
        guard let deviceID, let signDevice else { return }
        var record = LaneRecord(kind: .head, id: ControlRecords.deviceHeadID(deviceID), rev: 0, epoch: epoch,
                                blob: try ControlRecords.encode(ControlRecords.DeviceHead(device: deviceID, counter: counter, epoch: epoch)), writer: deviceID)
        record.sig = try signDevice(record.canonical)
        try await put(record)
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

    private func signed(_ record: LaneRecord, by admin: AdminSigner) throws -> LaneRecord {
        var r = record
        r.sig = try admin.sign(r.canonical)
        return r
    }

    private func envelopeRecord(device: String, epoch: Int, envelope: Data, admin: AdminSigner) throws -> LaneRecord {
        try signed(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: epoch, device: device), rev: 0, epoch: epoch, blob: envelope, writer: deviceID), by: admin)
    }

    /// Unconditional write of one record; anything but an acceptance is a failure of the lane.
    private func put(_ record: LaneRecord) async throws {
        guard case .accepted = try await storage.write([LaneWrite(record: record, expect: .any)])[0] else { throw SyncError.malformedResponse }
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
