#if BISEL_SOFTWARE_KEYS
import Foundation
import CryptoKit
import BiselCore
import BiselTestSupport

// The lane contract (docs/SYNC-LANES.md §10): the flows that must behave the same whichever lane carries the box. The flow
// tests run them against the in-memory `FakeLane` and the real server (`wrangler dev`, local D1); the signed app built from
// project.contract.yml runs them against CloudKit (opt-in, never in CI). A lane that passes is a lane the engine can trust
// the way it trusts the server today. Lane-specific behaviour (server endpoints, accounts, device codes) is covered by the
// other flow files.

public struct ContractFlow: Sendable {
    public let name: String
    let body: @Sendable (Rig, Checks) async throws -> Void
}

public enum LaneContract {
    /// Runs one flow on a fresh box and returns what it found wrong (empty: it passed).
    public static func run(_ flow: ContractFlow, on lane: ContractLane) async -> [Checks.Failure] {
        let c = Checks()
        do { try await Rig.with(lane) { try await flow.body($0, c) } }
        catch is Checks.Stop {}
        catch { c.fail("unexpected error: \(String(reflecting: error))") }
        return c.failures
    }

    public static func flow(named name: String) -> ContractFlow? { (flows + hostile).first { $0.name == name } }

    /// The flows every lane must pass.
    public static let flows: [ContractFlow] = [
        ContractFlow(name: "two devices converge on edits and deletes, and the lane only ever holds ciphertext") { rig, c in
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            c.expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw", "the enrolled device reads the first device's item")
            var edit = try await b.vault.item(id: bank.id); edit.password = "bank-pw-2"
            _ = try await b.vault.save(edit)
            let mail = try await b.vault.save(login("Mail", password: "mail-pw"))
            try await b.vault.sync()
            try await a.vault.sync()
            c.expect(try await a.vault.revealPassword(id: bank.id) == "bank-pw-2", "an edit reaches the other device")
            c.expect(try await a.vault.revealPassword(id: mail.id) == "mail-pw", "a new item reaches the other device")

            try await a.vault.delete(id: mail.id)
            try await a.vault.sync()
            try await b.vault.sync()
            c.expect(try await b.vault.items().items.map(\.title) == ["Bank"], "a delete reaches the other device")

            let held = try await rig.records(as: a, c)
            c.expect(!held.contains { $0.blob.range(of: Data("bank-pw".utf8)) != nil }, "the lane holds no plaintext")
            c.expect(try await a.vault.pendingChanges() == 0, "nothing left pending on a")
            c.expect(try await b.vault.pendingChanges() == 0, "nothing left pending on b")
        },

        ContractFlow(name: "concurrent edits keep the remote version and save the local edit as a '(conflict)' copy") { rig, c in
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            let item = try await a.vault.save(login("Router", user: "admin", password: "orig"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            var editA = try await a.vault.item(id: item.id); editA.password = "from-A"
            var editB = try await b.vault.item(id: item.id); editB.password = "from-B"
            _ = try await a.vault.save(editA)
            _ = try await b.vault.save(editB)

            c.expect(try await a.vault.sync().conflicts.isEmpty, "the first writer has no conflict")
            let conflict = try c.require(try await b.vault.sync().conflicts.first, "the second writer gets a conflict")
            c.expect(try await b.vault.revealPassword(id: item.id) == "from-A", "the remote version is kept")
            c.expect(try await b.vault.item(id: conflict.copyID).title == "Router (conflict)", "the local edit becomes a '(conflict)' copy")
            c.expect(try await b.vault.revealPassword(id: conflict.copyID) == "from-B", "the copy holds the local edit")
            try await a.vault.sync()
            c.expect(try await a.vault.revealPassword(id: conflict.copyID) == "from-B", "the copy reaches the other device")
        },

        ContractFlow(name: "a forged delete is undone and a lane that lost state is noticed and healed from the replica") { rig, c in
            let a = try rig.device("a"), b = try rig.device("b")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.save(login("Mail", password: "mail-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            // A delete nobody sealed with the vault key is not honoured.
            try await rig.forgeDelete(bank.id, as: a, c)
            let report = try await b.vault.sync()
            c.expect(report.rejectedTombstones == [bank.id], "the forged delete is rejected (\(report.rejectedTombstones))")
            c.expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw", "the item survives the forged delete")
            try await b.vault.sync()
            try await a.vault.sync()
            c.expect(try await a.vault.revealPassword(id: bank.id) == "bank-pw", "the other device still has the item")

            // The lane forgets its newest write: noticed, and put back from the replica.
            let newest = try await b.vault.save(login("Newest", password: "newest-pw"))
            try await b.vault.sync()
            let lost = try await rig.loseNewestWrite(as: b, c)
            try await rig.noticeAndHeal(b, lost: lost, c)
            c.expect(try await b.vault.pendingChanges() == 0, "nothing left pending after the heal")

            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.revealPassword(id: newest.id) == "newest-pw", "a fresh device recovers the healed record")
        },

        ContractFlow(name: "revoking a device rotates the key: the revoked device's key opens nothing the lane holds, the others carry on") { rig, c in
            let a = try rig.device("a"), b = try rig.device("b"), d = try rig.device("c")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            try await rig.enroll(d, through: a)

            let bIdentity = try c.require(try await b.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try c.require(bIdentity.envelope), reason: "test")
            func opens(_ r: StoredRecord) -> Bool {
                (try? ItemSealer.open(blob: r.blob, id: r.id, rev: r.rev, vaultKey: SymmetricKey(data: oldVK))) != nil
            }
            let before = try await rig.records(as: a, c).filter { !$0.deleted }
            c.expect(before.allSatisfy(opens), "sanity: the old key opens the lane's ciphertext before the revoke")

            try await a.vault.revoke(deviceID: bIdentity.deviceID)
            try await a.vault.sync()
            c.expect(try await a.vault.devices().first { $0.id == bIdentity.deviceID }?.isRevoked == true, "the device is listed as revoked")
            let after = try await rig.records(as: a, c).filter { !$0.deleted }
            c.expect(after.count == before.count, "the lane holds as many items after the rotation (\(before.count) → \(after.count))")
            c.expect(after.allSatisfy { !opens($0) }, "everything the lane holds is closed to the revoked device's key")

            let report = try await d.vault.sync()
            c.expect(report.rotationAdopted, "the remaining device adopts the rotation")
            try await d.vault.unlock()
            c.expect(try await d.vault.revealPassword(id: bank.id) == "bank-pw", "the remaining device reads under the new key")
            var edit = try await d.vault.item(id: bank.id); edit.password = "after-rotation"
            _ = try await d.vault.save(edit)
            try await d.vault.sync()
            try await a.vault.sync()
            c.expect(try await a.vault.revealPassword(id: bank.id) == "after-rotation", "edits after the rotation sync")

            // The same 24 words still recover the box after the rotation.
            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.revealPassword(id: bank.id) == "after-rotation", "the phrase recovers the rotated box")
        },

        ContractFlow(name: "the 24 words rebuild a box on a fresh device; a stranger's words and a rotated-away phrase do not") { rig, c in
            let a = try rig.device("a")
            let phrase = try await rig.bootstrap(a)
            let item = try await a.vault.save(login("Passport", password: "p-recover"))
            try await a.vault.sync()

            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.revealPassword(id: item.id) == "p-recover", "the phrase rebuilds the box")
            try await a.vault.sync()
            c.expect(try await a.vault.devices().count == 2, "the recovered device is listed")

            let stranger = try rig.device("stranger")
            await c.expectThrows("a stranger's phrase must not open the box") { try await rig.recover(stranger, phrase: try RecoveryPhrase.generate()) }

            let newPhrase = try await fresh.vault.rotateRecovery()
            let old = try rig.device("old")
            await c.expectThrows("a rotated-away phrase must not open the box") { try await rig.recover(old, phrase: phrase) }
            let again = try rig.device("again")
            try await rig.recover(again, phrase: newPhrase)
            try await again.vault.sync()
            c.expect(try await again.vault.revealPassword(id: item.id) == "p-recover", "the new phrase opens the box")
        },

        ContractFlow(name: "a box synced before lanes existed, with edits still pending, keeps its queue and its position through the migration") { rig, c in
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            var synced = try await a.vault.save(login("Synced", password: "s1"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            // Offline edits on top of a confirmed revision, and a brand-new item.
            synced.password = "s2"
            _ = try await a.vault.save(synced)
            let created = try await a.vault.save(login("Created offline", password: "c1"))
            c.expect(try await a.vault.pendingChanges() == 2, "two edits pending before the migration")

            try rig.downgradeToBeforeLanes(a.location)
            let reopened = try a.relaunched()
            try await reopened.unlock()
            let report = try await reopened.sync()
            c.expect(report.pushed == 2 && report.conflicts.isEmpty,
                     "the pending queue goes up as it was: no re-download, no '(conflict)' copies (pushed \(report.pushed), conflicts \(report.conflicts.count))")
            c.expect(try await reopened.pendingChanges() == 0, "nothing left pending after the migration")

            try await b.vault.sync()
            c.expect(try await b.vault.revealPassword(id: synced.id) == "s2", "the migrated edit reaches the other device")
            c.expect(try await b.vault.revealPassword(id: created.id) == "c1", "the migrated new item reaches the other device")
        },
    ]

    /// A lane that is only storage and misbehaves (nothing the server lane can be made to do). They drive `FakeLane` directly.
    public static let hostile: [ContractFlow] = [
        ContractFlow(name: "a lane restored to an older snapshot is caught by a full read and put right from the replica; nothing newer is lost") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            var x = try await a.vault.save(login("Kept", password: "x1"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            let snapshot = fake.snapshot()

            x.password = "x2"
            _ = try await a.vault.save(x)
            let y = try await a.vault.save(login("Newer", password: "y1"))
            try await a.vault.sync()
            fake.restore(snapshot)

            _ = try await a.vault.sync()   // reading only what is new, the restored lane looks quiet
            do { _ = try await a.vault.sync(audit: true); c.fail("a full read must notice the rollback") }
            catch IntegrityError.serverRolledBack {}

            try await a.vault.acknowledgeServerReset()
            let report = try await a.vault.sync()
            c.expect(report.conflicts.isEmpty, "the heal makes no conflict copies")
            c.expect(try await a.vault.pendingChanges() == 0, "nothing left pending after the heal")
            try await b.vault.sync()
            c.expect(try await b.vault.revealPassword(id: x.id) == "x2", "the newer edit survives the rollback")
            c.expect(try await b.vault.revealPassword(id: y.id) == "y1", "the newer item survives the rollback")
        },

        ContractFlow(name: "a replayed old version, a hard delete and a silently dropped record are each put back from the replica, with no conflict copies") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            var x = try await a.vault.save(login("Replayed", password: "x1"))
            let y = try await a.vault.save(login("Deleted", password: "y1"))
            let z = try await a.vault.save(login("Dropped", password: "z1"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            let old = try c.require(fake.record(x.id))

            x.password = "x2"
            _ = try await a.vault.save(x)
            try await a.vault.sync()
            fake.replay(old)
            fake.hardDelete(y.id)
            fake.dropSilently(z.id)

            let report = try await a.vault.sync(audit: true)
            c.expect(report.repaired == 3 && report.conflicts.isEmpty, "all three are repaired, no conflicts (repaired \(report.repaired))")
            c.expect(report.incidents.contains(.removed(.init(kind: .item, id: y.id))), "the hard delete is an incident")
            c.expect(report.incidents.contains(.lost(count: 1)), "the silent drop is an incident")
            try await b.vault.sync()
            c.expect(try await b.vault.revealPassword(id: x.id) == "x2", "the replayed record is put right")
            c.expect(try await b.vault.revealPassword(id: y.id) == "y1", "the hard-deleted record is put back")
            c.expect(try await b.vault.revealPassword(id: z.id) == "z1", "the dropped record is put back")
        },

        ContractFlow(name: "records forged by someone without the vault key, and writes for a key the box has left, are quarantined; out-of-order pages change nothing") { rig, c in
            let fake = try c.require(rig.fake)
            fake.setReordering(true)
            let a = try rig.device("a"), b = try rig.device("b"), d = try rig.device("c")
            _ = try await rig.bootstrap(a)
            let item = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            try await rig.enroll(d, through: a)
            c.expect(try await b.vault.revealPassword(id: item.id) == "bank-pw", "out-of-order pages still sync")

            // A forged "approve" entry (right place in the chain, wrong signature) and a forged envelope.
            let tail = try c.require(fake.records().filter { $0.kind == .log }.max { ($0.id.count, $0.id) < ($1.id.count, $1.id) })
            let n = try c.require(ControlRecords.logNumber(tail.id)) + 1
            let rogue = DeviceInfo(id: "rogue", name: "Rogue", kind: "mac", sigPubkey: Data(repeating: 4, count: 65).base64URLEncoded(),
                                   encPubkey: Data(repeating: 5, count: 65).base64URLEncoded(), createdAt: 0)
            let entry = ControlRecords.LogEntry(n: n, prev: ControlRecords.logHash(tail.blob), type: "approve", by: "rogue", subject: "rogue", epoch: 1, ts: 0, member: rogue)
            let garbage = Data(repeating: 7, count: 64)
            fake.inject(LaneRecord(kind: .log, id: ControlRecords.logID(n), rev: 0, epoch: 1, blob: try ControlRecords.encode(entry), sig: garbage))
            fake.inject(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: 1, device: "rogue"), rev: 0, epoch: 1, blob: Data(repeating: 9, count: 100), sig: garbage))
            let report = try await a.vault.sync()
            c.expect(report.quarantined == 2, "both forged records are quarantined (\(report.quarantined))")
            var ids: [String] = []
            for x in [a, b, d] { ids.append(try c.require(try await x.vault.identity()?.deviceID)) }
            c.expect(try await a.vault.devices().map(\.id).sorted() == ids.sorted(), "the rogue device is not a member")

            // The box still rotates (the rogue device is not given the new key), and a late write for the old key is quarantined, not applied.
            let bID = try c.require(try await b.vault.identity()?.deviceID)
            try await a.vault.revoke(deviceID: bID)
            fake.inject(LaneRecord(kind: .item, id: "late-write-by-b", rev: 1, epoch: 1, blob: Data(repeating: 3, count: 200)))
            let after = try await a.vault.sync()
            c.expect(after.quarantined == 1, "the stale-epoch write is quarantined (\(after.quarantined))")
            c.expect(try await a.vault.items().undecryptable.isEmpty, "nothing undecryptable is applied")
            c.expect(try await a.vault.items().items.map(\.title) == ["Bank"], "the box is unchanged")
        },
        ContractFlow(name: "someone who can only write to the storage cannot make a device adopt a vault key of their choosing and upload under it") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a")
            _ = try await rig.bootstrap(a)
            _ = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            let me = try c.require(try await a.vault.identity())
            let enc = try c.require(me.roster.first?.encPubkey)

            // A rotation announced by a head nobody with the admin key signed, an envelope to this device's public key holding a key
            // the writer picked, and a manifest sealed under that key so it "confirms" it.
            let evil = BiselRandom.bytes(32)
            var head = try c.require(ControlRecords.decode(ControlRecords.Head.self, try c.require(fake.record(ControlRecords.headID)).blob))
            head.epoch += 1
            fake.inject(LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: head.epoch, blob: try ControlRecords.encode(head),
                                   sig: Data(repeating: 7, count: 64)))
            fake.inject(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: head.epoch, device: me.deviceID), rev: 0, epoch: head.epoch,
                                   blob: try DeviceEnvelope.seal(vaultKey: evil, toEncryptionKey: enc)))
            let rev = try c.require(fake.record(ReservedRecord.manifestID)).rev + 1
            let planted = try ManifestCodec.seal(VaultManifest(), rev: rev, vaultKey: SymmetricKey(data: evil))
            fake.inject(LaneRecord(kind: .manifest, id: ReservedRecord.manifestID, rev: rev, epoch: head.epoch, blob: planted))

            _ = try await a.vault.save(login("New", password: "new-pw"))
            _ = try? await a.vault.sync()
            try await a.vault.unlock()
            _ = try? await a.vault.sync()
            _ = try? await a.vault.sync()

            for r in fake.records() where r.isItemLike && r.kind != .tombstone && r.blob != planted {
                c.expect((try? ItemSealer.open(blob: r.blob, id: r.id, rev: r.rev, vaultKey: SymmetricKey(data: evil))) == nil,
                         "nothing this device uploads opens under the planted key (\(r.id))")
            }
            c.expect(try await a.vault.identity()?.epoch == me.epoch, "the unsigned head announced no rotation")
        },
        ContractFlow(name: "a revoked device that kept the old admin key cannot replace the recovery material, here or for a device recovering, nor wedge sync with its counter") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a"), b = try rig.device("b")
            let phrase = try await rig.bootstrap(a)
            _ = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            _ = try await b.vault.save(login("From b", password: "b-pw"))   // b writes, so the box has seen a counter of b's
            try await b.vault.sync()
            try await a.vault.sync()
            let bIdentity = try c.require(try await b.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try c.require(bIdentity.envelope), reason: "test")
            try await a.vault.revoke(deviceID: bIdentity.deviceID)
            try await a.vault.sync()

            // Signed with the admin key of the epoch b was cut off in: the real recovery keys, with an envelope holding the old key.
            let keys = try RecoveryKeys(phrase: phrase)
            let stale = ControlRecords.Recovery(seq: 99, epoch: 1, pubkey: keys.publicKey.base64URLEncoded(), encPubkey: keys.encryptionPublicKey.base64URLEncoded(),
                                                envelope: try keys.seal(vaultKey: oldVK, epoch: 1).base64URLEncoded())
            var record = LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: 1, blob: try ControlRecords.encode(stale),
                                    writer: bIdentity.deviceID)
            record.sig = try AdminSigner(vaultKey: oldVK).sign(record.canonical)
            fake.inject(record)
            // And its own counter, lower than the one the box saw: on every device that reads as the lane rolling back.
            var counter = LaneRecord(kind: .head, id: ControlRecords.deviceHeadID(bIdentity.deviceID), rev: 0, epoch: 1,
                                     blob: try ControlRecords.encode(ControlRecords.DeviceHead(device: bIdentity.deviceID, counter: 0, epoch: 1)),
                                     writer: bIdentity.deviceID)
            counter.sig = try b.keyStore.sign(counter.canonical)
            fake.inject(counter)

            let envelopeBefore = try await a.vault.identity()?.recoveryEnvelope
            c.expect(try await a.vault.sync().quarantined == 2, "the old-epoch recovery record and the revoked device's counter are quarantined")
            c.expect(try await a.vault.identity()?.recoveryEnvelope == envelopeBefore, "the device keeps the recovery envelope it had")
            let fresh = try rig.device("fresh")
            await c.expectThrows("a fresh device does not recover into the key the revoked device holds") {
                try await rig.recover(fresh, phrase: phrase)
            }
        },
    ]
}
#endif
