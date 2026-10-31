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
    /// `serverForMoves`: a flow that moves a box onto the storage may start the real server as where it comes from.
    public static func run(_ flow: ContractFlow, on lane: ContractLane, serverForMoves: Bool = false) async -> [Checks.Failure] {
        let c = Checks()
        do { try await Rig.with(lane, serverForMoves: serverForMoves) { try await flow.body($0, c) } }
        catch is Checks.Stop {}
        catch { c.fail("unexpected error: \(String(reflecting: error))") }
        return c.failures
    }

    public static func flow(named name: String) -> ContractFlow? { (flows + storageOnly + hostile).first { $0.name == name } }

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

    /// Flows of a lane that is only storage (milestone L4): the staged rotation, enrollment over the lane, account changes,
    /// a deleted store, moving a box onto it. The server keeps these on its side, so they run on `FakeLane` in the flow tests
    /// and on CloudKit in the signed contract run, never against the server.
    public static let storageOnly: [ContractFlow] = [
        ContractFlow(name: "signing out pauses the lane with edits kept, another account is never uploaded to, and moving the box to it loses nothing") { rig, c in
            let account = try c.require(rig.account)
            let a = try rig.device("a"), b = try rig.device("b")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            // Signed out: nothing syncs, nothing is lost, and it resumes by itself.
            account.signIn(.signedOut("no iCloud account"))
            var edit = try await a.vault.item(id: bank.id); edit.password = "while-signed-out"
            _ = try await a.vault.save(edit)
            await c.expectThrows("a signed-out account cannot sync") { try await a.vault.sync() }
            let paused = try await a.vault.laneStatus()
            c.expect(paused == .accountUnavailable("no iCloud account"), "the lane reads as paused (\(paused))")
            c.expect(try await a.vault.pendingChanges() == 1, "the edit stays pending")
            account.signIn(.first)
            try await a.vault.sync()
            c.expect(try await a.vault.laneStatus() == .active, "the lane resumes once the account is back")
            try await b.vault.sync()
            c.expect(try await b.vault.revealPassword(id: bank.id) == "while-signed-out", "the edit made while signed out arrives")

            // Another account: never uploaded to, until the person moves the box there.
            account.signIn(.second)
            let offline = try await a.vault.save(login("Made on the new account", password: "new-acct"))
            do { try await a.vault.sync(); c.fail("a sync must not run against another account") } catch LaneError.accountChanged {}
            c.expect(try await a.vault.laneStatus() == .accountChanged, "the lane reads as on another account")
            // The other account has no zone at all on CloudKit (missing), an empty store on the fake: either way, nothing of ours.
            let reached = try await { () async throws -> [StoredRecord] in
                do { return try await rig.records(as: a, c) } catch LaneError.storeMissing { return [] }
            }()
            c.expect(reached.isEmpty, "nothing reached the other account's storage")
            let moved = try await a.vault.enableLane(rig.address)
            c.expect(moved.created, "the box is put on the new account's storage")
            c.expect(try await a.vault.laneStatus() == .active, "the lane is active on the new account")
            c.expect(try await a.vault.pendingChanges() == 0, "nothing left pending after the move")
            c.expect(try await rig.records(as: a, c).count >= 3, "the new storage holds the items and the manifest")
            // The other device signed in to the same new account joins the box already there.
            do { try await b.vault.sync(); c.fail("b must not sync against another account either") } catch LaneError.accountChanged {}
            let joined = try await b.vault.enableLane(rig.address)
            c.expect(!joined.created, "b finds the box a put there and joins it")
            c.expect(try await b.vault.revealPassword(id: offline.id) == "new-acct", "b reads what a made")
            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.revealPassword(id: bank.id) == "while-signed-out", "the 24 words recover the box on the new account")
        },

        ContractFlow(name: "storage deleted by the person is noticed, never recreated behind their back, and put back from the replica without losing an edit") { rig, c in
            let lane = try c.require(rig.account)
            let a = try rig.device("a"), b = try rig.device("b")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            _ = try await a.vault.save(login("Mail", password: "mail-pw"))
            try await a.vault.sync()
            try await b.vault.sync()

            try await lane.erase(confirmed: LaneEraseToken())   // "Delete Bisel data" in iCloud settings
            var edit = try await b.vault.item(id: bank.id); edit.password = "after-the-delete"
            _ = try await b.vault.save(edit)
            do { try await b.vault.sync(); c.fail("a deleted store must be reported") } catch LaneError.storeMissing {}
            let missing = try await b.vault.laneStatus()
            c.expect(missing == .storeMissing, "the lane reads as deleted (\(missing))")
            do { _ = try await lane.fetch(since: nil, limit: 1); c.fail("the failed sync must not have recreated the store") } catch LaneError.storeMissing {}
            c.expect(try await b.vault.pendingChanges() == 1, "the edit stays pending")

            // The person uploads a's copy again; b carries on, after accepting the reset if it noticed one.
            let put = try await a.vault.enableLane(rig.address)
            c.expect(put.created && put.uploaded >= 3, "the replica goes back up (\(put.uploaded) records)")
            do { try await b.vault.sync(audit: true) } catch is IntegrityError {
                try await b.vault.acknowledgeServerReset()
                try await b.vault.sync()
            }
            c.expect(try await b.vault.pendingChanges() == 0, "b's edit made during the outage is uploaded")
            try await a.vault.sync()
            c.expect(try await a.vault.revealPassword(id: bank.id) == "after-the-delete", "and reaches a")
            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.items().items.map(\.title).sorted() == ["Bank", "Mail"], "the 24 words recover the box put back")
        },

        ContractFlow(name: "a box moves onto the storage lane with nothing lost, its old lane left alone, and the other device follows by itself") { rig, c in
            try await rig.withMoveSource { source in
                let a = try rig.device("a"), b = try rig.device("b")
                let phrase = try await source.bootstrap(a)
                let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
                let gone = try await a.vault.save(login("Deleted", password: "gone"))
                try await a.vault.sync()
                try await source.enroll(b, through: a)
                try await a.vault.delete(id: gone.id)
                try await a.vault.sync()
                var edit = try await b.vault.item(id: bank.id); edit.password = "b-before-the-move"
                _ = try await b.vault.save(edit)
                try await b.vault.sync()
                try await a.vault.sync()

                // Moving needs the 24 words when the box never lived on storage that keeps its own control records.
                if source.server != nil {
                    await c.expectThrows("a box from the server is not moved without the phrase") { try await a.vault.enableLane(rig.address) }
                }
                try await a.vault.enableLane(rig.address, phrase: phrase)
                c.expect(try await a.vault.identity()?.serverURL == rig.address, "a now syncs through the storage lane")
                c.expect(try await a.vault.pendingChanges() == 0, "nothing left pending on a")
                let held = try await rig.records(as: a, c)
                c.expect(held.contains { $0.id == bank.id } && held.contains { $0.id == gone.id && $0.deleted }, "items and tombstones are on the lane")

                // b is still on the old lane; an edit made there before it notices still arrives.
                let late = try await b.vault.save(login("Made on the old lane", password: "late"))
                try await b.vault.sync()   // pushes to the old lane, sees the move in the sealed manifest
                try await b.vault.sync()   // follows
                c.expect(try await b.vault.identity()?.serverURL == rig.address, "b followed the move")
                try await a.vault.sync()
                c.expect(try await a.vault.revealPassword(id: late.id) == "late", "b's late edit reaches a on the new lane")
                c.expect(try await a.vault.revealPassword(id: bank.id) == "b-before-the-move", "b's earlier edit came along")
                c.expect(try await b.vault.pendingChanges() == 0, "nothing left pending on b")

                let fresh = try rig.device("fresh")
                try await rig.recover(fresh, phrase: phrase)
                try await fresh.vault.sync()
                c.expect(try await fresh.vault.items().items.map(\.title).sorted() == ["Bank", "Made on the old lane"], "the 24 words recover the moved box")
            }
        },
        ContractFlow(name: "a new device on the same account joins through the lane with the 8 words, and the lane keeps no request afterwards") { rig, c in
            let storage = try c.require(rig.storage)
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()

            let offer = try await b.vault.prepareEnrollment(lane: rig.address, deviceName: b.name)
            do { try await b.vault.completeEnrollment(); c.fail("nothing is taken before the approval") } catch EnrollmentError.notApprovedYet {}

            try await a.vault.sync()
            let pending = try c.require(try await a.vault.pendingEnrollments().first { $0.request.deviceID == offer.request.deviceID },
                                        "the approver lists the request it saw on the lane")
            c.expect(pending.request.fingerprint == offer.fingerprint, "the listed request carries the new device's own keys")
            c.expect(!pending.isExpired, "a request just seen is not expired")
            try await a.vault.approveEnrollment(pending, pairing: try PairingSecret(words: offer.secret.words))

            try await b.vault.completeEnrollment()
            try await b.vault.unlock()
            try await b.vault.confirmEnrollment(code: try await a.vault.verificationCode())
            try await b.vault.sync()
            c.expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw", "the new device reads the box")
            c.expect(try await b.vault.identity()?.pairingSecret == nil, "the pairing secret is gone once the device joined")

            try await a.vault.sync()
            c.expect(try await a.vault.pendingEnrollments().isEmpty, "the approver lists nothing once the device joined")
            c.expect(try await enrollRecords(storage.lane).isEmpty, "the lane holds no enroll records afterwards")
        },

        ContractFlow(name: "a request whose keys were swapped, or the wrong words, are never approved, and a new device takes no envelope nobody with the words approved") { rig, c in
            let lane = try c.require(rig.storage).lane
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            let offer = try await b.vault.prepareEnrollment(lane: rig.address, deviceName: b.name)
            let bID = offer.request.deviceID

            // Someone with the storage account rewrites the request with keys of their own: same device id, their own valid
            // signature, the new device's proof copied over.
            let genuine = try c.require(try await lane.read([LaneRecordRef(kind: .enroll, id: ControlRecords.enrollID(bID))]).first ?? nil,
                                        "the request is on the lane")
            var request = try c.require(ControlRecords.decode(ControlRecords.EnrollRequest.self, genuine.blob))
            let mallorySig = P256.Signing.PrivateKey(), malloryEnc = P256.KeyAgreement.PrivateKey()
            request.sigPubkey = mallorySig.publicKey.x963Representation.base64URLEncoded()
            request.encPubkey = malloryEnc.publicKey.x963Representation.base64URLEncoded()
            var swapped = LaneRecord(kind: .enroll, id: genuine.id, rev: 0, epoch: genuine.epoch, blob: try ControlRecords.encode(request), writer: bID)
            swapped.sig = try mallorySig.signature(for: swapped.canonical).rawRepresentation
            try await put(swapped, on: lane, c)

            try await a.vault.sync()
            let forged = try c.require(try await a.vault.pendingEnrollments().first { $0.request.deviceID == bID }, "the rewritten request is listed")
            c.expect(forged.request.fingerprint != offer.fingerprint, "sanity: the listed request carries the swapped keys")
            do { try await a.vault.approveEnrollment(forged, pairing: offer.secret); c.fail("swapped keys must not be approved") }
            catch EnrollmentError.pairingMismatch {}

            // The genuine request, with words the person mistyped.
            try await put(genuine, on: lane, c)
            try await a.vault.sync()
            let real = try c.require(try await a.vault.pendingEnrollments().first { $0.request.deviceID == bID }, "the genuine request is listed")
            c.expect(real.request.fingerprint == offer.fingerprint, "sanity: the genuine request is back")
            do { try await a.vault.approveEnrollment(real, pairing: PairingSecret.generate()); c.fail("the wrong words must not approve") }
            catch EnrollmentError.pairingMismatch {}

            c.expect(try await a.vault.devices().allSatisfy { $0.id != bID }, "the device is not a member")
            c.expect(try await a.vault.roster().allSatisfy { $0.deviceID != bID }, "the device is not in the roster")
            c.expect(try await lane.read([LaneRecordRef(kind: .envelope, id: ControlRecords.envelopeID(epoch: 1, device: bID))]).first! == nil,
                     "no envelope was sealed to anyone")
            do { try await b.vault.completeEnrollment(); c.fail("nothing was approved") } catch EnrollmentError.notApprovedYet {}

            // A holder of the box key (a device, or one that kept the key) seals an envelope to the new device, with an approval
            // that carries the right pairing MAC but a signature nobody in the box made: not an approval.
            let aEnvelope = try c.require(try await a.vault.identity()?.envelope)
            let vk = try await a.keyStore.openEnvelope(aEnvelope, reason: "test")
            let admin = try AdminSigner(vaultKey: vk)
            let planted = try DeviceEnvelope.seal(vaultKey: vk, toEncryptionKey: offer.request.encPubkey)
            try await put(try adminSigned(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: 1, device: bID), rev: 0, epoch: 1, blob: planted),
                                          by: admin), on: lane, c)
            let rightMAC = offer.secret.approval(deviceID: bID, envelopeHash: planted.sha256Hex(), rootAdminKey: admin.publicKey, epoch: 1)
            try await put(try approvalRecord(bID, envelope: planted, epoch: 1, mac: rightMAC, by: AdminSigner(key: .init())), on: lane, c)
            do { try await b.vault.completeEnrollment(); c.fail("an approval the box did not sign is no approval") } catch EnrollmentError.notApprovedYet {}

            // Someone who cannot see the words builds a box of their own around the new device's public keys: their head, their
            // admin key, an envelope with their key, an approval they signed. Everything checks out but the pairing MAC.
            var theirs = BiselRandom.bytes(32)
            defer { theirs.zeroize() }
            let theirAdmin = try AdminSigner(vaultKey: theirs)
            let head = ControlRecords.Head(epoch: 1, aks: [.init(epoch: 1, ak: theirAdmin.publicKey, sig: nil)])
            try await put(try adminSigned(LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: 1, blob: try ControlRecords.encode(head)),
                                          by: theirAdmin), on: lane, c)
            let theirEnvelope = try DeviceEnvelope.seal(vaultKey: theirs, toEncryptionKey: offer.request.encPubkey)
            try await put(try adminSigned(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: 1, device: bID), rev: 0, epoch: 1,
                                                     blob: theirEnvelope), by: theirAdmin), on: lane, c)
            let guessed = PairingSecret.generate().approval(deviceID: bID, envelopeHash: theirEnvelope.sha256Hex(),
                                                            rootAdminKey: theirAdmin.publicKey, epoch: 1)
            try await put(try approvalRecord(bID, envelope: theirEnvelope, epoch: 1, mac: guessed, by: theirAdmin), on: lane, c)
            do { try await b.vault.completeEnrollment(); c.fail("an envelope nobody with the words approved is not taken") }
            catch EnrollmentError.approvalUnproven {}
            c.expect(await b.vault.isConfigured == false, "the new device holds no envelope")
            c.expect(try await b.vault.identity()?.pairingSecret != nil, "the new device still waits for the real approval")
        },
        ContractFlow(name: "a rotation the lane stops taking part-way leaves a box every device still reads at the old key, and the same revoke succeeds once the lane takes writes again") { rig, c in
            let flaky = try c.require(rig.flaky)
            let a = try rig.device("a"), b = try rig.device("b"), d = try rig.device("c")
            _ = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            try await rig.enroll(d, through: a)
            try await a.vault.sync()
            let bIdentity = try c.require(try await b.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try c.require(bIdentity.envelope), reason: "test")

            // The journal and the one chunk of staged keys go in, then the lane stops taking writes: the new envelopes never land.
            flaky.failWrites(after: 2)
            await c.expectThrows("the rotation fails while the lane takes no writes") { try await a.vault.revoke(deviceID: bIdentity.deviceID) }
            flaky.heal()
            c.expect(try await rig.stored(.stage).isEmpty, "the failed attempt leaves nothing staged on the lane")
            for x in [a, b, d] {
                c.expect(!(try await x.vault.sync().rotationAdopted), "\(x.name) sees no rotation")
                c.expect(try await x.vault.identity()?.epoch == 1, "\(x.name) is still at the old key")
                c.expect(try await x.vault.revealPassword(id: bank.id) == "bank-pw", "\(x.name) still reads the box")
            }
            var edit = try await d.vault.item(id: bank.id); edit.password = "between-attempts"
            _ = try await d.vault.save(edit)
            c.expect(try await d.vault.sync().pushed == 1, "nothing left behind holds other devices' edits off")

            try await a.vault.revoke(deviceID: bIdentity.deviceID)
            c.expect(try await rig.stored(.stage).isEmpty, "a finished rotation leaves nothing staged")
            let after = try await rig.records(as: a, c).filter { !$0.deleted }
            c.expect(after.allSatisfy { (try? ItemSealer.open(blob: $0.blob, id: $0.id, rev: $0.rev, vaultKey: SymmetricKey(data: oldVK))) == nil },
                     "everything the lane holds is closed to the revoked device's key")
            c.expect(try await d.vault.sync().rotationAdopted, "the remaining device adopts the rotation")
            try await d.vault.unlock()
            c.expect(try await d.vault.revealPassword(id: bank.id) == "between-attempts", "the remaining device reads under the new key")
        },

        ContractFlow(name: "a lane that silently drops a rotation's staged records never gets its commit: the box stays at the old key until the lane keeps writes again") { rig, c in
            let flaky = try c.require(rig.flaky)
            let a = try rig.device("a"), b = try rig.device("b"), d = try rig.device("c")
            _ = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            try await rig.enroll(d, through: a)
            try await a.vault.sync()
            let bID = try c.require(try await b.vault.identity()?.deviceID)

            // The journal is kept; the staged keys and envelopes are reported taken and never stored.
            flaky.failWrites(after: 1, silently: true)
            do { _ = try await a.vault.revoke(deviceID: bID); c.fail("a rotation the lane did not keep must not commit") }
            catch RotationError.laneDroppedWrites {}
            flaky.heal()
            let head = try c.require(try await rig.stored(.head).first { $0.id == ControlRecords.headID }, "the lane holds a head")
            c.expect(ControlRecords.decode(ControlRecords.Head.self, head.blob)?.epoch == 1, "the head never moved")
            c.expect(try await rig.stored(.stage).isEmpty, "the refused attempt leaves nothing staged")
            for x in [a, d] {
                c.expect(!(try await x.vault.sync().rotationAdopted), "\(x.name) sees no rotation")
                c.expect(try await x.vault.revealPassword(id: bank.id) == "bank-pw", "\(x.name) still reads the box at the old key")
            }

            try await a.vault.revoke(deviceID: bID)
            c.expect(try await d.vault.sync().rotationAdopted, "once the lane keeps writes the revoke goes through")
            try await d.vault.unlock()
            c.expect(try await d.vault.revealPassword(id: bank.id) == "bank-pw", "the remaining device reads under the new key")
        },

        ContractFlow(name: "a rotation that stops right after its commit is reported incomplete, and another unlocked device finishes it for every device") { rig, c in
            let flaky = try c.require(rig.flaky)
            let a = try rig.device("a"), b = try rig.device("b"), d = try rig.device("c")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            let mail = try await a.vault.save(login("Mail", password: "mail-pw"))
            let gone = try await a.vault.save(login("Gone", password: "gone-pw"))
            try await a.vault.sync()
            try await a.vault.delete(id: gone.id)
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            try await rig.enroll(d, through: a)
            try await a.vault.sync()
            let bIdentity = try c.require(try await b.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try c.require(bIdentity.envelope), reason: "test")

            // The journal, one chunk, an envelope for each device that stays and the commit (head, recovery, log entry) go in;
            // every fold after that fails.
            flaky.failWrites(after: 1 + 1 + 2 + 3)
            let report = try await a.vault.revoke(deviceID: bIdentity.deviceID)
            flaky.heal()
            c.expect(report.epoch == 2, "the rotation committed (epoch \(report.epoch))")
            c.expect(report.incomplete, "a rotation whose fold failed says so")
            c.expect(try await a.vault.revealPassword(id: mail.id) == "mail-pw", "the rotator reads everything under the new key")
            c.expect(!(try await rig.stored(.stage).isEmpty), "the staged keys wait on the lane")

            c.expect(try await d.vault.sync().rotationAdopted, "the remaining device adopts the rotation")
            c.expect(try await d.vault.sync().rotationPending, "locked, it sees the rotation is unfinished")
            try await d.vault.unlock()
            let finished = try await d.vault.sync()
            c.expect(finished.folded >= 3 && !finished.rotationPending, "the unlocked device finishes the fold (folded \(finished.folded))")
            c.expect(try await d.vault.revealPassword(id: bank.id) == "bank-pw", "it reads the items the rotator did not fold")
            c.expect(try await d.vault.revealPassword(id: mail.id) == "mail-pw", "it reads the items the rotator did not fold")
            c.expect(try await rig.stored(.stage).isEmpty, "nothing is left staged on the lane")
            let after = try await rig.records(as: a, c).filter { !$0.deleted }
            c.expect(after.allSatisfy { (try? ItemSealer.open(blob: $0.blob, id: $0.id, rev: $0.rev, vaultKey: SymmetricKey(data: oldVK))) == nil },
                     "everything the lane holds is closed to the revoked device's key")

            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.revealPassword(id: bank.id) == "bank-pw", "the phrase recovers the finished box")
            c.expect(try await fresh.vault.items().items.map(\.title).sorted() == ["Bank", "Mail"], "with the delete still in it")
            c.expect(try await fresh.vault.items().undecryptable.isEmpty, "and nothing it cannot open")
            try await a.vault.sync()
            c.expect(try await a.vault.revealPassword(id: bank.id) == "bank-pw", "the rotator carries on")
        },
    ]

    /// The `enroll` records a lane holds.
    private static func enrollRecords(_ lane: any SyncLane) async throws -> [LaneRecord] {
        var out: [LaneRecord] = []
        var cursor: LaneCursor?
        while true {
            let page = try await lane.fetch(since: cursor, limit: 200)
            out += page.upserts.filter { $0.kind == .enroll }
            cursor = page.cursor
            if !page.hasMore { return out }
        }
    }

    /// Writes a record straight to the storage, as anyone with the account can.
    private static func put(_ record: LaneRecord, on lane: any SyncLane, _ c: Checks) async throws {
        guard case .accepted = try await lane.write([LaneWrite(record: record, expect: .any)])[0] else {
            c.fail("the storage refused \(record.id)"); throw Checks.Stop()
        }
    }

    private static func adminSigned(_ record: LaneRecord, by admin: AdminSigner) throws -> LaneRecord {
        var r = record
        r.sig = try admin.sign(r.canonical)
        return r
    }

    private static func approvalRecord(_ device: String, envelope: Data, epoch: Int, mac: Data, by admin: AdminSigner) throws -> LaneRecord {
        let approval = ControlRecords.EnrollApproval(deviceID: device, epoch: epoch, envelopeHash: envelope.sha256Hex(), mac: mac.base64URLEncoded())
        return try adminSigned(LaneRecord(kind: .enroll, id: ControlRecords.enrollApprovedID(device), rev: 0, epoch: epoch,
                                          blob: try ControlRecords.encode(approval)), by: admin)
    }

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
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
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
            // The planted manifest does not lock the device out either: it publishes its own again and carries on.
            c.expect(try await a.vault.revealPassword(id: bank.id) == "bank-pw", "the device still opens its box")
            let manifest = try c.require(fake.record(ReservedRecord.manifestID))
            c.expect(manifest.blob != planted && manifest.rev > rev, "the device's own manifest replaces the planted one")
        },
        ContractFlow(name: "a revoked device that kept the old admin key cannot replace the recovery material, here or for a device recovering, nor wedge sync with its counter") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a"), b = try rig.device("b")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
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
            // The device that refused it put the real one back: a fresh device recovers into the box's key, not the one b holds.
            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.identity()?.epoch == 2, "the fresh device is at the box's epoch")
            c.expect(try await fresh.vault.revealPassword(id: bank.id) == "bank-pw", "and opens the box with its key")
        },
        ContractFlow(name: "someone who can write to the storage but never held the key cannot build a box the 24 words recover into") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a")
            let phrase = try await rig.bootstrap(a)
            _ = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()

            // Only public material: the recovery keys as the recovery record shows them. A head of their own, signed by an admin key
            // of their own, and a recovery record whose envelope (sealed to the public recovery key) holds a key they picked.
            let real = try c.require(ControlRecords.decode(ControlRecords.Recovery.self, try c.require(fake.record(ControlRecords.recoveryID)).blob))
            let enc = try c.require(Data(base64URLEncoded: real.encPubkey)), sig = try c.require(Data(base64URLEncoded: real.pubkey))
            let evil = BiselRandom.bytes(32)
            let admin = try AdminSigner(vaultKey: evil)
            var head = LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: 1,
                                  blob: try ControlRecords.encode(ControlRecords.Head(epoch: 1, aks: [.init(epoch: 1, ak: admin.publicKey, sig: nil)])))
            head.sig = try admin.sign(head.canonical)
            fake.inject(head)
            let forged = ControlRecords.Recovery(seq: real.seq + 1, epoch: 1, pubkey: real.pubkey, encPubkey: real.encPubkey,
                                                 envelope: try RecoveryKeys.seal(vaultKey: evil, toEncryptionKey: enc, signingKey: sig, epoch: 1).base64URLEncoded(),
                                                 anchor: real.anchor)
            var recovery = LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: 1, blob: try ControlRecords.encode(forged))
            recovery.sig = try admin.sign(recovery.canonical)
            fake.inject(recovery)

            let fresh = try rig.device("fresh")
            await c.expectThrows("the phrase must not recover into a box it never vouched for") { try await rig.recover(fresh, phrase: phrase) }
        },
        ContractFlow(name: "a record written over at the same revision by someone without the key can still be taken back") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a")
            _ = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()

            // Same id and revision, newer position, junk where the payload was: what a rotation's re-wrap looks like from outside.
            var junk = try c.require(fake.record(bank.id))
            junk.blob = junk.blob.prefix(ItemSealer.wrappedKeyLength) + Data(repeating: 6, count: junk.blob.count - ItemSealer.wrappedKeyLength)
            fake.inject(junk)
            _ = try await a.vault.sync()
            c.expect(try await a.vault.items().undecryptable == [bank.id], "sanity: the record now holds the junk")
            let kept = try await a.vault.trash().first { $0.itemID == bank.id }
            c.expect(kept?.item.password == "bank-pw", "the version it replaced is kept and can be restored")
        },

        // The freshness witness (docs/SYNC-LANES.md §8): a revoked Mac on the same Apple ID keeps the admin key of the epoch it was
        // cut off in. Against a device recovering fresh, which has seen nothing newer, only a second store can tell its work apart.
        ContractFlow(name: "a revoked device that forks the chain with the old admin key cannot make a fresh device recover into its key, and its forked witness and head are put right") { rig, c in
            let fake = try c.require(rig.fake), witness = try c.require(rig.fakeWitness)
            let a = try rig.device("a"), b = try rig.device("b")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            let bIdentity = try c.require(try await b.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try c.require(bIdentity.envelope), reason: "test")
            try await a.vault.revoke(deviceID: bIdentity.deviceID)
            let head = try c.require(ControlRecords.decode(ControlRecords.Head.self, try c.require(fake.record(ControlRecords.headID)).blob))
            let key = FreshnessStatement.key(root: try c.require(head.aks.first?.ak))
            c.expect(witness.all[key] != nil, "the rotation is witnessed at once")

            // An epoch 2 of its own: a key it picked, chained from the epoch-1 admin key it kept, and a recovery record whose envelope
            // (sealed to the public recovery key) holds the key it picked. The anchor still holds: the root is the box's own.
            let real = try c.require(ControlRecords.decode(ControlRecords.Recovery.self, try c.require(fake.record(ControlRecords.recoveryID)).blob))
            let evil = BiselRandom.bytes(32)
            let forkAdmin = try AdminSigner(vaultKey: evil)
            let link = ControlRecords.AKLink(epoch: 2, ak: forkAdmin.publicKey,
                                             sig: try AdminSigner(vaultKey: oldVK).sign(ControlRecords.chainMessage(newKey: forkAdmin.publicKey)))
            let forkChain = [head.aks[0], link]
            var forkHead = LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: 2,
                                      blob: try ControlRecords.encode(ControlRecords.Head(epoch: 2, aks: forkChain)), writer: bIdentity.deviceID)
            forkHead.sig = try forkAdmin.sign(forkHead.canonical)
            let enc = try c.require(Data(base64URLEncoded: real.encPubkey)), sig = try c.require(Data(base64URLEncoded: real.pubkey))
            let forged = ControlRecords.Recovery(seq: real.seq + 1, epoch: 2, pubkey: real.pubkey, encPubkey: real.encPubkey,
                                                 envelope: try RecoveryKeys.seal(vaultKey: evil, toEncryptionKey: enc, signingKey: sig, epoch: 2).base64URLEncoded(),
                                                 anchor: real.anchor)
            var recovery = LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: 2, blob: try ControlRecords.encode(forged),
                                      writer: bIdentity.deviceID)
            recovery.sig = try forkAdmin.sign(recovery.canonical)
            fake.inject(forkHead)
            fake.inject(recovery)

            let first = try rig.device("fresh")
            do { try await rig.recover(first, phrase: phrase); c.fail("a fresh device must not recover into the forked chain") }
            catch FreshnessError.forked {}

            // It writes the witness too, for its fork. A device of the box that syncs sees the fork and puts its own statement back.
            let statement = FreshnessStatement(epoch: 2, aks: forkChain, counter: 1 << 30, writer: bIdentity.deviceID, ts: 0)
            let blob = try ControlRecords.encode(statement)
            witness.plant(SignedFreshness(statement: blob, sig: try forkAdmin.sign(FreshnessStatement.message(blob))), key: key)
            let report = try await a.vault.sync()
            c.expect(report.freshness == .forked, "the device of the box raises the fork (\(report.freshness))")
            c.expect(witness.all[key]?.statement != blob, "the forked statement is replaced")
            // It also put the real head and recovery record back: the next fresh device recovers into the box's own key.
            let second = try rig.device("second")
            try await rig.recover(second, phrase: phrase)
            try await second.vault.sync()
            c.expect(try await second.vault.identity()?.epoch == 2, "the second fresh device is at the box's epoch")
            c.expect(try await second.vault.revealPassword(id: bank.id) == "bank-pw", "and opens the box with its key, not b's")
        },
        ContractFlow(name: "a genuine snapshot from before a revoke, restored to the storage, is refused by a device recovering fresh") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a"), b = try rig.device("b")
            let phrase = try await rig.bootstrap(a)
            _ = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            let beforeRevoke = fake.snapshot()   // epoch 1: its recovery envelope holds the key b has
            try await a.vault.revoke(deviceID: try c.require(try await b.vault.identity()?.deviceID))
            c.expect(try await a.vault.sync().freshness == .current, "the witness has the rotation")

            fake.restore(beforeRevoke)
            let fresh = try rig.device("fresh")
            do { try await rig.recover(fresh, phrase: phrase); c.fail("a fresh device must not recover from a snapshot older than the witness") }
            catch FreshnessError.laneBehind {}
        },
        ContractFlow(name: "with the freshness witness unreachable or cleared, a box syncs and recovers as before and says which") { rig, c in
            let witness = try c.require(rig.fakeWitness)
            witness.setReachable(false)
            let a = try rig.device("a")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            c.expect(try await a.vault.sync().freshness == .unavailable, "an unreachable witness is reported as such")
            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.revealPassword(id: bank.id) == "bank-pw", "recovery works without the witness")

            witness.setReachable(true)
            c.expect(try await a.vault.sync().freshness == .current, "once reachable, the witness is written and the lane is current")
            // Cleared (the owner deleted iCloud data, or anyone on the account wrote junk): nothing to compare, nothing refused.
            let key = try c.require(witness.all.keys.first)
            witness.plant(SignedFreshness(statement: Data("{}".utf8), sig: Data()), key: key)
            let again = try rig.device("again")
            try await rig.recover(again, phrase: phrase)
            c.expect(try await fresh.vault.sync().freshness == .current, "a device of the box writes the witness again")
            let restored = try c.require(witness.all[key])
            c.expect(LaneVerifier().freshness(restored, chain: try c.require(ControlRecords.decode(ControlRecords.Head.self, try c.require(rig.fake?.record(ControlRecords.headID)).blob)).aks,
                                              counter: nil).state == .current, "the rewritten statement verifies")
        },

        // A device that slept through the revoke still pins the epoch the revoked device was cut off in, and the revoked device kept
        // that epoch's admin key. What its fork looks like to that device is what the real rotation looks like.
        ContractFlow(name: "a device that slept through a revoke does not take the revoked device's fork, and takes the real rotation once a device of the box puts it back") { rig, c in
            let fake = try c.require(rig.fake)
            _ = try c.require(rig.fakeWitness)
            let a = try rig.device("a"), b = try rig.device("b"), late = try rig.device("late")
            _ = try await rig.bootstrap(a)
            _ = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            try await rig.enroll(late, through: a)
            try await late.vault.sync()
            let bIdentity = try c.require(try await b.vault.identity()), lateIdentity = try c.require(try await late.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try c.require(bIdentity.envelope), reason: "test")
            try await a.vault.revoke(deviceID: bIdentity.deviceID)   // `late` is asleep: it still pins epoch 1
            let realHead = try c.require(fake.record(ControlRecords.headID))

            // b's own epoch 2, and an envelope for `late` (sealed to its public key) holding the key b picked, over the real one.
            let evil = BiselRandom.bytes(32)
            let (forkAdmin, _, forkHead) = try fork(realHead, oldVK: oldVK, evil: evil, writer: bIdentity.deviceID, c)
            let enc = try c.require(lateIdentity.roster.first { $0.deviceID == lateIdentity.deviceID }?.encPubkey)
            fake.inject(forkHead)
            fake.inject(try adminSigned(LaneRecord(kind: .envelope, id: ControlRecords.envelopeID(epoch: 2, device: lateIdentity.deviceID), rev: 0, epoch: 2,
                                                   blob: try DeviceEnvelope.seal(vaultKey: evil, toEncryptionKey: enc), writer: bIdentity.deviceID), by: forkAdmin))

            _ = try? await late.vault.sync()
            c.expect(try await late.vault.identity()?.epoch == 1, "the late device does not take an epoch the witness contradicts")
            _ = try await a.vault.sync()
            c.expect(fake.record(ControlRecords.headID)?.blob == realHead.blob, "a device of the box puts the real head back")
            _ = try? await late.vault.sync()
            try await late.vault.unlock()
            _ = try await late.vault.sync()
            c.expect(try await late.vault.identity()?.epoch == 2, "the late device takes the real rotation")
            let note = try await late.vault.save(login("Late", password: "late-pw"))
            try await late.vault.sync()
            for r in fake.records() where r.isItemLike && r.kind != .tombstone {
                c.expect((try? ItemSealer.open(blob: r.blob, id: r.id, rev: r.rev, vaultKey: SymmetricKey(data: evil))) == nil,
                         "nothing on the lane opens under the forked key (\(r.id))")
            }
            try await a.vault.sync()
            c.expect(try await a.vault.revealPassword(id: note.id) == "late-pw", "the late device's edit reaches the box")
        },
        ContractFlow(name: "a revoked device cannot stop the next revoke: its forked head and recovery record are put back, and a record no key opens is left behind") { rig, c in
            let fake = try c.require(rig.fake)
            let a = try rig.device("a"), b = try rig.device("b"), d = try rig.device("d")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            try await rig.enroll(d, through: a)
            let bIdentity = try c.require(try await b.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try c.require(bIdentity.envelope), reason: "test")
            try await a.vault.revoke(deviceID: bIdentity.deviceID)
            let realHead = try c.require(fake.record(ControlRecords.headID)), realRecovery = try c.require(fake.record(ControlRecords.recoveryID))

            // One write each, with the key b kept or none at all: a forked head, a recovery record of the fork, a record nothing opens.
            let evil = BiselRandom.bytes(32)
            let (forkAdmin, _, forkHead) = try fork(realHead, oldVK: oldVK, evil: evil, writer: bIdentity.deviceID, c)
            var forged = try c.require(ControlRecords.decode(ControlRecords.Recovery.self, realRecovery.blob))
            forged.seq += 1
            fake.inject(forkHead)
            fake.inject(try adminSigned(LaneRecord(kind: .recovery, id: ControlRecords.recoveryID, rev: 0, epoch: 2, blob: try ControlRecords.encode(forged),
                                                   writer: bIdentity.deviceID), by: forkAdmin))
            fake.inject(LaneRecord(kind: .item, id: BiselRandom.identifier(), rev: 1, epoch: 2, blob: Data(repeating: 3, count: 600)))

            _ = try await a.vault.sync()
            c.expect(fake.record(ControlRecords.headID)?.blob == realHead.blob, "the real head is put back")
            c.expect(fake.record(ControlRecords.recoveryID)?.blob == realRecovery.blob, "the real recovery record is put back")
            try await a.vault.revoke(deviceID: try c.require(try await d.vault.identity()?.deviceID))
            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            c.expect(try await fresh.vault.revealPassword(id: bank.id) == "bank-pw", "the phrase still recovers the box after both")
        },
    ]

    /// What a revoked device that kept the admin key of epoch 1 can sign: an epoch 2 of its own, a key it picked (`evil`) chained
    /// from that admin key. The anchor still holds, since the root is the box's own.
    private static func fork(_ realHead: LaneRecord, oldVK: Data, evil: Data, writer: String, _ c: Checks) throws
        -> (admin: AdminSigner, chain: [ControlRecords.AKLink], head: LaneRecord) {
        let head = try c.require(ControlRecords.decode(ControlRecords.Head.self, realHead.blob))
        let admin = try AdminSigner(vaultKey: evil)
        let link = ControlRecords.AKLink(epoch: 2, ak: admin.publicKey,
                                         sig: try AdminSigner(vaultKey: oldVK).sign(ControlRecords.chainMessage(newKey: admin.publicKey)))
        let chain = [head.aks[0], link]
        let record = try adminSigned(LaneRecord(kind: .head, id: ControlRecords.headID, rev: 0, epoch: 2,
                                                blob: try ControlRecords.encode(ControlRecords.Head(epoch: 2, aks: chain)), writer: writer), by: admin)
        return (admin, chain, record)
    }
}
#endif
