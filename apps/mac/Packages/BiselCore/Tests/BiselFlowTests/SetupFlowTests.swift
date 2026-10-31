#if BISEL_SOFTWARE_KEYS
import Foundation
import Testing
import BiselCore
import BiselTestSupport
import BiselLaneContract

// First run, iCloud first (BoxSetup, SETUP.md): create, add this Mac, restore, and the iCloud account changing under a box.
// iCloud is a `FakeHome` (one private database per Apple Account, a `FakeLane` per box) and the freshness witness a
// `FakeFreshnessWitness`, shared by the Macs of one Apple Account as iCloud is.
@Suite("First run in iCloud", .serialized)
struct SetupFlowTests {
    /// One Mac signed in to the home's iCloud.
    struct Mac {
        let device: Device
        let setup: BoxSetup
        var vault: Vault { device.vault }

        init(_ name: String, home: FakeHome, witness: FakeFreshnessWitness) throws {
            let route = home.laneProvider
            device = try Device(name, laneProvider: { id, _ in route(id.serverURL) }, freshnessWitness: witness)
            setup = BoxSetup(vault: device.vault, home: home)
        }
    }

    private func backupFile() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("bisel-setup-\(UUID().uuidString).bisel-backup")
    }

    @Test("a box is never created while iCloud cannot take it, and a refused attempt leaves nothing that blocks the next one")
    func createRefusesEveryICloudProblemAndLeavesNothing() async throws {
        let home = FakeHome(), witness = FakeFreshnessWitness()
        let a = try Mac("a", home: home, witness: witness)

        func refused(_ expected: HomeUnavailable) async throws {
            await #expect(throws: SetupError.iCloud(expected)) { try await a.setup.create(deviceName: "a") }
            #expect(await !a.vault.isConfigured, "nothing was made on this Mac (\(expected))")
            #expect(try await a.vault.identity() == nil, "no keys or identity left behind (\(expected))")
            guard case .welcome = await a.setup.state else { Issue.record("back on the welcome screen (\(expected))"); return }
        }

        home.signIn(.signedOut)
        guard case .welcome(let w) = await a.setup.start() else { Issue.record("welcome"); return }
        #expect(w.iCloud == .unavailable(.notSignedIn), "the welcome screen already knows iCloud is signed out")
        try await refused(.notSignedIn)
        home.signIn(.first)
        for reason in [HomeUnavailable.turnedOffForApp, .restricted, .offline, .temporarilyUnavailable] {
            home.refuse(reason)
            try await refused(reason)
        }
        home.refuse(nil)
        home.fill(true)   // signed in and reachable, but the first write is refused
        try await refused(.quotaFull)
        #expect(try await home.boxes().isEmpty, "a refused create leaves no half-box in iCloud")
        home.fill(false)

        let phrase = try await a.setup.create(deviceName: "a")
        guard case .showPhrase(let new) = await a.setup.state, case .iCloud(let address) = new.place else {
            Issue.record("the new box is in iCloud and its words are on screen"); return
        }
        #expect(new.phrase == phrase)
        #expect(try await home.boxes() == [address], "exactly one box in iCloud")
    }

    @Test("a new iCloud box is never left without its backup reminder, and going back from its phrase leaves no orphan box in iCloud")
    func newBoxIsRemindedAndDiscardLeavesNoOrphan() async throws {
        let home = FakeHome(), witness = FakeFreshnessWitness()
        let a = try Mac("a", home: home, witness: witness)
        await a.setup.start()

        try await a.setup.create(deviceName: "a")
        try await a.setup.discardNewBox()
        #expect(try await home.boxes().isEmpty, "Back erased the box it had just put in iCloud")
        #expect(try await a.vault.identity() == nil, "and everything it made on this Mac")
        guard case .welcome(let w) = await a.setup.state, !w.iCloudHasBox else { Issue.record("an empty iCloud again"); return }

        try await a.setup.create(deviceName: "a")   // not refused with `.iCloudHasBox` by the discarded one
        let done = try await a.setup.phraseStored()
        let backup = try #require(done.backup)
        #expect(backup.copies == .cloudKitOnly)
        #expect(backup.reminder == .noBackupYet, "D4: a box only in iCloud is reminded to export a backup at once")
        #expect(await a.vault.recoveryNeedsConfirmation == false)
    }

    @Test("a second box is never made over the one iCloud holds: the Mac joins it with the 8 words, survives a relaunch mid-pairing, and another Apple Account sees no box")
    func existingICloudBoxIsJoinedNotDuplicated() async throws {
        let home = FakeHome(), witness = FakeFreshnessWitness()
        let a = try Mac("a", home: home, witness: witness), b = try Mac("b", home: home, witness: witness)
        await a.setup.start()
        try await a.setup.create(deviceName: "a")
        try await a.setup.phraseStored()
        let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
        try await a.vault.sync()

        guard case .welcome(let w) = await b.setup.start(), w.boxesInICloud.count == 1 else {
            Issue.record("the box already in iCloud is detected on the welcome screen"); return
        }
        await #expect(throws: SetupError.iCloudHasBox(w.boxesInICloud)) { try await b.setup.create(deviceName: "b") }
        #expect(try await home.boxes().count == 1, "no second box")

        // D2: another Apple Account's iCloud does not show this box.
        home.signIn(.second)
        await #expect(throws: SetupError.noBoxInICloud) { try await b.setup.startPairing(deviceName: "b") }
        home.signIn(.first)

        let offer = try await b.setup.startPairing(deviceName: "b")
        #expect(try await b.setup.checkPairing() == false, "not approved yet")
        // The app quits while the words are on screen: the same request comes back.
        let relaunched = BoxSetup(vault: try b.device.relaunched(), home: home)
        guard case .pairing(let again) = await relaunched.start() else { Issue.record("pairing resumes after a relaunch"); return }
        #expect(again.secret.words == offer.secret.words && again.fingerprint == offer.fingerprint)

        try await a.vault.sync()
        let pending = try #require(try await a.vault.pendingEnrollments().first)
        #expect(pending.request.fingerprint == offer.fingerprint)
        try await a.vault.approveEnrollment(pending, pairing: try PairingSecret(words: offer.secret.words))

        #expect(try await relaunched.checkPairing())
        guard case .compareCode = await relaunched.state else { Issue.record("the codes are compared next"); return }
        await #expect(throws: SetupError.codeMismatch) { try await relaunched.confirmPairing(code: "AAAA-AAAA") }
        try await relaunched.cancelPairing()
        #expect(try await b.vault.identity() == nil, "a mismatch leaves nothing trusted here")

        // From the top, the way it should go.
        let c = try Mac("c", home: home, witness: witness)
        await c.setup.start()
        let fresh = try await c.setup.startPairing(deviceName: "c")
        try await a.vault.sync()
        let request = try #require(try await a.vault.pendingEnrollments().first { $0.request.fingerprint == fresh.fingerprint })
        try await a.vault.approveEnrollment(request, pairing: try PairingSecret(words: fresh.secret.words))
        #expect(try await c.setup.checkPairing())
        let done = try await c.setup.confirmPairing(code: try await a.vault.verificationCode())
        #expect(done.place == .iCloud(w.boxesInICloud[0]))
        #expect(try await c.vault.revealPassword(id: bank.id) == "bank-pw")
        #expect(try await home.boxes().count == 1)
    }

    @Test("the 24 words restore the box from iCloud, and wrong words or an unreachable iCloud write nothing")
    func wordsRestoreFromICloud() async throws {
        let home = FakeHome(), witness = FakeFreshnessWitness()
        let a = try Mac("a", home: home, witness: witness), b = try Mac("b", home: home, witness: witness)
        await a.setup.start()
        let phrase = try await a.setup.create(deviceName: "a")
        try await a.setup.phraseStored()
        let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
        try await a.vault.sync()

        await b.setup.start()
        await #expect(throws: SetupError.wrongPhrase) { try await b.setup.restore(words: try RecoveryPhrase.generate(), deviceName: "b") }
        #expect(try await b.vault.identity() == nil, "wrong words leave nothing here")
        home.refuse(.offline)
        await #expect(throws: SetupError.iCloud(.offline)) { try await b.setup.restore(words: phrase, deviceName: "b") }
        home.refuse(nil)

        let done = try await b.setup.restore(words: phrase, deviceName: "b")
        guard case .iCloud = done.place else { Issue.record("restored onto the box in iCloud"); return }
        #expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw")
        #expect(try await home.boxes().count == 1)

        // D7 (c): on iCloud the words plus the Apple Account make a full member at once, with no hold-back. The other devices are
        // told on their next sync, with the id of the device that recovered, so the alert can revoke exactly that one.
        let recovered = try #require(try await b.vault.identity()?.deviceID)
        let news = try await a.vault.sync()
        let event = try #require(news.events.first { $0.type == "recovery" }, "a phrase recovery is announced to the other devices")
        #expect(event.subjectId == recovered && event.deviceId == recovered)
        #expect(try await a.vault.sync().events.isEmpty, "announced once, not on every sync")
    }

    @Test("a backup file goes back into iCloud when iCloud is empty, is merged into the live iCloud box instead of making a second one, and is never lost when iCloud refuses it")
    func backupFileRestoresIntoICloud() async throws {
        let home = FakeHome(), witness = FakeFreshnessWitness()
        let a = try Mac("a", home: home, witness: witness)
        await a.setup.start()
        let phrase = try await a.setup.create(deviceName: "a")
        try await a.setup.phraseStored()
        let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
        let old = try await a.vault.save(login("Old forum", password: "old-pw"))
        try await a.vault.sync()
        let file = backupFile()
        defer { try? FileManager.default.removeItem(at: file) }
        try await a.vault.exportBackup(to: file)
        try await a.vault.delete(id: old.id)
        let later = try await a.vault.save(login("Made after the backup", password: "later-pw"))
        try await a.vault.sync()

        // iCloud holds the box: the iCloud copy is the live one, the file only adds what it lacks.
        let b = try Mac("b", home: home, witness: witness)
        await b.setup.start()
        await #expect(throws: SetupError.wrongPhrase) { try await b.setup.restore(backup: file, words: try RecoveryPhrase.generate(), deviceName: "b") }
        #expect(try await b.vault.identity() == nil, "a file the words do not open writes nothing")
        let merged = try await b.setup.restore(backup: file, words: phrase, deviceName: "b")
        guard case .iCloud = merged.place else { Issue.record("joined the box in iCloud"); return }
        #expect(try await home.boxes().count == 1, "no second box")
        #expect(try await b.vault.revealPassword(id: later.id) == "later-pw", "what was made after the backup is kept")
        #expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw")

        // Another Apple Account (its own key-value storage too) whose iCloud is full: the box is restored on this Mac and stays
        // there, whole.
        home.signIn(.second)
        home.fill(true)
        let secondWitness = FakeFreshnessWitness()
        let c = try Mac("c", home: home, witness: secondWitness)
        await c.setup.start()
        let kept = try await c.setup.restore(backup: file, words: phrase, deviceName: "c")
        #expect(kept.place == .thisMacOnly && kept.iCloudProblem == .quotaFull, "the restore stands even though iCloud refused it")
        #expect(try await c.vault.revealPassword(id: old.id) == "old-pw")

        // Room again: it goes up, and the box is in this account's iCloud.
        home.fill(false)
        try await c.setup.putInICloud(words: phrase)
        guard case .done(let up) = await c.setup.state, case .iCloud = up.place else { Issue.record("put in iCloud"); return }
        #expect(try await home.boxes().count == 1)
        let d = try Mac("d", home: home, witness: secondWitness)
        await d.setup.start()
        try await d.setup.restore(words: phrase, deviceName: "d")
        #expect(try await d.vault.revealPassword(id: bank.id) == "bank-pw", "another Mac on that account restores it from iCloud")
    }

    @Test("the iCloud account changing never uploads to the other account and never loses this Mac's box; signing out pauses and signing back in resumes")
    func accountChangeFailsClosed() async throws {
        let home = FakeHome(), witness = FakeFreshnessWitness()
        let a = try Mac("a", home: home, witness: witness)
        await a.setup.start()
        try await a.setup.create(deviceName: "a")
        try await a.setup.phraseStored()
        let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
        try await a.vault.sync()
        guard case .done(let done) = await a.setup.refresh(), case .iCloud(let address) = done.place else { Issue.record("in iCloud"); return }
        let zone = address.lastPathComponent

        // Signed out: paused, the edit stays on this Mac, and it goes up by itself once signed back in.
        home.signIn(.signedOut)
        var edit = try await a.vault.item(id: bank.id); edit.password = "while-signed-out"
        _ = try await a.vault.save(edit)
        guard case .attention(.accountUnavailable) = await a.setup.refresh() else { Issue.record("paused while signed out"); return }
        #expect(try await a.vault.pendingChanges() == 1)
        home.signIn(.first)
        guard case .done = await a.setup.refresh() else { Issue.record("resumes once signed back in"); return }
        #expect(try await a.vault.pendingChanges() == 0)

        // Another Apple Account, which already holds a box of its own.
        home.signIn(.second)
        let other = try Mac("other", home: home, witness: FakeFreshnessWitness())
        await other.setup.start()
        try await other.setup.create(deviceName: "other")
        try await other.setup.phraseStored()
        let fresh = try await a.vault.save(login("Made on the other account", password: "new-pw"))
        guard case .attention(.accountChanged) = await a.setup.refresh() else { Issue.record("the other account is noticed"); return }
        #expect(home.store(zone, on: .second).records().isEmpty, "nothing of this box reached the other account")
        #expect(try await a.vault.revealPassword(id: bank.id) == "while-signed-out", "the box is whole on this Mac")
        #expect(try await a.vault.pendingChanges() >= 1, "the edit waits")

        // Moving there is the person's choice, and not into an account that holds another box unless they say so.
        let theirs = try await home.boxes()
        await #expect(throws: SetupError.iCloudHasBox(theirs)) { try await a.setup.moveBoxToThisAccount() }
        #expect(home.store(zone, on: .second).records().isEmpty)
        try await a.setup.moveBoxToThisAccount(evenIfItHoldsAnotherBox: true)
        guard case .done = await a.setup.state else { Issue.record("active on the new account"); return }
        #expect(try await a.vault.pendingChanges() == 0)
        #expect(!home.store(zone, on: .second).records().isEmpty, "the box is on the account the person chose")
        #expect(try await a.vault.revealPassword(id: fresh.id) == "new-pw")
    }
}
#endif
