#if BISEL_SOFTWARE_KEYS
import Foundation
import Testing
import CryptoKit
import BiselCore
import BiselTestSupport
import BiselLaneContract

// Flows for SECURITY-REVIEW.md: real server (wrangler dev, local D1), real crypto, software key store. A "hostile" party
// is played by raw SyncClient calls (what a stolen device-signing key can do) and by SQL against the server's database
// (what a breached or malicious server can do).
@Suite("Security flows against the local server", .serialized)
struct SecurityFlowTests {

    private func wireDevice(name: String, in directory: URL, vault: Data, epoch: Int? = nil) throws -> (WireDevice, DevicePublicKeys) {
        let keys = try SoftwareDeviceKeyStore(directory: directory).createKeys()
        let envelope = try DeviceEnvelope.seal(vaultKey: vault, toEncryptionKey: keys.enc)
        return (WireDevice(id: BiselRandom.identifier(), name: name, kind: "cli", sigPubkey: keys.sig, encPubkey: keys.enc, envelope: envelope, epoch: epoch), keys)
    }

    private func tempDir(_ name: String) -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("bisel-sec-\(name)-\(UUID().uuidString)")
    }

    // MARK: H1

    @Test("a stolen device-signing key cannot rotate, approve, revoke or replace the recovery key: those need the vault-admin signature")
    func adminSignatureGatesDestruction() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            // The attacker can sign requests as A (DK-sig never prompts) but has no VK, hence no admin key of its own.
            let aID = try #require(try await a.vault.identity()?.deviceID), bID = try #require(try await b.vault.identity()?.deviceID)
            let client = a.signedClientFactory(server.url, aID)
            let impostor = AdminSigner(key: Curve25519.Signing.PrivateKey())
            let refused = SyncError.server(status: 403, code: "admin_signature_required")
            let (rogue, _) = try wireDevice(name: "planted", in: tempDir("rogue"), vault: Data(repeating: 1, count: 32), epoch: 1)
            await #expect(throws: refused) { try await client.addDevice(rogue, admin: impostor) }
            await #expect(throws: refused) { try await client.revokeDevice(id: bID, admin: impostor) }
            await #expect(throws: refused) {
                try await client.rotateRecovery(publicKey: Data(repeating: 9, count: 32), encryptionPublicKey: Data(repeating: 8, count: 32),
                                                envelope: Data(repeating: 7, count: 80), epoch: 1, admin: impostor)
            }
            let page = try await client.pull(since: 0)
            await #expect(throws: refused) {
                _ = try await client.rotate(baseEpoch: 1, baseSeq: page.headSeq, revoke: bID, newAdminPublicKey: impostor.publicKey,
                                            items: page.records.filter { !$0.deleted && $0.id != ReservedRecord.manifestID }.map { (id: $0.id, rev: $0.rev, wrappedKey: Data(repeating: 3, count: 60)) }
                                                + [(id: ReservedRecord.manifestID, rev: page.records.first { $0.id == ReservedRecord.manifestID }!.rev, wrappedKey: Data(repeating: 3, count: 60))],
                                            tombstones: [], devices: [(id: aID, envelope: Data(repeating: 4, count: 125))],
                                            recoveryEnvelope: Data(repeating: 5, count: 60), admin: impostor)
            }

            // The same key cannot overwrite or delete the manifest either (it would lock every device out on the next sync).
            let manifest = try #require(page.records.first { $0.id == ReservedRecord.manifestID })
            await #expect(throws: refused) { _ = try await client.put(id: manifest.id, baseRev: manifest.rev, blob: Data(repeating: 6, count: 80), epoch: 1) }
            await #expect(throws: refused) { _ = try await client.put(id: manifest.id, baseRev: manifest.rev, blob: Data(repeating: 6, count: 80), epoch: 1, admin: impostor) }
            await #expect(throws: refused) { _ = try await client.delete(id: manifest.id, baseRev: manifest.rev, marker: Data(repeating: 6, count: 40), epoch: 1) }

            // Nothing moved: both devices work, the recovery phrase's keys are intact, the item still decrypts.
            #expect(try await a.vault.devices().filter { !$0.isRevoked }.count == 2)
            _ = try await a.vault.sync()
            _ = try await b.vault.sync()
            #expect(try await b.vault.revealPassword(id: try await b.vault.items().items[0].id) == "bank-pw")
            #expect(try await b.vault.identity()?.epoch == 1)
            // The owner, with an unlocked vault, can still do every one of those things.
            let c = try Device("c")
            try await c.enroll(through: a, server: server)
            try await a.vault.revoke(deviceID: try #require(try await c.vault.identity()?.deviceID))
        }
    }

    @Test("history: a bad overwrite by a stolen device key is undone from what the server retained")
    func serverHistoryRestoresOverwrite() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            try await a.bootstrap(server)
            let bank = try await a.vault.save(login("Bank", password: "the-real-password"))
            try await a.vault.sync()

            // Hostile overwrite: junk ciphertext at the next revision (the server cannot tell it from a real edit).
            let aID = try #require(try await a.vault.identity()?.deviceID)
            let client = a.signedClientFactory(server.url, aID)
            let current = try #require(try await client.pull(since: 0).records.first { $0.id == bank.id })
            guard case .accepted = try await client.put(id: bank.id, baseRev: current.rev, blob: Data(repeating: 0xAB, count: 700), epoch: 1)
            else { Issue.record("put refused"); return }
            try await a.vault.sync()
            #expect(try await a.vault.items().undecryptable == [bank.id], "the vandalised item no longer opens")

            let past = try await a.vault.serverHistory(itemID: bank.id)
            let good = try #require(past.first { $0.item.title == "Bank" })
            #expect(good.item.password == "the-real-password")
            try await a.vault.restore(good)
            try await a.vault.sync()
            #expect(try await a.vault.items().undecryptable.isEmpty)
            #expect(try await a.vault.revealPassword(id: bank.id) == "the-real-password")
        }
    }

    // MARK: H2

    @Test("a device nobody approved blocks rotation; revoking it, or confirming its fingerprint, unblocks it")
    func rosterBlocksUnknownDevices() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.bootstrap(server)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()

            // Somebody who saw the 24 words registers a device of their own, without touching any enrolled device.
            let (vk, keys, epoch) = try await RecoveryService.fetchVaultKey(server: server.url, phrase: phrase, boxID: try server.onlyBoxID())
            let (rogue, rogueKeys) = try wireDevice(name: "unfamiliar laptop", in: tempDir("rogue"), vault: vk, epoch: nil)
            try await SyncClient(baseURL: server.url, signer: RecoverySigner(keys: keys, boxID: try server.onlyBoxID())).recoveryRegister(device: rogue, epoch: epoch)

            // The next time the owner revokes or rotates, the new key is NOT sealed to it.
            do { try await a.vault.rotateVaultKey(); Issue.record("rotation should have stopped") }
            catch IntegrityError.unknownDevices(let unknown) {
                #expect(unknown.map(\.id) == [rogue.id])
                #expect(unknown[0].fingerprint == rogueKeys.fingerprint)
            }
            #expect(try await a.vault.identity()?.epoch == 1, "nothing was rotated")
            #expect(fingerprintBits(rogueKeys.fingerprint) >= 96)

            // Revoking the stranger is allowed: the rotation excludes it, and the vault key it received opens nothing now on the server.
            let report = try await a.vault.revoke(deviceID: rogue.id)
            #expect(report.revokedDeviceID == rogue.id)
            let blobs = try await serverBlobs(server, as: a)
            #expect(!blobs.isEmpty)
            #expect(blobs.allSatisfy { (try? ItemSealer.open(blob: $0.blob, id: $0.id, rev: $0.rev, vaultKey: SymmetricKey(data: vk))) == nil })
            _ = bank

            // A second newcomer is one the owner really recognises: confirming its fingerprint adds it to the roster.
            let current = try await RecoveryService.fetchVaultKey(server: server.url, phrase: phrase, boxID: try server.onlyBoxID())   // the phrase still opens the NEW key
            let (friend, friendKeys) = try wireDevice(name: "friend", in: tempDir("friend"), vault: current.vaultKey, epoch: nil)
            try await SyncClient(baseURL: server.url, signer: RecoverySigner(keys: current.keys, boxID: try server.onlyBoxID())).recoveryRegister(device: friend, epoch: current.epoch)
            do { try await a.vault.rotateVaultKey(); Issue.record("rotation should have stopped") }
            catch IntegrityError.unknownDevices(let unknown) { #expect(unknown.map(\.id) == [friend.id]) }
            await #expect(throws: IntegrityError.verificationCodeMismatch) {
                try await a.vault.trustDevice(id: friend.id, fingerprint: "0000-0000-0000-0000-0000-0000")
            }
            try await a.vault.trustDevice(id: friend.id, fingerprint: friendKeys.fingerprint)
            #expect(try await a.vault.roster().contains { $0.deviceID == friend.id && $0.via == "trusted" })
            let done = try await a.vault.rotateVaultKey()
            #expect(done.epoch == 3)
        }
    }

    // MARK: H3

    @Test("an envelope swapped by the server is caught: the manifest is the canary, the verification code is the human check")
    func swappedEnvelopeIsDetected() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()

            let request = try await b.vault.prepareEnrollment(server: server.url, deviceName: "b")
            try await a.vault.approveEnrollment(request)
            // The server replaces the approver's envelope with one holding a vault key of its own choosing.
            let fake = BiselRandom.bytes(32)
            let forged = try DeviceEnvelope.seal(vaultKey: fake, toEncryptionKey: request.encPubkey)
            try server.sql("UPDATE devices SET envelope = '\(forged.base64URLEncoded())' WHERE id = '\(request.deviceID)'")

            try await b.vault.completeEnrollment()
            try await b.vault.unlock()          // opens fine: it is a well-formed envelope
            #expect(await b.vault.enrollmentNeedsConfirmation)
            let codeA = try await a.vault.verificationCode(), codeB = try await b.vault.verificationCode()
            #expect(codeA != codeB, "the two humans would see different codes")
            await #expect(throws: IntegrityError.verificationCodeMismatch) { try await b.vault.confirmEnrollment(code: codeA) }
            #expect(await !b.vault.isUnlocked, "a mismatch locks the vault")

            // And without anyone comparing codes, the first sync refuses: the vault's own manifest does not open under that key.
            try await b.vault.unlock()
            await #expect(throws: IntegrityError.keyConfirmationFailed) { try await b.vault.sync() }
            #expect(await !b.vault.isUnlocked)

            // An honest enrollment on the same server is accepted and shows matching codes.
            let c = try Device("c")
            let ok = try await c.vault.prepareEnrollment(server: server.url, deviceName: "c")
            try await a.vault.approveEnrollment(ok)
            try await c.vault.completeEnrollment()
            try await c.vault.unlock()
            #expect(try await c.vault.verificationCode() == a.vault.verificationCode())
            try await c.vault.confirmEnrollment(code: try await a.vault.verificationCode().lowercased())
            _ = try await c.vault.sync()
            #expect(try await c.vault.items().items.count == 1)
            #expect(try await c.vault.roster().count == 3, "bootstrap device, b (approved), and c itself arrive through the sealed manifest")
        }
    }

    // MARK: M3, M5

    @Test("recovery keys are pinned: the server cannot swap them; the phrase must be proved written down")
    func recoveryPinsAndConfirmation() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            let phrase = try await a.bootstrap(server)
            #expect(await a.vault.recoveryNeedsConfirmation, "a phrase nobody confirmed stays flagged across restarts")
            #expect(await (try a.relaunched()).recoveryNeedsConfirmation)

            let positions = RecoveryPhrase.quizPositions()
            #expect(positions.count == 3 && Set(positions).count == 3 && positions.allSatisfy { (1...24).contains($0) })
            let answers = Dictionary(uniqueKeysWithValues: positions.map { ($0, phrase.words[$0 - 1]) })
            #expect(phrase.verify(answers: answers))
            #expect(!phrase.verify(answers: [positions[0]: "wrongword"]))
            await #expect(throws: BiselCryptoError.invalidRecoveryPhrase) { try await a.vault.confirmRecovery(phrase: try RecoveryPhrase.generate()) }
            #expect(await a.vault.recoveryNeedsConfirmation)
            try await a.vault.confirmRecovery(phrase: phrase)
            #expect(await !a.vault.recoveryNeedsConfirmation)

            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            let pinned = try #require(try await b.vault.identity())
            #expect(pinned.recoveryPinned, "an enrolled device learns the pins from the sealed manifest")
            #expect(pinned.recoveryPublicKey == (try RecoveryKeys(phrase: phrase)).publicKey)

            // A new phrase is flagged again, and moves the pins everywhere through the manifest.
            let second = try await a.vault.rotateRecovery()
            #expect(await a.vault.recoveryNeedsConfirmation)
            try await a.vault.sync()
            _ = try await b.vault.sync()
            #expect(try await b.vault.identity()?.recoveryPublicKey == (try RecoveryKeys(phrase: second)).publicKey)

            // A device whose recovery keys are not pinned (they only came from the server) must not seal a new vault key to them.
            let store = try LocalStore(location: b.location)
            var unpinned = try #require(try store.identity())
            unpinned.recoveryPinned = false
            try store.setIdentity(unpinned)
            let reopened = try b.relaunched()
            try await reopened.unlock()
            await #expect(throws: IntegrityError.recoveryNotPinned) { _ = try await reopened.rotateVaultKey() }
            _ = try await reopened.sync()   // the sealed manifest pins them again
            #expect(try await reopened.identity()?.recoveryPinned == true)

            // A hostile server swaps the recovery key: reported, never adopted, and no backup is written.
            let other = try RecoveryKeys(phrase: try RecoveryPhrase.generate())
            try server.sql("UPDATE boxes SET recovery_pubkey = '\(other.publicKey.base64URLEncoded())'")
            _ = try await b.vault.sync()
            #expect(await b.vault.recoveryMaterialChanged)
            #expect(try await b.vault.identity()?.recoveryPublicKey == (try RecoveryKeys(phrase: second)).publicKey)
            let file = tempDir("backup").appendingPathExtension("bisel-backup")
            await #expect(throws: IntegrityError.recoveryMaterialChanged) { try await b.vault.exportBackup(to: file) }
            #expect(!FileManager.default.fileExists(atPath: file.path))
        }
    }

    @Test("a key the server relayed (recovery phrase, rotation) is checked against the box before anything is uploaded under it")
    func relayedKeysAreConfirmedBeforeUploading() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.bootstrap(server)
            try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            let count = { try server.value("SELECT COUNT(*) FROM items") }
            let boxItems = try count()

            // Honest recovery: an item saved before the first sync is uploaded once the key is confirmed.
            let honest = try Device("honest")
            try await honest.vault.recover(server: server.url, phrase: phrase, deviceName: "honest", boxID: try server.onlyBoxID())
            let mine = try await honest.vault.save(login("Mine", password: "mine-pw"))
            try await honest.vault.sync()
            #expect(try count() != boxItems, "confirmed, then uploaded")
            #expect(try await honest.vault.identity()?.keyUnconfirmed == false)
            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: mine.id) == "mine-pw")
            let afterHonest = try count()

            // A lying server seals a key of its own to the recovery public key it knows. The phrase holder cannot tell on the spot.
            let keys = try RecoveryKeys(phrase: phrase)
            let fake = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            let forged = try RecoveryKeys.seal(vaultKey: fake, toEncryptionKey: keys.encryptionPublicKey, signingKey: keys.publicKey, epoch: 1)
            try server.sql("UPDATE boxes SET recovery_envelope = '\(forged.base64URLEncoded())'")
            let victim = try Device("victim")
            try await victim.vault.recover(server: server.url, phrase: phrase, deviceName: "victim", boxID: try server.onlyBoxID())
            _ = try await victim.vault.save(login("Secret", password: "never-upload"))
            await #expect(throws: IntegrityError.keyConfirmationFailed) { _ = try await victim.vault.sync() }
            #expect(try count() == afterHonest, "nothing was uploaded under the server's key")
            #expect(!(await victim.vault.isUnlocked))
        }
    }

    @Test("a rotation the server forged for a device is not trusted with uploads")
    func forgedRotationAdoptionUploadsNothing() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            let count = { try server.value("SELECT COUNT(*) FROM items") }
            let before = try count()

            // The server claims epoch 2 and hands b an envelope for a key it made up.
            let me = try #require(try await b.vault.identity())
            let encPub = try #require(me.roster.first { $0.deviceID == me.deviceID }?.encPubkey)
            let fake = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            let envelope = try DeviceEnvelope.seal(vaultKey: fake, toEncryptionKey: encPub)
            try server.sql("UPDATE boxes SET epoch = 2")
            try server.sql("UPDATE devices SET envelope = '\(envelope.base64URLEncoded())', envelope_epoch = 2 WHERE id = '\(me.deviceID)'")
            let report = try await b.vault.sync()
            #expect(report.rotationAdopted)
            try await b.vault.unlock()
            _ = try await b.vault.save(login("Secret", password: "never-upload"))
            await #expect(throws: IntegrityError.keyConfirmationFailed) { _ = try await b.vault.sync() }
            #expect(try count() == before, "nothing was uploaded under the server's key")
        }
    }

    // MARK: M2

    @Test("a delete forged without the vault key is undone; a real delete lands in the trash; a rolled-back server is noticed")
    func tombstonesTrashAndRollback() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            let mail = try await a.vault.save(login("Mail", password: "mail-pw"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            // A stolen signing key deletes Bank: the server accepts it (it cannot check the marker).
            let aID = try #require(try await a.vault.identity()?.deviceID)
            let client = a.signedClientFactory(server.url, aID)
            let rev = try #require(try await client.pull(since: 0).records.first { $0.id == bank.id }).rev
            guard case .accepted = try await client.delete(id: bank.id, baseRev: rev, marker: Data(repeating: 1, count: 32), epoch: 1)
            else { Issue.record("delete refused"); return }

            let report = try await b.vault.sync()
            #expect(report.rejectedTombstones == [bank.id])
            #expect(try await b.vault.items().items.map(\.title).sorted() == ["Bank", "Mail"], "the forged delete did not take effect")
            #expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw")
            _ = try await b.vault.sync()        // the restored revision reaches the server
            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: bank.id) == "bank-pw")

            // A real delete by the owner is honoured everywhere and kept in the trash for 30 days.
            try await a.vault.delete(id: mail.id)
            try await a.vault.sync()
            let honoured = try await b.vault.sync()
            #expect(honoured.rejectedTombstones.isEmpty)
            #expect(try await b.vault.items().items.map(\.title) == ["Bank"])
            let trashed = try #require(try await b.vault.trash().first { $0.itemID == mail.id })
            #expect(trashed.source == .localTrash(reason: "remote-delete"))
            try await b.vault.restore(trashed)
            #expect(try await b.vault.revealPassword(id: mail.id) == "mail-pw")

            // A server that reports less than it already told us, or positions beyond its own head, is refused.
            _ = try await b.vault.sync()
            try server.sql("UPDATE boxes SET head_seq = head_seq - 1")
            do { _ = try await b.vault.sync(); Issue.record("rollback should be refused") }
            catch IntegrityError.serverRolledBack(let known, let reported) { #expect(reported == known - 1) }
            try server.sql("UPDATE boxes SET head_seq = head_seq + 1")
            _ = try await b.vault.sync()
            try server.sql("UPDATE items SET seq = seq + 1000 WHERE id = '\(bank.id)'")
            await #expect(throws: IntegrityError.invalidCursor) { _ = try await b.vault.sync() }
        }
    }

    // MARK: M4

    @Test("a device added with the recovery phrase is held back, announced to every device, and cancellable")
    func recoveryActivationDelayAndEvents() async throws {
        try await TestServer.with(vars: ["RECOVERY_ACTIVATION_DELAY_SECONDS": "3"]) { server in
            let a = try Device("a")
            let phrase = try await a.bootstrap(server)
            try await a.vault.save(login("Bank", password: "bank-pw"))
            let first = try await a.vault.sync()
            #expect(first.events.isEmpty, "a device's first sync learns the position, it is not news")

            let thief = try Device("phrase-holder")
            try await thief.vault.recover(server: server.url, phrase: phrase, deviceName: "phrase-holder", boxID: try server.onlyBoxID())
            let until = try #require(await thief.vault.activationDate())
            do { _ = try await thief.vault.sync(); Issue.record("must wait") }
            catch IntegrityError.pendingActivation(let at) { #expect(abs(at.timeIntervalSince(until)) < 1) }

            // The owner's device is told on its very next sync, sees the pending device, and cannot rotate around it.
            let news = try await a.vault.sync()
            #expect(news.events.contains { $0.type == "recovery" })
            let pending = try #require(try await a.vault.devices().first { $0.isPending() })
            do { _ = try await a.vault.rotateVaultKey(); Issue.record("rotation should stop") }
            catch IntegrityError.unknownDevices(let u) { #expect(u.map(\.id) == [pending.id]); #expect(u[0].pendingActivation) }

            // Cancelling = revoking it; after the delay it is still refused.
            try await a.vault.revoke(deviceID: pending.id)
            try await Task.sleep(for: .seconds(3.3))
            await #expect(throws: SyncError.notAuthorized) { _ = try await thief.vault.sync() }

            // The honest path works too: recover on a fresh install, wait, sync.
            let again = try Device("again")
            let secondPhrase = phrase
            try await again.vault.recover(server: server.url, phrase: secondPhrase, deviceName: "again", boxID: try server.onlyBoxID())
            try await Task.sleep(for: .seconds(3.3))
            _ = try await again.vault.sync()
            #expect(try await again.vault.items().items.count == 1)
        }
    }

    // MARK: M8, M17

    @Test("revoking reports what the device could have read; the server address never sits in the plaintext database")
    func revocationReportAndServerAddress() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            try await a.vault.save(Item(title: "Bank", username: "me", password: "pw", totp: TOTPParameters(secret: "JBSWY3DPEHPK3PXP")))
            try await a.vault.save(Item(type: .note, title: "Wi-Fi note", notes: "no password here"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            _ = try await b.vault.sync()

            let report = try await a.vault.revoke(deviceID: try #require(try await b.vault.identity()?.deviceID))
            #expect(report.revokedDeviceName == "b")
            #expect(report.exposed.map(\.title) == ["Bank", "Wi-Fi note"])
            #expect(report.secretsToChange.map(\.title) == ["Bank"], "only logins/secrets with a password or TOTP need changing")
            #expect(report.exposed.first?.hasTOTP == true)

            // SECURITY-REVIEW M17: look at the bytes on disk.
            let host = try #require(server.url.host), port = try #require(server.url.port)
            for file in ["bisel.sqlite", "bisel.sqlite-wal"] {
                guard let data = try? Data(contentsOf: a.location.directory.appendingPathComponent(file)) else { continue }
                #expect(data.range(of: Data("\(host):\(port)".utf8)) == nil, "\(file) contains the server address")
            }
            #expect(try await a.relaunched().identity()?.serverURL == server.url, "...and it still comes back from the secret store")
        }
    }

    // MARK: Local surface audit (2026-10-31), fill origin

    @Test("a login is never typed into a lookalike, another tenant of a shared host, or a page under a bare TLD")
    func fillOriginRefusesLookalikesAndOtherTenants() {
        // A few rules of the Public Suffix List (the app passes the bundled list): ICANN suffixes and private shared-hosting ones.
        let suffixes: Set<String> = ["com", "net", "uk", "co.uk", "io", "github.io", "app", "vercel.app", "myshopify.com", "bank"]
        func fits(_ page: String, _ itemURL: String) -> Bool {
            let p = SiteMatch.normalized(page)
            return SiteMatch.hosts(of: [itemURL]).contains { SiteMatch.matches(page: p, item: $0, isPublicSuffix: { suffixes.contains($0) || !$0.contains(".") }) }
        }

        // The same site and its subdomains, both ways.
        #expect(fits("bank.com", "https://bank.com/login"))
        #expect(fits("WWW.Bank.com.", "bank.com"))
        #expect(fits("login.bank.com", "https://www.bank.com"))
        #expect(fits("bank.com", "https://login.bank.com"))
        #expect(fits("alice.github.io", "https://alice.github.io/admin"))
        #expect(fits("shop.example.co.uk", "example.co.uk"))

        // Lookalikes and look-through tricks.
        #expect(!fits("bank.com.evil.net", "bank.com"))
        #expect(!fits("evilbank.com", "bank.com"))
        #expect(!fits("xn--bnk-sna.com", "bank.com"), "a homograph is another host")
        #expect(!fits("bank.com", "https://bank.com@evil.net"), "the item's host is evil.net, the user-info is not a host")

        // A public suffix is not a site: other tenants of a shared host, or any page under a TLD saved as an address.
        #expect(!fits("bob.github.io", "https://alice.github.io"))
        #expect(!fits("attacker.github.io", "https://github.io"))
        #expect(!fits("github.io", "https://alice.github.io"))
        #expect(!fits("evil-store.myshopify.com", "myshopify.com"))
        #expect(!fits("phish.vercel.app", "vercel.app"))
        #expect(!fits("evil.com", "com"))
        #expect(!fits("anything.co.uk", "co.uk"))
        #expect(!fits("phish.bank", "bank"), "`.bank` is a real TLD")
        #expect(!fits("intranet.localhost", "localhost"))

        // IP addresses only match exactly.
        #expect(fits("192.168.1.1", "http://192.168.1.1:8080"))
        #expect(!fits("10.192.168.1.1", "192.168.1.1"))
        #expect(!fits("1.1", "192.168.1.1"))
    }

    // MARK: helpers

    private func fingerprintBits(_ fingerprint: String) -> Int { fingerprint.filter { $0 != "-" }.count * 4 }

    private func serverBlobs(_ server: TestServer, as device: Device) async throws -> [StoredRecord] {
        let id = try #require(try await device.vault.identity())
        return try await device.signedClientFactory(server.url, id.deviceID).pull(since: 0).records.filter { !$0.deleted }
    }
}

#endif
