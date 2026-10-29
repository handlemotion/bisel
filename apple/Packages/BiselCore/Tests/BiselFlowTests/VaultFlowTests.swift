#if BISEL_SOFTWARE_KEYS
import Foundation
import Testing
import BiselCore
import BiselTestSupport

// Flow tests: real server (wrangler dev, local D1), real crypto, software key store.
// Run with: swift test --traits SoftwareKeys
@Suite("Vault flows against the local server", .serialized)
struct VaultFlowTests {

    @Test("a write on device A is readable on device B, and the server only ever holds ciphertext")
    func twoDevicesShareAVault() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)

            let github = try await a.vault.save(Item(title: "GitHub", urls: ["https://github.com"], username: "rodrigo",
                                                     password: "correct-horse-battery-staple",
                                                     totp: TOTPParameters(secret: "JBSWY3DPEHPK3PXP"),
                                                     notes: "personal account", tags: ["dev"]))
            // The app is killed before it ever synced: the edit must survive in the local store.
            let relaunched = try a.relaunched()
            try await relaunched.unlock()
            #expect(try await relaunched.items().items.map(\.title) == ["GitHub"])
            #expect(try await relaunched.pendingChanges() == 1)
            let report = try await relaunched.sync()
            #expect(report.pushed == 1)

            try await b.enroll(through: a, server: server)
            let onB = try await b.vault.items().items
            #expect(onB.count == 1)
            #expect(onB.first?.id == github.id)
            #expect(onB.first?.username == "rodrigo")
            #expect(onB.first?.notes == "personal account")
            #expect(try await b.vault.revealPassword(id: github.id) == "correct-horse-battery-staple")

            // Edit on B, delete another on A; both sides converge.
            var edited = try await b.vault.item(id: github.id)
            edited.password = "rotated-by-b"
            try await b.vault.save(edited)
            let temp = try await a.vault.save(login("Temp", password: "x"))
            try await a.vault.sync()
            try await b.vault.sync()
            try await b.vault.delete(id: temp.id)
            try await b.vault.sync()
            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: github.id) == "rotated-by-b")
            #expect(try await a.vault.items().items.map(\.title) == ["GitHub"])

            // Zero knowledge: pull the raw records as a device would and look for plaintext.
            let id = try #require(try await a.vault.identity())
            let page = try await a.signedClientFactory(server.url, id.deviceID).pull(since: 0)
            #expect(page.records.count == 2)   // GitHub + the Temp tombstone
            for record in page.records {
                for needle in ["GitHub", "github.com", "rotated-by-b", "correct-horse", "rodrigo", "JBSWY3DPEHPK3PXP"] {
                    #expect(record.blob.range(of: Data(needle.utf8)) == nil, "server record leaks \(needle)")
                }
            }
            #expect(page.records.filter { !$0.deleted }.allSatisfy { $0.blob.count % 16 != 1 })   // sanity: not raw text
            #expect(page.records.filter { !$0.deleted }.allSatisfy { ($0.blob.count - 60 - 28) % 512 == 0 })   // padded to 512
        }
    }

    @Test("TOTP matches the RFC 6238 test vector and needs a fresh biometric check each time")
    func totpAndSensitiveActionsAskForBiometrics() async throws {
        try await TestServer.with { server in
            let gate = RecordingGate()
            let a = try Device("a", gate: gate)
            try await a.bootstrap(server)

            let item = try await a.vault.save(Item(title: "Bank", username: "me", password: "pw-1",
                                                   totp: TOTPParameters(secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", algo: .sha1, digits: 8, period: 30)))
            #expect(gate.calls.isEmpty, "creating an item and listing must not prompt")
            _ = try await a.vault.items()
            _ = try await a.vault.summaries()
            #expect(gate.calls.isEmpty, "browsing inside the fill window must not prompt")

            let code = try await a.vault.copyTOTP(id: item.id, at: Date(timeIntervalSince1970: 59))
            #expect(code.code == "94287082")           // RFC 6238 appendix B, SHA-1, T=59
            #expect(code.secondsRemaining == 1)
            #expect(gate.calls.count == 1)
            _ = try await a.vault.copyTOTP(id: item.id)
            #expect(gate.calls.count == 2, "TOTP prompts every single time")

            _ = try await a.vault.revealPassword(id: item.id)
            var edit = try await a.vault.item(id: item.id)
            edit.title = "Bank 2"
            try await a.vault.save(edit)
            try await a.vault.delete(id: item.id)
            #expect(gate.calls.count == 5, "reveal, edit and delete each prompt: \(gate.calls)")

            // Refusal blocks the action and leaks nothing.
            let other = try await a.vault.save(login("Other", password: "secret-x"))
            gate.deny(true)
            await #expect(throws: KeyStoreError.userCancelled) { _ = try await a.vault.revealPassword(id: other.id) }
            await #expect(throws: KeyStoreError.userCancelled) { _ = try await a.vault.copyTOTP(id: other.id) }
            await #expect(throws: KeyStoreError.userCancelled) { try await a.vault.delete(id: other.id) }
            var changed = try await a.vault.item(id: other.id)
            changed.password = "attacker"
            await #expect(throws: KeyStoreError.userCancelled) { try await a.vault.save(changed) }
            gate.deny(false)
            #expect(try await a.vault.revealPassword(id: other.id) == "secret-x")
        }
    }

    @Test("VK leaves memory on lock and when the fill window ends; unlock brings it back")
    func lockAndFillWindow() async throws {
        try await TestServer.with { server in
            let a = try Device("a", fillWindow: 1.0)
            try await a.bootstrap(server)
            try await a.vault.save(login("One", password: "p"))
            #expect(try await a.vault.items().items.count == 1)

            try await Task.sleep(for: .milliseconds(1300))
            #expect(await !a.vault.isUnlocked)
            await #expect(throws: VaultError.locked) { _ = try await a.vault.items() }

            try await a.vault.unlock()
            #expect(try await a.vault.items().items.count == 1)
            await a.vault.lock()
            await #expect(throws: VaultError.locked) { _ = try await a.vault.item(id: "anything") }
            // Background sync works while locked (no VK needed to move ciphertext).
            let report = try await a.vault.sync()
            #expect(report.pushed == 1)
        }
    }

    @Test("concurrent edits keep the remote version and save the local edit as a '(conflict)' item")
    func conflictingEdits() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            let item = try await a.vault.save(login("Router", user: "admin", password: "orig"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            var editA = try await a.vault.item(id: item.id); editA.password = "from-A"
            var editB = try await b.vault.item(id: item.id); editB.password = "from-B"
            try await a.vault.save(editA)
            try await b.vault.save(editB)       // both offline from each other

            #expect(try await a.vault.sync().conflicts.isEmpty)
            let report = try await b.vault.sync()
            let conflict = try #require(report.conflicts.first)
            #expect(conflict.itemID == item.id)

            // B: remote (A's) version wins on the original, B's edit survives under the copy. Nothing silently lost.
            #expect(try await b.vault.revealPassword(id: item.id) == "from-A")
            let copy = try await b.vault.item(id: conflict.copyID)
            #expect(copy.title == "Router (conflict)")
            #expect(try await b.vault.revealPassword(id: copy.id) == "from-B")

            try await a.vault.sync()
            #expect(try await a.vault.items().items.map(\.title).sorted() == ["Router", "Router (conflict)"])
            #expect(try await a.vault.revealPassword(id: conflict.copyID) == "from-B")
        }
    }

    @Test("a revoked device is cut off at once; remaining devices keep working")
    func revocation() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            let item = try await a.vault.save(login("Shared", password: "p1"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            #expect(try await b.vault.items().items.count == 1)

            let devices = try await a.vault.devices()
            let bID = try #require(try await b.vault.identity()?.deviceID)
            #expect(devices.count == 2)
            try await a.vault.revoke(deviceID: bID)
            #expect(try await a.vault.devices().first { $0.id == bID }?.isRevoked == true)

            await #expect(throws: SyncError.notAuthorized) { try await b.vault.sync() }
            try await b.vault.save(login("Sneaky", password: "x"))
            await #expect(throws: SyncError.notAuthorized) { try await b.vault.sync() }

            var edit = try await a.vault.item(id: item.id); edit.password = "p2"
            try await a.vault.save(edit)
            try await a.vault.sync()
            #expect(try await a.vault.items().items.map(\.title) == ["Shared"], "revoked device's write never reached the vault")
        }
    }

    @Test("recover from the 24 words on a fresh store; wrong or rotated-away phrases do not work")
    func recoveryFromPhrase() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.bootstrap(server)
            #expect(phrase.words.count == 24)
            let item = try await a.vault.save(Item(title: "Passport scan code", username: "me", password: "p-recover",
                                                   totp: TOTPParameters(secret: "JBSWY3DPEHPK3PXP")))
            try await a.vault.sync()

            let fresh = try Device("fresh")
            try await fresh.vault.recover(server: server.url, phrase: phrase, deviceName: "fresh")
            try await fresh.vault.sync()
            let items = try await fresh.vault.items().items
            #expect(items.map(\.title) == ["Passport scan code"])
            #expect(try await fresh.vault.revealPassword(id: item.id) == "p-recover")
            #expect(try await a.vault.devices().count == 2)

            // A different but valid phrase gets the uniform 404.
            let stranger = try Device("stranger")
            await #expect(throws: SyncError.notAuthorized) {
                try await stranger.vault.recover(server: server.url, phrase: try RecoveryPhrase.generate(), deviceName: "x")
            }
            // Words that fail the BIP-39 checksum are rejected before any network call.
            #expect(throws: BiselCryptoError.invalidRecoveryPhrase) { try RecoveryPhrase(phrase.words.reversed().joined(separator: " ")) }
            // Input is forgiving about case and whitespace.
            _ = try RecoveryPhrase("  " + phrase.text.uppercased().replacingOccurrences(of: " ", with: "\n") + " ")

            // Rotation: the new phrase works, the old one stops at once.
            let newPhrase = try await fresh.vault.rotateRecovery()
            let again = try Device("again")
            await #expect(throws: SyncError.notAuthorized) { try await again.vault.recover(server: server.url, phrase: phrase, deviceName: "old") }
            try await again.vault.recover(server: server.url, phrase: newPhrase, deviceName: "new")
            try await again.vault.sync()
            #expect(try await again.vault.items().items.count == 1)
        }
    }

    @Test("a backup file restores onto a brand-new server, opens only with its phrase, and the same phrase keeps working")
    func backupAndRestore() async throws {
        let backup = FileManager.default.temporaryDirectory.appendingPathComponent("flow-\(UUID().uuidString).bisel-backup")
        defer { try? FileManager.default.removeItem(at: backup) }
        let phrase: RecoveryPhrase

        phrase = try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.bootstrap(server)
            try await a.vault.save(login("Keep me", user: "u1", password: "pw-keep"))
            let gone = try await a.vault.save(login("Delete me", password: "pw-gone"))
            try await a.vault.save(login("Also keep", user: "u2", password: "pw-also"))
            try await a.vault.sync()
            try await a.vault.delete(id: gone.id)
            try await a.vault.save(try await a.vault.items().items.first { $0.title == "Keep me" }.map { var i = $0; i.password = "pw-keep-v2"; return i }!)
            try await a.vault.exportBackup(to: backup)       // syncs first
            return phrase
        }

        // The old server is gone. Restore onto a new one.
        try await TestServer.with { fresh in
            let wrong = try Device("wrong")
            await #expect(throws: VaultError.self) {
                try await wrong.vault.importBackup(from: backup, phrase: try RecoveryPhrase.generate(), server: fresh.url,
                                                   bootstrapToken: TestServer.bootstrapToken, deviceName: "w")
            }

            let restored = try Device("restored")
            try await restored.vault.importBackup(from: backup, phrase: phrase, server: fresh.url,
                                                  bootstrapToken: TestServer.bootstrapToken, deviceName: "restored")
            let items = try await restored.vault.items().items
            #expect(items.map(\.title).sorted() == ["Also keep", "Keep me"], "deleted items stay deleted")
            let keep = try #require(items.first { $0.title == "Keep me" })
            #expect(try await restored.vault.revealPassword(id: keep.id) == "pw-keep-v2")

            // The server now holds the vault again, and the original phrase still recovers a brand-new install.
            let reinstall = try Device("reinstall")
            try await reinstall.vault.recover(server: fresh.url, phrase: phrase, deviceName: "reinstall")
            try await reinstall.vault.sync()
            #expect(try await reinstall.vault.items().items.count == 2)
        }
    }

    @Test("ciphertext cannot be moved to another item id or replayed at another revision")
    func swapAndRollbackProtection() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            let mail = try await a.vault.save(login("Mail", password: "mail-pw"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            // A hostile server (or anyone who can write records) copies Bank's ciphertext to a new id…
            let aID = try #require(try await a.vault.identity()?.deviceID)
            let client = a.signedClientFactory(server.url, aID)
            let page = try await client.pull(since: 0)
            let bankBlob = try #require(page.records.first { $0.id == bank.id }).blob
            let swapped = BiselRandom.identifier()
            guard case .accepted = try await client.put(id: swapped, baseRev: 0, blob: bankBlob) else { Issue.record("put refused"); return }
            // …and also over Mail itself.
            let mailRecord = try #require(page.records.first { $0.id == mail.id })
            guard case .accepted = try await client.put(id: mail.id, baseRev: mailRecord.rev, blob: bankBlob) else { Issue.record("put refused"); return }

            try await b.vault.sync()
            let listing = try await b.vault.items()
            #expect(listing.items.map(\.title) == ["Bank"], "only the genuine Bank record decrypts")
            #expect(Set(listing.undecryptable) == [swapped, mail.id])
            await #expect(throws: (any Error).self) { _ = try await b.vault.item(id: swapped) }
            await #expect(throws: (any Error).self) { _ = try await b.vault.item(id: mail.id) }

            // Rollback: an old revision of Bank is replayed as the newest one.
            var edit = try await a.vault.item(id: bank.id); edit.password = "bank-pw-2"
            try await a.vault.save(edit)
            try await a.vault.sync()
            let current = try #require(try await client.pull(since: 0).records.first { $0.id == bank.id })
            guard case .accepted = try await client.put(id: bank.id, baseRev: current.rev, blob: bankBlob) else { Issue.record("put refused"); return }
            try await b.vault.sync()
            #expect(try await b.vault.items().undecryptable.contains(bank.id), "revision is bound into the AAD")
        }
    }
}
#endif
