#if BISEL_SOFTWARE_KEYS
import Foundation
import Testing
import BiselCore
import BiselTestSupport
import CryptoKit

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
            #expect(try await relaunched.pendingChanges() == 2, "the item and the vault manifest")
            let report = try await relaunched.sync()
            #expect(report.pushed == 2)

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
            #expect(page.records.count == 3)   // GitHub, the Temp tombstone, and the sealed vault manifest
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
            #expect(report.pushed == 1)   // the item; the manifest needs the vault-admin signature, so it waits for an unlock
            try await a.vault.unlock()
            #expect(try await a.vault.sync().pushed == 1)   // the deferred manifest
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

    @Test("Back from a brand-new box's recovery phrase erases it, and creating again works with a new phrase")
    func discardFreshLocalBoxThenStartOver() async throws {
        let a = try Device("fresh")
        let first = try await a.vault.bootstrapLocal(deviceName: "fresh")
        #expect(await a.vault.isConfigured)
        try await a.vault.removeLocalDevice()
        #expect(!(await a.vault.isConfigured), "nothing is left on this Mac after Back")
        let second = try await a.vault.bootstrapLocal(deviceName: "fresh again")
        #expect(await a.vault.isConfigured)
        #expect(first.words != second.words, "starting over makes a new phrase")
    }

    @Test("a local-only vault works offline, then connecting a server uploads everything and the phrase recovers it elsewhere")
    func localFirstThenConnect() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.vault.bootstrapLocal(deviceName: "a")
            #expect(try await a.vault.identity()?.serverURL == nil)
            let item = try await a.vault.save(Item(title: "Imported", username: "me", password: "p-local"))
            let report = try await a.vault.sync()
            #expect(report.pushed == 0 && report.pulled == 0, "no server: sync is a no-op")
            await #expect(throws: VaultError.noServer) { _ = try await a.vault.devices() }
            let relaunched = try a.relaunched()
            try await relaunched.unlock()
            #expect(try await relaunched.revealPassword(id: item.id) == "p-local", "it survives a relaunch with no server")

            try await a.vault.connectServer(server.url, bootstrapToken: TestServer.bootstrapToken)
            #expect(try await a.vault.identity()?.serverURL == server.url)
            let pushed = try await a.vault.sync()
            #expect(pushed.pushed >= 1)

            let fresh = try Device("fresh")
            try await fresh.vault.recover(server: server.url, phrase: phrase, deviceName: "fresh", boxID: try server.onlyBoxID())
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: item.id) == "p-local")
            #expect(try await a.vault.devices().count == 2)
        }
    }

    @Test("a local-only vault exports a full backup and restores from it offline, as after the device key was lost")
    func localOnlyBackupAndOfflineRestore() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.vault.bootstrapLocal(deviceName: "a")
            let kept = try await a.vault.save(Item(title: "Never pushed", username: "me", password: "p-kept"))
            let gone = try await a.vault.save(Item(title: "Deleted", username: "me", password: "p-gone"))
            try await a.vault.delete(id: gone.id)
            let backup = FileManager.default.temporaryDirectory.appendingPathComponent("local-\(UUID().uuidString).bisel-backup")
            defer { try? FileManager.default.removeItem(at: backup) }
            try await a.vault.exportBackup(to: backup)

            // The Mac's fingerprint set changed: a fresh store, no server anywhere.
            let b = try Device("b")
            await #expect(throws: VaultError.self) { try await b.vault.importBackupLocal(from: backup, phrase: try RecoveryPhrase.generate(), deviceName: "b") }
            let skipped = try await b.vault.importBackupLocal(from: backup, phrase: phrase, deviceName: "b")
            #expect(skipped == 0)
            #expect(try await b.vault.identity()?.serverURL == nil)
            let listing = try await b.vault.items()
            #expect(listing.items.map(\.id) == [kept.id], "the unsynced item survives, the deleted one stays deleted")
            #expect(try await b.vault.revealPassword(id: kept.id) == "p-kept")

            // And the restored vault can still be connected to a server and recovered with the same phrase.
            try await b.vault.connectServer(server.url, bootstrapToken: TestServer.bootstrapToken)
            try await b.vault.sync()
            let c = try Device("c")
            try await c.vault.recover(server: server.url, phrase: phrase, deviceName: "c", boxID: try server.onlyBoxID())
            try await c.vault.sync()
            #expect(try await c.vault.revealPassword(id: kept.id) == "p-kept")
        }
    }

    @Test("after the server's database is restored from an earlier point, the device uploads again what the restore lost")
    func deviceReseedsARestoredServer() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.bootstrap(server)
            var x = try await a.vault.save(login("Kept", password: "x1"))
            try await a.vault.sync()
            x.password = "x2"
            _ = try await a.vault.save(x)
            let y = try await a.vault.save(login("Newer", password: "y1"))
            try await a.vault.sync()

            // Restore point: Y does not exist yet and X is back at its first revision.
            try server.sql("DELETE FROM items WHERE id = '\(y.id)'")
            try server.sql("UPDATE items SET rev = 1 WHERE id = '\(x.id)'")
            try server.sql("UPDATE boxes SET head_seq = head_seq - 1")
            do { _ = try await a.vault.sync(); Issue.record("a rolled-back server must be refused") }
            catch IntegrityError.serverRolledBack {}

            try await a.vault.acknowledgeServerReset()
            let report = try await a.vault.sync()
            #expect(report.pushed >= 2, "both the lost item and the lost revision go back up")
            #expect(report.conflicts.isEmpty)
            #expect(try await a.vault.pendingChanges() == 0)
            let fresh = try Device("fresh")
            try await fresh.vault.recover(server: server.url, phrase: phrase, deviceName: "fresh", boxID: try server.onlyBoxID())
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: x.id) == "x2")
            #expect(try await fresh.vault.revealPassword(id: y.id) == "y1")
        }
    }

    @Test("a healthy device re-seeds a rebuilt server, and a pending edit against a record the server lost is uploaded, not stuck")
    func deviceReseedsAnEmptyServer() async throws {
        try await TestServer.with { old in
            let a = try Device("a")
            let phrase = try await a.bootstrap(old)
            let one = try await a.vault.save(login("One", password: "p1"))
            let two = try await a.vault.save(login("Two", password: "p2"))
            try await a.vault.sync()
            try await a.vault.delete(id: two.id)
            try await a.vault.sync()

            try await TestServer.with { rebuilt in
                try await a.vault.reconnectServer(rebuilt.url, bootstrapToken: TestServer.bootstrapToken)
                let report = try await a.vault.sync()
                #expect(report.pushed >= 1)
                #expect(try await a.vault.pendingChanges() == 0)
                let fresh = try Device("fresh")
                try await fresh.vault.recover(server: rebuilt.url, phrase: phrase, deviceName: "fresh", boxID: try rebuilt.onlyBoxID())
                try await fresh.vault.sync()
                #expect(try await fresh.vault.items().items.map(\.id) == [one.id], "the live item came back, the deleted one stays deleted")
                #expect(try await fresh.vault.revealPassword(id: one.id) == "p1")

                // An edit made against the old revision when the server has lost the record altogether.
                try rebuilt.sql("DELETE FROM items WHERE id = '\(one.id)'")
                try rebuilt.sql("UPDATE boxes SET head_seq = (SELECT COALESCE(MAX(seq), 0) FROM items)")
                var edited = try await a.vault.item(id: one.id)
                edited.password = "p1-edited"
                _ = try await a.vault.save(edited)
                let again = try await a.vault.sync()
                #expect(again.deferredConflicts.isEmpty)
                #expect(try await a.vault.pendingChanges() == 0, "the edit was not left stuck")
            }
        }
    }

    @Test("a connect whose answer was lost is adopted on retry instead of being refused for good")
    func connectAfterLostAnswer() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.vault.bootstrapLocal(deviceName: "a")
            let item = try await a.vault.save(login("Local", password: "p-local"))
            let id = try #require(try await a.vault.identity())
            let me = try #require(id.roster.first { $0.deviceID == id.deviceID })

            // The first attempt reached the server (it now holds this device and the recovery keys); the answer never came back.
            try await SyncClient.bootstrap(
                baseURL: server.url, token: TestServer.bootstrapToken,
                device: WireDevice(id: id.deviceID, name: "a", kind: "test", sigPubkey: me.sigPubkey, encPubkey: me.encPubkey, envelope: id.envelope),
                recoveryPublicKey: try #require(id.recoveryPublicKey), recoveryEncryptionPublicKey: try #require(id.recoveryEncryptionPublicKey),
                recoveryEnvelope: try #require(id.recoveryEnvelope),
                adminPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
            #expect(try await a.vault.identity()?.serverURL == nil, "the app still believes it is local-only")

            try await a.vault.connectServer(server.url, bootstrapToken: TestServer.bootstrapToken)
            #expect(try await a.vault.identity()?.serverURL == server.url)
            try await a.vault.sync()
            let fresh = try Device("fresh")
            try await fresh.vault.recover(server: server.url, phrase: phrase, deviceName: "fresh", boxID: try server.onlyBoxID())
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: item.id) == "p-local")

            // Another vault's server is not adopted: this device is not registered there.
            try await TestServer.with { other in
                let b = try Device("b")
                _ = try await b.vault.bootstrapLocal(deviceName: "b")
                await #expect(throws: SyncError.notAuthorized) {
                    try await b.vault.connectServer(other.url, bootstrapToken: "wrong-token")
                }
            }
        }
    }

    @Test("a push the server accepted but never answered is recognised on retry: no duplicate '(conflict)' item")
    func lostPushResponse() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            try await a.bootstrap(server)
            let item = try await a.vault.save(login("Once", password: "p"))
            let id = try #require(try await a.vault.identity())
            // The push reaches the server; the answer never comes back.
            let store = try LocalStore(location: a.location, secrets: FileSecretStore(directory: a.location.directory))
            let rec = try #require(try store.pendingRecords().first { $0.id == item.id })
            let outcome = try await a.signedClientFactory(server.url, id.deviceID).put(id: rec.id, baseRev: rec.baseRev, blob: rec.blob, epoch: id.epoch)
            guard case .accepted = outcome else { Issue.record("the first push should be accepted"); return }

            let report = try await a.vault.sync()
            #expect(report.conflicts.isEmpty && report.deferredConflicts.isEmpty)
            #expect(try await a.vault.items().items.map(\.title) == ["Once"])
            #expect(try await a.vault.pendingChanges() == 0)
        }
    }

    @Test("an edit made while its own earlier version is being pushed continues from it: no '(conflict)' copy of the user's own item")
    func editDuringPush() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            try await a.bootstrap(server)
            var item = try await a.vault.save(login("Busy", password: "v0"))
            try await a.vault.sync()
            for round in 1...3 {
                item.password = "v\(round)-a"
                _ = try await a.vault.save(item)
                let syncing = Task { try await a.vault.sync() }
                for n in 0..<6 {
                    item.password = "v\(round)-b\(n)"
                    _ = try await a.vault.save(item)
                    try await Task.sleep(for: .milliseconds(6))
                }
                _ = try await syncing.value
                try await a.vault.sync()
            }
            let titles: [String]
            do { titles = try await a.vault.items().items.map(\.title) } catch { Issue.record("items() threw \(error)"); return }
            #expect(titles == ["Busy"], "no conflict copies of the user's own edits")
            #expect(try await a.vault.revealPassword(id: item.id) == "v3-b5")
            #expect(try await a.vault.pendingChanges() == 0)
        }
    }

    @Test("a forged delete that arrives as the answer to a push is checked like any other: it is rejected, the user's edit survives")
    func forgedDeleteThroughConflict() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            try await a.bootstrap(server)
            var item = try await a.vault.save(login("Target", password: "v1"))
            try await a.vault.sync()
            try server.sql("UPDATE items SET deleted = 1, rev = rev + 1, blob = 'AAAA' WHERE id = '\(item.id)'")
            item.password = "v2"
            _ = try await a.vault.save(item)
            let report = try await a.vault.sync()
            #expect(report.rejectedTombstones == [item.id], "the marker did not verify")
            #expect(report.conflicts.count == 1)
            let listing = try await a.vault.items()
            let copy = try #require(listing.items.first { $0.title == "Target (conflict)" })
            #expect(try await a.vault.revealPassword(id: copy.id) == "v2", "the edit lives on in the copy")
        }
    }

    @Test("a damaged backup restores what opens and uploads it; one where nothing opens is refused before the server is touched")
    func damagedBackup() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.bootstrap(server)
            for n in 0..<3 { try await a.vault.save(login("Item \(n)", password: "pw-\(n)")) }
            try await a.vault.sync()
            let good = FileManager.default.temporaryDirectory.appendingPathComponent("good-\(UUID().uuidString).bisel-backup")
            let some = FileManager.default.temporaryDirectory.appendingPathComponent("some-\(UUID().uuidString).bisel-backup")
            let none = FileManager.default.temporaryDirectory.appendingPathComponent("none-\(UUID().uuidString).bisel-backup")
            defer { for f in [good, some, none] { try? FileManager.default.removeItem(at: f) } }
            try await a.vault.exportBackup(to: good)

            // Move ciphertext between ids: the AAD binds id and revision, so every moved blob fails authentication.
            func damaged(swapping count: Int) throws -> Data {
                var json = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: good)) as? [String: Any])
                var items = try #require(json["items"] as? [[String: Any]])
                let blobs = items.map { $0["blob"] }
                let count = min(count, items.count)
                for i in 0..<count { items[i]["blob"] = blobs[(i + 1) % count] }
                json["items"] = items
                return try JSONSerialization.data(withJSONObject: json)
            }
            try damaged(swapping: 2).write(to: some)
            try damaged(swapping: .max).write(to: none)   // every record moved

            try await TestServer.with { fresh in
                let refused = try Device("refused")
                await #expect(throws: VaultError.self) {
                    try await refused.vault.importBackup(from: none, phrase: phrase, server: fresh.url, bootstrapToken: TestServer.bootstrapToken, deviceName: "refused")
                }
                #expect(try await refused.vault.identity() == nil, "nothing was bootstrapped or written")

                // The same fresh server still accepts the partly damaged one, uploads what opened, and says what it skipped.
                let partial = try Device("partial")
                await #expect(throws: VaultError.self) {
                    try await partial.vault.importBackup(from: some, phrase: phrase, server: fresh.url, bootstrapToken: TestServer.bootstrapToken, deviceName: "partial")
                }
                #expect(try await partial.vault.identity()?.serverURL == fresh.url)
                #expect(try await partial.vault.pendingChanges() == 0, "what could be restored is already on the server")
                #expect(try await partial.vault.items().items.count >= 1)
            }
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
            try await fresh.vault.recover(server: server.url, phrase: phrase, deviceName: "fresh", boxID: try server.onlyBoxID())
            try await fresh.vault.sync()
            let items = try await fresh.vault.items().items
            #expect(items.map(\.title) == ["Passport scan code"])
            #expect(try await fresh.vault.revealPassword(id: item.id) == "p-recover")
            #expect(try await a.vault.devices().count == 2)

            // A different but valid phrase gets the uniform 404.
            let stranger = try Device("stranger")
            await #expect(throws: SyncError.notAuthorized) {
                try await stranger.vault.recover(server: server.url, phrase: try RecoveryPhrase.generate(), deviceName: "x", boxID: try server.onlyBoxID())
            }
            // Words that fail the BIP-39 checksum are rejected before any network call.
            #expect(throws: BiselCryptoError.invalidRecoveryPhrase) { try RecoveryPhrase(phrase.words.reversed().joined(separator: " ")) }
            // Input is forgiving about case and whitespace.
            _ = try RecoveryPhrase("  " + phrase.text.uppercased().replacingOccurrences(of: " ", with: "\n") + " ")

            // Rotation: the new phrase works, the old one stops at once.
            let newPhrase = try await fresh.vault.rotateRecovery()
            let again = try Device("again")
            await #expect(throws: SyncError.notAuthorized) { try await again.vault.recover(server: server.url, phrase: phrase, deviceName: "old", boxID: try server.onlyBoxID()) }
            try await again.vault.recover(server: server.url, phrase: newPhrase, deviceName: "new", boxID: try server.onlyBoxID())
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
            try await reinstall.vault.recover(server: fresh.url, phrase: phrase, deviceName: "reinstall", boxID: try fresh.onlyBoxID())
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
            guard case .accepted = try await client.put(id: swapped, baseRev: 0, blob: bankBlob, epoch: 1) else { Issue.record("put refused"); return }
            // …and also over Mail itself.
            let mailRecord = try #require(page.records.first { $0.id == mail.id })
            guard case .accepted = try await client.put(id: mail.id, baseRev: mailRecord.rev, blob: bankBlob, epoch: 1) else { Issue.record("put refused"); return }

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
            guard case .accepted = try await client.put(id: bank.id, baseRev: current.rev, blob: bankBlob, epoch: 1) else { Issue.record("put refused"); return }
            try await b.vault.sync()
            #expect(try await b.vault.items().undecryptable.contains(bank.id), "revision is bound into the AAD")
        }
    }

    // MARK: vault-key rotation

    /// What a hostile or breached server holds: every live record exactly as stored.
    private func serverRecords(_ server: TestServer, as device: Device) async throws -> [StoredRecord] {
        let id = try #require(try await device.vault.identity())
        return try await device.signedClientFactory(server.url, id.deviceID).pull(since: 0).records
    }

    /// Tries to open a stored record with a raw vault key; nil when it does not authenticate.
    private func open(_ record: StoredRecord, with vk: Data) -> Data? {
        record.deleted ? nil : try? ItemSealer.open(blob: record.blob, id: record.id, rev: record.rev, vaultKey: SymmetricKey(data: vk))
    }

    @Test("revoking a device rotates the vault key: the revoked device keeps nothing it can use against the server's data")
    func revokeRotatesTheVaultKey() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b"), c = try Device("c")
            let phrase = try await a.bootstrap(server)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            let mail = try await a.vault.save(login("Mail", password: "mail-pw"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            try await c.enroll(through: a, server: server)

            // What device B walks away with: its envelope, and so the old vault key, plus everything it synced.
            let bIdentity = try #require(try await b.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try #require(bIdentity.envelope), reason: "test")
            let before = try await serverRecords(server, as: a)
            #expect(before.filter { !$0.deleted }.allSatisfy { open($0, with: oldVK) != nil }, "sanity: the old key opens the pre-revoke ciphertext")

            try await a.vault.revoke(deviceID: bIdentity.deviceID)

            // Cut off at once.
            await #expect(throws: SyncError.notAuthorized) { try await b.vault.sync() }
            await #expect(throws: SyncError.notAuthorized) { try await b.vault.completeEnrollment() }   // its server-side envelope is gone too
            #expect(try await a.vault.devices().first { $0.id == bIdentity.deviceID }?.isRevoked == true)

            // Everything now on the server (rotated and untouched items alike) is closed to the old key,
            // and so is everything written afterwards.
            var edit = try await a.vault.item(id: bank.id); edit.password = "bank-pw-2"
            try await a.vault.save(edit)
            let fresh = try await a.vault.save(login("Created after revoke", password: "new-pw"))
            try await a.vault.sync()
            let after = try await serverRecords(server, as: a)
            #expect(after.filter { !$0.deleted }.count == 4)   // three items and the manifest
            #expect(after.allSatisfy { open($0, with: oldVK) == nil }, "the revoked device's key opens nothing the server holds now")
            // Item payloads and revisions are not rewritten by a rotation: Mail only had its key re-wrapped.
            let mailBefore = try #require(before.first { $0.id == mail.id }), mailAfter = try #require(after.first { $0.id == mail.id })
            #expect(mailAfter.rev == mailBefore.rev)
            #expect(mailAfter.blob.dropFirst(ItemSealer.wrappedKeyLength) == mailBefore.blob.dropFirst(ItemSealer.wrappedKeyLength))
            #expect(mailAfter.blob.prefix(ItemSealer.wrappedKeyLength) != mailBefore.blob.prefix(ItemSealer.wrappedKeyLength))
            // (What B already copied stays readable to B: that data left the vault before the revoke.)
            #expect(before.filter { !$0.deleted }.allSatisfy { open($0, with: oldVK) != nil })

            // The remaining devices carry on. C learns of the rotation on its next sync, locks, and unlocks into the new key.
            #expect(try await a.vault.revealPassword(id: mail.id) == "mail-pw")
            #expect(await c.vault.isUnlocked)
            let report = try await c.vault.sync()
            #expect(report.rotationAdopted)
            #expect(await !c.vault.isUnlocked, "a device holding a rotated-away key locks itself")
            await #expect(throws: VaultError.locked) { _ = try await c.vault.items() }
            try await c.vault.unlock()
            let onC = try await c.vault.items()
            #expect(onC.undecryptable.isEmpty)
            #expect(onC.items.map(\.title).sorted() == ["Bank", "Created after revoke", "Mail"])
            #expect(try await c.vault.revealPassword(id: bank.id) == "bank-pw-2")
            var fromC = try await c.vault.item(id: fresh.id); fromC.password = "edited-on-c"
            try await c.vault.save(fromC)
            try await c.vault.sync()
            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: fresh.id) == "edited-on-c")

            // The same 24 words still recover everything, including what was written after the rotation.
            let fresh2 = try Device("reinstall")
            try await fresh2.vault.recover(server: server.url, phrase: phrase, deviceName: "reinstall", boxID: try server.onlyBoxID())
            try await fresh2.vault.sync()
            let recovered = try await fresh2.vault.items()
            #expect(recovered.undecryptable.isEmpty)
            #expect(try await fresh2.vault.revealPassword(id: fresh.id) == "edited-on-c")
            #expect(recovered.items.count == 3)

            // And a backup taken after the rotation restores onto a new server with the same phrase.
            let backup = FileManager.default.temporaryDirectory.appendingPathComponent("rot-\(UUID().uuidString).bisel-backup")
            defer { try? FileManager.default.removeItem(at: backup) }
            try await a.vault.exportBackup(to: backup)
            try await TestServer.with { other in
                let restored = try Device("restored")
                try await restored.vault.importBackup(from: backup, phrase: phrase, server: other.url,
                                                      bootstrapToken: TestServer.bootstrapToken, deviceName: "restored")
                #expect(try await restored.vault.revealPassword(id: bank.id) == "bank-pw-2")
            }
        }
    }

    @Test("an edit made offline under the old key survives a rotation by another device")
    func offlineEditAcrossRotation() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            let router = try await a.vault.save(login("Router", password: "r1"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            // B edits and creates while "offline" (never syncs); both are sealed under the old vault key.
            var edit = try await b.vault.item(id: router.id); edit.password = "r2-from-b"
            try await b.vault.save(edit)
            let created = try await b.vault.save(login("Made on B", password: "b-pw"))
            #expect(try await b.vault.pendingChanges() == 2)

            try await a.vault.rotateVaultKey()          // meanwhile A rotates the key (no device removed)

            // B syncs: the server refuses the stale-key edits, B adopts the new envelope and locks, the edits stay pending.
            let first = try await b.vault.sync()
            #expect(first.rotationAdopted)
            #expect(first.pushed == 0)
            #expect(try await b.vault.pendingChanges() == 2)
            #expect(await !b.vault.isUnlocked)
            // Unlocking re-wraps the pending edits under the new key; the next sync pushes them.
            try await b.vault.unlock()
            let second = try await b.vault.sync()
            #expect(second.pushed == 2)
            #expect(second.conflicts.isEmpty)

            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: router.id) == "r2-from-b")
            #expect(try await a.vault.revealPassword(id: created.id) == "b-pw")
            #expect(try await a.vault.items().undecryptable.isEmpty)
            #expect(try await b.vault.items().undecryptable.isEmpty)
        }
    }

    @Test("edits racing a rotation are never lost, never undecryptable")
    func editsRaceRotation() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            for n in 0..<12 { try await a.vault.save(login("Seed \(n)", password: "s\(n)")) }
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            // B keeps editing and syncing while A rotates the key and revokes nobody.
            async let rotation = a.vault.rotateVaultKey()
            var written: [String: String] = [:]
            for n in 0..<8 {
                let item = try await b.vault.save(login("Race \(n)", password: "race-\(n)"))
                written[item.id] = "race-\(n)"
                do { try await b.vault.sync() } catch is VaultError { try await b.vault.unlock() }
                if await !b.vault.isUnlocked { try await b.vault.unlock() }
            }
            _ = try await rotation
            // Informational: how often the server turned a rotation away because B's writes landed in between.
            print("race flow: server rotate conflicts = \(server.log.components(separatedBy: "rotate_conflict").count - 1)")

            // Converge: everybody syncs (unlocking where the rotation locked them) until nothing is pending.
            for _ in 0..<4 {
                for d in [a, b] {
                    if await !d.vault.isUnlocked { try await d.vault.unlock() }
                    try await d.vault.sync()
                }
            }
            for d in [a, b] {
                if await !d.vault.isUnlocked { try await d.vault.unlock() }
                let listing = try await d.vault.items()
                #expect(listing.undecryptable.isEmpty)
                #expect(listing.items.count == 20, "\(d.name) sees all 12 seeds and all 8 racing items")
                #expect(try await d.vault.pendingChanges() == 0)
                for (id, password) in written { #expect(try await d.vault.revealPassword(id: id) == password) }
            }
        }
    }

    @Test("edits made on the rotating device while its own rotation is in flight are kept")
    func ownEditsDuringOwnRotation() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            var ids: [String] = []
            for n in 0..<12 { ids.append(try await a.vault.save(login("Seed \(n)", password: "seed-\(n)")).id) }
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            // A writer keeps editing on A the whole time; the rotation is retried until it gets past its "nothing pending"
            // check, after which every edit lands while the rotate request is in flight.
            final class Writer: @unchecked Sendable {
                private let lock = NSLock()
                private var stopped = false, written: [String: String] = [:]
                var isStopped: Bool { lock.withLock { stopped } }
                func stop() { lock.withLock { stopped = true } }
                func record(_ id: String, _ password: String) { lock.withLock { written[id] = password } }
                var edits: [String: String] { lock.withLock { written } }
            }
            let writer = Writer()
            let writing = Task {
                var n = 0
                // Capped: the server's flood limit counts every push of these edits.
                while !writer.isStopped && n < 60 {
                    var item = try await a.vault.item(id: ids[n % ids.count])
                    item.password = "edit-\(n)"
                    _ = try await a.vault.save(item)
                    writer.record(item.id, "edit-\(n)")
                    n += 1
                    try await Task.sleep(for: .milliseconds(25))
                }
            }
            var rotated = false
            for _ in 0..<100 where !rotated {
                do { _ = try await a.vault.rotateVaultKey(); rotated = true }
                catch RotationError.pendingChanges { try await Task.sleep(for: .milliseconds(300)) }
                catch RotationError.tooManyConflicts { try await Task.sleep(for: .milliseconds(300)) }
            }
            writer.stop()
            try await writing.value
            #expect(rotated)
            let edited = writer.edits

            for d in [a, b] {
                for _ in 0..<3 {
                    if await !d.vault.isUnlocked { try await d.vault.unlock() }
                    try await d.vault.sync()
                }
                let listing = try await d.vault.items()
                #expect(listing.undecryptable.isEmpty)
                #expect(try await d.vault.pendingChanges() == 0)
                for (id, password) in edited { #expect(try await d.vault.revealPassword(id: id) == password, "\(d.name) lost an edit") }
            }
        }
    }

    @Test("versions in the local trash stay restorable across a key rotation, on the rotating device and on the one that adopts it")
    func trashSurvivesRotation() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            var item = try await a.vault.save(login("Doc", password: "v1"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            item.password = "v2"
            _ = try await a.vault.save(item)
            try await a.vault.sync()
            try await b.vault.sync()                       // B keeps v1 in its trash
            var edited = try await b.vault.item(id: item.id)
            edited.password = "v3"
            _ = try await b.vault.save(edited)
            try await b.vault.sync()
            try await a.vault.sync()                       // A keeps v2 in its trash
            func passwords(_ d: Device) async throws -> [String] { try await d.vault.trash().filter { $0.itemID == item.id }.compactMap(\.item.password).sorted() }
            #expect(try await passwords(a) == ["v2"])
            #expect(try await passwords(b) == ["v1"])

            _ = try await a.vault.rotateVaultKey()
            #expect(try await passwords(a) == ["v2"], "the rotating device still reads what it kept")

            let report = try await b.vault.sync()
            #expect(report.rotationAdopted)
            try await b.vault.unlock()
            #expect(try await passwords(b) == ["v1"], "the adopting device reads it after unlocking with the new key")
        }
    }

    @Test("a record nobody can decrypt blocks rotation until it is deleted; rotating without a revoke keeps every device working")
    func rotationNeedsCleanRecords() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            // Somebody with write access plants Bank's ciphertext under a new id.
            let aID = try #require(try await a.vault.identity()?.deviceID)
            let client = a.signedClientFactory(server.url, aID)
            let blob = try #require(try await client.pull(since: 0).records.first { $0.id == bank.id }).blob
            let planted = BiselRandom.identifier()
            guard case .accepted = try await client.put(id: planted, baseRev: 0, blob: blob, epoch: 1) else { Issue.record("put refused"); return }
            try await a.vault.sync()

            do { try await a.vault.rotateVaultKey(); Issue.record("rotation should have been refused") }
            catch RotationError.undecryptableItems(let ids) { #expect(ids == [planted]) }
            #expect(try await a.vault.devices().count == 2, "nothing changed on the server")

            try await a.vault.delete(id: planted)
            try await a.vault.sync()
            try await a.vault.rotateVaultKey()
            #expect(try await a.vault.revealPassword(id: bank.id) == "bank-pw")
            #expect(try await b.vault.sync().rotationAdopted)
            try await b.vault.unlock()
            #expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw")

            // A device cannot revoke itself (it would be rotating the key out from under its own revocation).
            let bID = try #require(try await b.vault.identity()?.deviceID)
            await #expect(throws: RotationError.cannotRevokeThisDevice) { try await b.vault.revoke(deviceID: bID) }
            await #expect(throws: RotationError.deviceNotFound("nope")) { try await a.vault.revoke(deviceID: "nope") }
        }
    }
}
#endif
