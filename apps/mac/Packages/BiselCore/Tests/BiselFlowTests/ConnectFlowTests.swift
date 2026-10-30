#if BISEL_SOFTWARE_KEYS
import Foundation
import Testing
import BiselCore
import BiselTestSupport

// Accounts and device-code connect against the real local server. The dashboard (a browser with a passkey) is played by
// `TestServer.approveConnect`, which makes the same database updates the dashboard's approve route does.
@Suite("Accounts, boxes and device-code connect", .serialized)
struct ConnectFlowTests {

    @Test("a Mac with no token is approved by an account, creates its box, syncs, and the phrase recovers it with the box id")
    func connectCreatesTheBox() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.vault.bootstrapLocal(deviceName: "Ada's MacBook")
            let item = try await a.vault.save(login("Local", password: "p-local"))

            let code = try await Vault.startConnect(server: server.url, deviceName: "Ada's MacBook")
            #expect(code.userCode.count == 9 && code.userCode.contains("-"))
            #expect(code.verificationURL.absoluteString.hasSuffix("/connect?code=\(code.userCode)"))
            #expect(code.expiresIn == 600 && code.interval == 3)
            #expect(try await Vault.pollConnect(server: server.url, deviceCode: code.deviceCode) == .pending)
            #expect(try await Vault.pollConnect(server: server.url, deviceCode: String(repeating: "A", count: 43)) == .expired, "a guess looks like a timeout")

            // Not approved yet: the secret redeems nothing.
            await #expect(throws: SyncError.notAuthorized) {
                try await a.vault.connectServer(server.url, credential: .connect(deviceCode: code.deviceCode))
            }
            #expect(try await a.vault.identity()?.serverURL == nil)

            try server.approveConnect(userCode: code.userCode, account: "acct_ada")
            #expect(try await Vault.pollConnect(server: server.url, deviceCode: code.deviceCode) == .approved(accountHasBox: false))

            try await a.vault.connectServer(server.url, credential: .connect(deviceCode: code.deviceCode))
            let identity = try #require(try await a.vault.identity())
            #expect(identity.serverURL == server.url)
            #expect(identity.boxID == (try server.onlyBoxID()), "the box id from bootstrap is kept")
            #expect(try server.value("SELECT owner_id FROM boxes") == "acct_ada", "the account owns the new box")
            #expect(try await Vault.pollConnect(server: server.url, deviceCode: code.deviceCode) == .consumed(boxID: nil))
            #expect(try await a.vault.sync().pushed >= 1)

            // A device code is single use.
            let replay = try Device("replay")
            await #expect(throws: SyncError.notAuthorized) {
                _ = try await replay.vault.bootstrap(server: server.url, credential: .connect(deviceCode: code.deviceCode), deviceName: "replay")
            }

            // A fresh Mac restores with the phrase and the box id.
            let fresh = try Device("fresh")
            try await fresh.vault.recover(server: server.url, phrase: phrase, deviceName: "fresh", boxID: identity.boxID)
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: item.id) == "p-local")
            #expect(try await fresh.vault.identity()?.boxID == identity.boxID)
        }
    }

    @Test("an account that already has a box is told so, a denied or expired code ends the wait, and nothing is created")
    func refusals() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            _ = try await a.vault.bootstrapLocal(deviceName: "a")
            let first = try await Vault.startConnect(server: server.url, deviceName: "a")
            try server.approveConnect(userCode: first.userCode, account: "acct_ada")
            try await a.vault.connectServer(server.url, credential: .connect(deviceCode: first.deviceCode))

            // Ada's second Mac: approved, but her account already owns a box.
            let b = try Device("b")
            _ = try await b.vault.bootstrapLocal(deviceName: "b")
            let second = try await Vault.startConnect(server: server.url, deviceName: "b")
            try server.approveConnect(userCode: second.userCode, account: "acct_ada")
            #expect(try await Vault.pollConnect(server: server.url, deviceCode: second.deviceCode) == .approved(accountHasBox: true))
            await #expect(throws: ConnectError.accountHasBox) {
                try await b.vault.connectServer(server.url, credential: .connect(deviceCode: second.deviceCode))
            }
            #expect(try await b.vault.identity()?.serverURL == nil, "still local-only")
            #expect(try server.value("SELECT COUNT(*) FROM boxes") == "1")

            let denied = try await Vault.startConnect(server: server.url, deviceName: "c")
            try server.denyConnect(userCode: denied.userCode, account: "acct_eve")
            #expect(try await Vault.pollConnect(server: server.url, deviceCode: denied.deviceCode) == .denied)
            await #expect(throws: SyncError.notAuthorized) {
                try await b.vault.connectServer(server.url, credential: .connect(deviceCode: denied.deviceCode))
            }

            let late = try await Vault.startConnect(server: server.url, deviceName: "d")
            try server.expireConnect(userCode: late.userCode)
            #expect(try await Vault.pollConnect(server: server.url, deviceCode: late.deviceCode) == .expired)
            #expect(try server.value("SELECT COUNT(*) FROM boxes") == "1")
        }
    }

    @Test("an existing box is linked to an account with a claim code, once; an account with a box cannot claim another")
    func claimLinksTheBox() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            try await a.bootstrap(server)   // the operator's token: a box nobody owns
            #expect(try server.value("SELECT owner_id FROM boxes") == nil)
            try await a.vault.unlock()

            let code = try await a.vault.claimBox()
            #expect(try await a.vault.pollClaim(code) == .pending)
            try server.approveConnect(userCode: code.userCode, account: "acct_ada")
            #expect(try await a.vault.pollClaim(code) == .consumed(boxID: nil))
            #expect(try server.value("SELECT owner_id FROM boxes") == "acct_ada")
            _ = try await a.vault.sync()   // sync does not depend on the account

            await #expect(throws: ConnectError.alreadyLinked) { _ = try await a.vault.claimBox() }

            // Ada signs in again for another, unowned box: her account owns one already, so the claim is denied.
            let b = try Device("b")
            try await b.bootstrap(server)
            try await b.vault.unlock()
            let second = try await b.vault.claimBox()
            try server.approveConnect(userCode: second.userCode, account: "acct_ada")
            #expect(try await b.vault.pollClaim(second) == .denied)
            #expect(try server.value("SELECT COUNT(*) FROM boxes WHERE owner_id IS NULL") == "1")

            // A locked vault cannot claim: it needs the admin signature.
            let relaunched = try b.relaunched()
            await #expect(throws: VaultError.locked) { _ = try await relaunched.claimBox() }
        }
    }

    @Test("recovery names its box: with the right id it works, without or with another box's id it gets the bare 404")
    func recoveryNeedsTheBoxID() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            let phraseA = try await a.bootstrap(server)
            let phraseB = try await b.bootstrap(server)
            let boxA = try #require(try await a.vault.identity()?.boxID)
            let boxB = try #require(try await b.vault.identity()?.boxID)
            #expect(boxA != boxB)
            let item = try await a.vault.save(login("A's", password: "pa"))
            try await a.vault.sync()
            _ = phraseB

            let nobody = try Device("nobody")
            await #expect(throws: SyncError.notAuthorized, "no box id: the pre-accounts box, which this server never had") {
                try await nobody.vault.recover(server: server.url, phrase: phraseA, deviceName: "x")
            }
            await #expect(throws: SyncError.notAuthorized, "another box's id does not open this phrase") {
                try await nobody.vault.recover(server: server.url, phrase: phraseA, deviceName: "x", boxID: boxB)
            }
            await #expect(throws: SyncError.notAuthorized) {
                try await nobody.vault.recover(server: server.url, phrase: phraseA, deviceName: "x", boxID: "no_such_box_000000")
            }
            #expect(try await nobody.vault.identity() == nil)

            let fresh = try Device("fresh")
            try await fresh.vault.recover(server: server.url, phrase: phraseA, deviceName: "fresh", boxID: boxA)
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: item.id) == "pa")
            #expect(try await fresh.vault.identity()?.boxID == boxA)
            #expect(try await fresh.vault.items().items.map(\.title) == ["A's"], "box B's items never show up")
        }
    }

    @Test("an identity from before accounts (no box id) still decodes, syncs and enrolls another device")
    func identityWithoutBoxID() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            try await a.bootstrap(server)
            var id = try #require(try await a.vault.identity())
            #expect(id.boxID != nil)

            // What an older app wrote: the same JSON without the field.
            var json = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(id)) as? [String: Any])
            json.removeValue(forKey: "boxID")
            let old = try JSONDecoder().decode(LocalIdentity.self, from: JSONSerialization.data(withJSONObject: json))
            #expect(old.boxID == nil)
            #expect(old.deviceID == id.deviceID && old.serverURL == id.serverURL)

            // A device request carries no box header whatever the identity holds: it syncs the same without one.
            id.boxID = nil
            let store = try LocalStore(location: a.location, secrets: FileSecretStore(directory: a.location.directory))
            try store.setIdentity(id)
            #expect(try await a.vault.identity()?.boxID == nil)
            let saved = try await a.vault.save(login("Old", password: "p-old"))
            #expect(try await a.vault.sync().pushed >= 1)

            let b = try Device("b")
            try await b.enroll(through: a, server: server)
            #expect(try await b.vault.revealPassword(id: saved.id) == "p-old")
        }
    }
}
#endif
