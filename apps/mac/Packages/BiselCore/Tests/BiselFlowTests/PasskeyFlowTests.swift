#if BISEL_SOFTWARE_KEYS
import Foundation
import CryptoKit
import Security
import Testing
import BiselCore
import BiselTestSupport
import BiselLaneContract

// The passkey engine, read the way a website reads it: the parsing and the signature check below share no code with the engine.
@Suite("Passkeys", .serialized)
struct PasskeyFlowTests {

    private static let rp = "example.com"
    private static let hash = Data(SHA256.hash(data: Data("clientDataJSON".utf8)))
    private static let request = PasskeyRegistrationRequest(rpID: rp, userHandle: Data([1, 2, 3, 4]), userName: "someone@example.com", userDisplayName: "Someone")

    /// What a site stores after a registration.
    private struct Registered {
        var flags: UInt8
        var signCount: UInt32
        var credentialID: Data
        var publicKey: SecKey
    }

    /// Just enough CBOR to read an attestation object: unsigned and negative integers, bytes, text, maps.
    private struct Reader {
        var bytes: [UInt8]
        var at = 0
        init(_ data: Data) { bytes = Array(data) }

        private mutating func argument(_ info: UInt8) throws -> Int {
            if info < 24 { return Int(info) }
            let width = try #require([24: 1, 25: 2, 26: 4][info])
            var value = 0
            for _ in 0..<width { value = value << 8 | Int(bytes[at]); at += 1 }
            return value
        }

        mutating func next() throws -> AnyHashable {
            let first = bytes[at]; at += 1
            let length = try argument(first & 0x1f)
            switch first >> 5 {
            case 0: return length
            case 1: return -1 - length
            case 2: defer { at += length }; return Data(bytes[at..<at + length])
            case 3: defer { at += length }; return String(decoding: bytes[at..<at + length], as: UTF8.self)
            case 5:
                var map: [AnyHashable: AnyHashable] = [:]
                for _ in 0..<length { let k = try next(); map[k] = try next() }
                return map
            default: Issue.record("unexpected CBOR major type"); return 0
            }
        }
    }

    private func site(_ attestationObject: Data, rpID: String = rp) throws -> Registered {
        var object = Reader(attestationObject)
        let top = try #require(try object.next() as? [AnyHashable: AnyHashable])
        #expect(object.at == attestationObject.count, "nothing after the map")
        #expect(top["fmt"] == AnyHashable("none"))
        #expect((top["attStmt"] as? [AnyHashable: AnyHashable])?.isEmpty == true)
        let data = Array(try #require(top["authData"] as? Data))

        #expect(Data(data[0..<32]) == Data(SHA256.hash(data: Data(rpID.utf8))))
        let flags = data[32]
        #expect(flags & 0x40 != 0, "attested credential data present")
        let signCount = data[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        #expect(Data(data[37..<53]) == Data(count: 16), "AAGUID")
        let idLength = Int(data[53]) << 8 | Int(data[54])
        let credentialID = Data(data[55..<55 + idLength])

        var cose = Reader(Data(data[(55 + idLength)...]))
        let key = try #require(try cose.next() as? [AnyHashable: AnyHashable])
        #expect(55 + idLength + cose.at == data.count, "the key is the last thing in authenticator data")
        #expect(key[1] == AnyHashable(2) && key[3] == AnyHashable(-7) && key[-1] == AnyHashable(1), "EC2, ES256, P-256")
        let x = try #require(key[-2] as? Data), y = try #require(key[-3] as? Data)
        #expect(x.count == 32 && y.count == 32)

        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
        let publicKey = try #require(SecKeyCreateWithData(Data([4]) + x + y as CFData, attributes, nil))
        return Registered(flags: flags, signCount: signCount, credentialID: credentialID, publicKey: publicKey)
    }

    private func verifies(_ a: PasskeyAssertion, _ key: SecKey, hash: Data = hash) -> Bool {
        SecKeyVerifySignature(key, .ecdsaSignatureMessageX962SHA256, a.authenticatorData + hash as CFData, a.signature as CFData, nil)
    }

    private func privateKeyText(_ item: Item) throws -> String {
        guard case .object(let o)? = item.passkey, case .string(let key)? = o["privateKey"] else { throw PasskeyError.noCredential }
        return key
    }

    private func localBox(_ name: String = "a") async throws -> Device {
        let device = try Device(name)
        _ = try await device.vault.bootstrapLocal(deviceName: name)
        return device
    }

    @Test("a site would reject our passkey: an assertion must verify against the key from registration, and only for what was signed")
    func assertionVerifiesAgainstRegistration() async throws {
        let a = try await localBox()
        let made = try await a.vault.registerPasskey(Self.request)
        let site = try site(made.attestationObject)
        #expect(site.credentialID == made.credentialID && made.credentialID.count == 32)
        #expect(site.flags & 0x1f == 0x0d, "present, verified, eligible; not backed up while the box is on this Mac only")
        #expect(site.signCount == 0)
        #expect(a.gate.calls.suffix(1) == ["Create a passkey for example.com"])

        let pending = try await a.vault.pendingChanges()
        let stored = try await a.vault.items().items
        let assertion = try await a.vault.assertPasskey(rpID: Self.rp, credentialID: made.credentialID, clientDataHash: Self.hash)
        #expect(a.gate.calls.suffix(1) == ["Sign in to example.com"], "each signature takes a fresh check")
        #expect(verifies(assertion, site.publicKey))
        #expect(!verifies(assertion, site.publicKey, hash: Data(SHA256.hash(data: Data("other".utf8)))))
        #expect(assertion.userHandle == Self.request.userHandle && assertion.credentialID == made.credentialID)

        let data = Array(assertion.authenticatorData)
        #expect(data.count == 37, "no attested credential data on an assertion")
        #expect(Data(data[0..<32]) == Data(SHA256.hash(data: Data(Self.rp.utf8))))
        #expect(data[32] == 0x0d)
        #expect(data[33..<37].allSatisfy { $0 == 0 }, "a shared key keeps no counter")
        #expect(try await a.vault.pendingChanges() == pending, "signing writes nothing to the box, so it cannot make sync conflicts")
        #expect(try await a.vault.items().items == stored)

        a.gate.deny(true)
        await #expect(throws: (any Error).self) { _ = try await a.vault.assertPasskey(rpID: Self.rp, credentialID: made.credentialID, clientDataHash: Self.hash) }
        a.gate.deny(false)
        await a.vault.lock()
        await #expect(throws: VaultError.locked) { _ = try await a.vault.assertPasskey(rpID: Self.rp, credentialID: made.credentialID, clientDataHash: Self.hash) }
    }

    @Test("a passkey leaks to another site: the RP ID must match exactly, and the allow list is honoured")
    func wrongRelyingPartyGetsNothing() async throws {
        let a = try await localBox()
        let first = try await a.vault.registerPasskey(Self.request)
        var other = Self.request
        other.userHandle = Data([9])
        let second = try await a.vault.registerPasskey(other)

        for rp in ["evil.com", "sub.example.com", "com", "example.com.evil.com", "notexample.com", "www.example.com", ""] {
            #expect(try await a.vault.passkeys(rpID: rp).isEmpty, "offered to \(rp)")
            await #expect(throws: PasskeyError.noCredential) { _ = try await a.vault.assertPasskey(rpID: rp, credentialID: first.credentialID, clientDataHash: Self.hash) }
        }
        #expect(try await a.vault.passkeys(rpID: Self.rp).count == 2, "an empty allow list is a discoverable sign-in")
        #expect(try await a.vault.passkeys(rpID: Self.rp, allowList: [second.credentialID]).map(\.credentialID) == [second.credentialID])
        #expect(try await a.vault.passkeys(rpID: Self.rp, allowList: [Data(repeating: 7, count: 32)]).isEmpty)
        await #expect(throws: PasskeyError.noCredential) {
            _ = try await a.vault.assertPasskey(rpID: Self.rp, credentialID: Data(repeating: 7, count: 32), clientDataHash: Self.hash)
        }
        await #expect(throws: PasskeyError.invalidRequest) { _ = try await a.vault.assertPasskey(rpID: Self.rp, credentialID: first.credentialID, clientDataHash: Data(count: 31)) }

        // Moving an item's address does not move its passkey: the RP ID is inside the credential, not in anything a draft edits.
        let id = try #require(try await a.vault.passkeys(rpID: Self.rp, allowList: [first.credentialID]).first).itemID
        var draft = ItemDraft(editing: try await a.vault.item(id: id))
        draft.urls = ["https://evil.com"]
        draft.title = "Renamed"
        try await a.vault.updateItem(draft)
        #expect(try await a.vault.passkeys(rpID: "evil.com").isEmpty)
        let assertion = try await a.vault.assertPasskey(rpID: Self.rp, credentialID: first.credentialID, clientDataHash: Self.hash)
        #expect(verifies(assertion, try site(first.attestationObject).publicKey), "and an edit leaves the key working")

        // Drafts cannot make one, or copy one.
        #expect(ItemValidator.issues(for: ItemDraft(type: .passkey)).contains { $0.code == .unsupportedType })
        #expect(ItemValidator.issues(for: ItemDraft(copying: try await a.vault.item(id: id))).contains { $0.code == .unsupportedType })
    }

    @Test("registering twice leaves two passkeys for one account, or makes one the site excluded")
    func registrationRules() async throws {
        let a = try await localBox()
        let first = try await a.vault.registerPasskey(Self.request)

        var excluded = Self.request
        excluded.excludedCredentialIDs = [first.credentialID]
        await #expect(throws: PasskeyError.excludedCredential) { _ = try await a.vault.registerPasskey(excluded) }
        var es512Only = Self.request
        es512Only.algorithms = [-36]
        await #expect(throws: PasskeyError.unsupportedAlgorithm) { _ = try await a.vault.registerPasskey(es512Only) }
        var noHandle = Self.request
        noHandle.userHandle = Data()
        await #expect(throws: PasskeyError.invalidRequest) { _ = try await a.vault.registerPasskey(noHandle) }
        #expect(try await a.vault.items().items.count == 1, "a refused registration writes nothing")

        let replaced = try await a.vault.registerPasskey(Self.request)
        #expect(try await a.vault.passkeys(rpID: Self.rp).map(\.credentialID) == [replaced.credentialID])
        #expect(try await a.vault.items().items.count == 1)
        let previous = try await a.vault.trash().map(\.item.passkeyState)
        #expect(previous.contains { if case .usable(let c)? = $0 { c.credentialID == first.credentialID } else { false } }, "the old key stays in the item's history")
    }

    @Test("a passkey loses its key on the way to another device or through a backup: it must sign there with the same key, and appear only sealed")
    func keySurvivesSyncAndBackup() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            let phrase = try await a.bootstrap(server)
            let made = try await a.vault.registerPasskey(Self.request)
            let key = try site(made.attestationObject).publicKey
            #expect(try site(made.attestationObject).flags & 0x10 != 0, "backed up: the box syncs")
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            try await b.vault.sync()

            let match = try #require(try await b.vault.passkeys(rpID: Self.rp).first)
            #expect(match.credentialID == made.credentialID && match.userName == Self.request.userName)
            #expect(verifies(try await b.vault.assertPasskey(rpID: Self.rp, credentialID: made.credentialID, clientDataHash: Self.hash), key))

            // Both devices rename it offline: the "(conflict)" copy holds the same credential, which is still offered once.
            var onA = try await a.vault.item(id: match.itemID); onA.title = "From A"
            var onB = try await b.vault.item(id: match.itemID); onB.title = "From B"
            try await a.vault.save(onA)
            try await b.vault.save(onB)
            try await a.vault.sync()
            #expect(try await b.vault.sync().conflicts.count == 1)
            #expect(try await b.vault.items().items.count == 2)
            #expect(try await b.vault.passkeys(rpID: Self.rp).map(\.credentialID) == [made.credentialID])
            #expect(verifies(try await b.vault.assertPasskey(rpID: Self.rp, credentialID: made.credentialID, clientDataHash: Self.hash), key))

            let file = FileManager.default.temporaryDirectory.appendingPathComponent("passkey-\(UUID().uuidString).bisel-backup")
            defer { try? FileManager.default.removeItem(at: file) }
            try await a.vault.exportBackup(to: file)
            let secret = try privateKeyText(try await a.vault.item(id: match.itemID))
            let bytes = try Data(contentsOf: file)
            #expect(bytes.range(of: Data(secret.utf8)) == nil, "no key in the file")

            let fresh = try Device("fresh")
            try await fresh.vault.restoreBackup(from: file, phrase: phrase, deviceName: "fresh")
            #expect(verifies(try await fresh.vault.assertPasskey(rpID: Self.rp, credentialID: made.credentialID, clientDataHash: Self.hash), key))
        }
    }

    @Test("an imported blob is rewritten, lost or signed with: anything the engine cannot use stays as it was and is reported")
    func unusableBlobsSurviveUnchanged() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            let made = try await a.vault.registerPasskey(Self.request)
            let stored = try await a.vault.item(id: try #require(try await a.vault.passkeys(rpID: Self.rp).first).itemID)
            guard case .object(let good)? = stored.passkey else { Issue.record("no slot"); return }
            func ours(with key: String, _ value: JSONValue) -> JSONValue { var o = good; o[key] = value; return .object(o) }

            // Shapes older builds stored, and our own format from a later version or with a part that cannot work.
            let imported: JSONValue = .object(["credentialId": .string("FAKECRED123"), "rpId": .string(Self.rp), "userHandle": .string("FAKEHANDLE"),
                                               "key": .string("not-for-us"), "counter": .number(7), "extra": .array([.null, .bool(true), .object(["a": .number(1.5)])])])
            let blobs: [(ItemType, JSONValue, PasskeyUnusableReason)] = [
                (.passkey, imported, .imported),
                (.login, imported, .imported),
                (.passkey, .string("blob"), .imported),
                (.passkey, ours(with: "version", .number(2)), .newerFormat),
                (.passkey, ours(with: "privateKey", .string("AAAA")), .damaged),
                (.passkey, ours(with: "algorithm", .number(-8)), .damaged),
                (.login, .object(good), .damaged),
            ]
            var saved: [(Item, PasskeyUnusableReason)] = []
            for (i, blob) in blobs.enumerated() {
                saved.append((try await a.vault.save(Item(type: blob.0, title: "Old \(i)", passkey: blob.1)), blob.2))
            }

            // The payload an older build wrote opens and is written back with the same slot.
            let payload = Data(#"{"createdAt":"2026-01-02T03:04:05Z","fields":[],"passkey":{"counter":7,"credentialId":"abc"},"tags":[],"title":"Stored","type":"passkey","updatedAt":"2026-01-02T03:04:05Z","urls":[],"v":1}"#.utf8)
            #expect(try ItemCodec.encode(try ItemCodec.decode(payload, id: "x")) == payload)

            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            try await b.vault.sync()
            for (item, reason) in saved {
                var draft = ItemDraft(editing: try await b.vault.item(id: item.id))
                draft.notes = "edited"
                guard case .saved(let edited, _) = try await b.vault.updateItem(draft) else { Issue.record("not saved"); return }
                #expect(edited.passkey == item.passkey, "\(item.title)")
                #expect(edited.passkeyState == .unusable(reason), "\(item.title)")
            }
            try await b.vault.sync()
            try await a.vault.sync()
            for (item, _) in saved { #expect(try await a.vault.item(id: item.id).passkey == item.passkey) }

            let reported = try await b.vault.unusablePasskeys()
            #expect(Set(reported.map(\.itemID)) == Set(saved.map(\.0.id)))
            #expect(try await b.vault.passkeys(rpID: Self.rp).map(\.credentialID) == [made.credentialID], "only the one that can sign is offered")
        }
    }

    @Test("a private key reaches an agent or a log")
    func keyStaysOutOfAgentsAndLogs() async throws {
        struct Host: AgentHost {
            func isAllowed() async -> Bool { true }
            func isUnlocked() async -> Bool { true }
            func approve(_ reason: String) async throws {}
            func fill(_ item: Item, login: Bool, submit: Bool) async throws {}
            func didChange(_ reason: String) async {}
        }
        let a = try await localBox()
        let made = try await a.vault.registerPasskey(Self.request)
        let id = try #require(try await a.vault.passkeys(rpID: Self.rp).first).itemID
        let item = try await a.vault.item(id: id)
        let secret = try privateKeyText(item)
        let broker = AgentBroker(vault: a.vault, host: Host())

        guard case .items(let found) = await broker.handle(.search("example")) else { Issue.record("no answer"); return }
        #expect(found.isEmpty, "agents do not see passkey items")
        for field in [AgentField.password, .username, .totp, .custom("privateKey"), .custom("passkey")] {
            let result = await broker.handle(.run(refs: [AgentSecretRef(item: id, field: field)], command: ["/usr/bin/true"]))
            if case .secrets(let values) = result {
                #expect(field == .username && !values.contains { $0.bytes.range(of: Data(secret.utf8)) != nil }, "only the user name is an item field")
            }
        }

        var dumped = ""
        dump(made, to: &dumped); dump(item, to: &dumped); dump(made.credential, to: &dumped)
        let texts = [dumped, "\(made)", "\(made.credential)", String(reflecting: made.credential), "\(item)", "\(item.passkeyState as Any)"]
        let raw = try #require(Data(base64URLEncoded: secret))
        for text in texts {
            #expect(!text.contains(secret) && !text.contains(raw.hexEncoded()) && !text.contains(raw.base64EncodedString()))
        }
    }
}
#endif
