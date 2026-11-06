#if BISEL_SOFTWARE_KEYS
import CryptoKit
import Foundation
import Synchronization
import Testing
import BiselCore
import BiselLaneContract

// The Chrome link's guarantees (docs/SPEC.md §8, "Chrome extension"), against the real store and crypto. Touch ID is the fake host's answer.
@Suite("Chrome save link", .serialized)
struct BrowserSaveFlowTests {

    private actor FakeHost: BrowserSaveHost {
        var answer: AgentError?
        var reasons: [String] = []
        var saves = 0
        func set(answer: AgentError?) { self.answer = answer }
        func authenticate(_ reason: String) async throws {
            reasons.append(reason)
            if let answer { throw answer }
        }
        func loginSaved() async { saves += 1 }
    }

    private static let site = "https://github.com"
    private static let username = "someone@example.com"
    private static let password = "correct-horse-battery"
    private static let login = BrowserLogin(site: site, username: username)

    private func box(holding: Bool = true) async throws -> (Device, FakeHost, BrowserSaveBroker) {
        let device = try Device("chrome")
        _ = try await device.vault.bootstrapLocal(deviceName: "chrome")
        if holding {
            var draft = ItemDraft(type: .login)
            draft.title = "GitHub"
            draft.urls = [Self.site]
            draft.username = Self.username
            draft.password = Self.password
            draft.notes = "private note"
            try await device.vault.createItem(draft)
        }
        let host = FakeHost()
        return (device, host, BrowserSaveBroker(vault: device.vault, host: host, isPublicSuffix: { ["github.io", "com"].contains($0) }))
    }

    private func check(_ password: String, login: BrowserLogin = login) -> BrowserRequest {
        let salt = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        return .saveCheck(login, salt: salt, digest: Data(SHA256.hash(data: salt + Data(password.utf8))))
    }

    private func save(_ password: String, replace: Bool = false, login: BrowserLogin = login) -> BrowserRequest {
        .save(login, password: AgentSecret(password), replace: replace)
    }

    @Test("a save without a passed Touch ID writes nothing")
    func nothingSavedWithoutTouchID() async throws {
        let (device, host, broker) = try await box(holding: false)
        await host.set(answer: AgentError(.denied))
        #expect(await broker.handle(save("new-password")) == .refused(.denied))
        await host.set(answer: AgentError(.timeout))
        #expect(await broker.handle(save("new-password")) == .refused(.timeout))
        #expect(try await device.vault.items().items.isEmpty)
        #expect(await host.saves == 0)

        await host.set(answer: nil)
        #expect(await broker.handle(save("new-password")) == .saved, "control: a passed one does save")
        let item = try #require(try await device.vault.items().items.first)
        #expect(item.password == "new-password" && item.username == Self.username && item.urls == [Self.site])
        #expect(await host.saves == 1, "the app reloads and syncs")
        #expect(await host.reasons.last?.contains("github.com") == true, "the prompt names the site")
    }

    @Test("a different password never replaces a stored one unless the person chose Update, and the old one stays in history")
    func existingPasswordNeverLost() async throws {
        let (device, host, broker) = try await box()
        #expect(await broker.handle(save("changed")) == .exists)
        #expect(try await device.vault.items().items.first?.password == Self.password, "a plain Save changed nothing")
        #expect(await host.saves == 0)

        #expect(await broker.handle(save(Self.password, replace: true)) == .unchanged)
        await host.set(answer: AgentError(.denied))
        #expect(await broker.handle(save("changed", replace: true)) == .refused(.denied))
        #expect(try await device.vault.items().items.first?.password == Self.password)

        await host.set(answer: nil)
        #expect(await broker.handle(save("changed", replace: true)) == .saved)
        let items = try await device.vault.items().items
        #expect(items.count == 1 && items[0].password == "changed" && items[0].notes == "private note", "same item, only the password moved")
        #expect(try await device.vault.trash().contains { $0.itemID == items[0].id && $0.item.password == Self.password })
    }

    @Test("a site that is not an https origin of its own is refused before any prompt")
    func wrongSiteRefused() async throws {
        let (device, host, broker) = try await box(holding: false)
        for site in ["http://github.com", "https://github.com/login", "https://user@github.com", "chrome-extension://abc", "github.com", "", "https://github.io"] {
            let login = BrowserLogin(site: site, username: Self.username)
            #expect(await broker.handle(save("x", login: login)) == .refused(.wrongSite), "\(site)")
            #expect(await broker.handle(check("x", login: login)) == .refused(.wrongSite), "\(site)")
        }
        let spoofed = BrowserLogin(site: Self.site, username: "a\u{202E}moc.live")
        #expect(await broker.handle(save("x", login: spoofed)) == .refused(.badRequest), "a username that would misread in the prompt")
        #expect(await host.reasons.isEmpty)
        #expect(try await device.vault.items().items.isEmpty)

        let origin = BrowserLink.extensionOrigin
        let wrong = BrowserRelay.answer(Data(), callerOrigin: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/", socketPath: "/nonexistent", serverRequirement: nil)
        #expect(try JSONDecoder().decode(BrowserReply.self, from: wrong).answer == .refused(.wrongSite), "the host stops any other extension")
        let none = BrowserRelay.answer(Data(), callerOrigin: nil, socketPath: "/nonexistent", serverRequirement: nil)
        #expect(try JSONDecoder().decode(BrowserReply.self, from: none).answer == .refused(.wrongSite))
        let right = BrowserRelay.answer(Data("{}".utf8), callerOrigin: origin, socketPath: "/nonexistent", serverRequirement: nil)
        #expect(try JSONDecoder().decode(BrowserReply.self, from: right).answer == .refused(.badRequest), "control: this caller gets as far as the message")
        let manifest = try JSONSerialization.jsonObject(with: BrowserLink.manifest(hostPath: "/Applications/Bisel.app/Contents/Helpers/bisel-browser-host")) as? [String: Any]
        #expect(manifest?["allowed_origins"] as? [String] == [origin], "Chrome is told the same single origin")
    }

    @Test("the app talks to the signed host only, and the host to the signed app only")
    func unsignedPeerRefused() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString.prefix(8).description)
        let strict = directory.appendingPathComponent("s").path, open = directory.appendingPathComponent("o").path
        let reached = Mutex(false)
        let handler: SocketListener<BrowserEnvelope, BrowserReply>.Handler = { envelope in
            reached.withLock { $0 = true }
            return BrowserReply(id: envelope.id, answer: .saved)
        }
        try SocketListener(path: strict, clientRequirement: AgentPeer.browserHostRequirement, handler: handler).start()
        try SocketListener(path: open, clientRequirement: nil, handler: handler).start()
        let message = BrowserEnvelope(id: "1", request: save("x"))

        func exchange(_ path: String, _ requirement: String?) throws(AgentError) -> BrowserReply {
            try AgentSocket.exchange(message, path: path, serverRequirement: requirement)
        }
        #expect(throws: AgentError(.failed)) { try exchange(strict, nil) }
        #expect(!reached.withLock { $0 }, "this unsigned test process got no byte through")
        #expect(throws: AgentError(.untrustedApp)) { try exchange(open, AgentPeer.appRequirement) }
        #expect(!reached.withLock { $0 }, "the password never went to an unsigned app")
        #expect(try exchange(open, nil).answer == .saved, "control: the same exchange works once the check is off")
    }

    @Test("nothing from the box comes back, a wrong guess is rationed, and there is no request that reads")
    func noReadPath() async throws {
        let (device, host, broker) = try await box()

        // The answers: fixed words. Whatever is asked, no stored title, password, note or id can travel in one.
        var seen: [BrowserAnswer] = []
        seen.append(await broker.handle(check(Self.password)))
        seen.append(await broker.handle(check("wrong")))
        seen.append(await broker.handle(save(Self.password)))
        seen.append(await broker.handle(save("other")))
        #expect(seen == [.same, .differs, .unchanged, .exists])
        let id = try #require(try await device.vault.items().items.first?.id)
        for answer in seen {
            let wire = String(decoding: try JSONEncoder().encode(BrowserReply(id: "1", answer: answer)), as: UTF8.self)
            for secret in [Self.password, "private note", "GitHub", id] { #expect(!wire.contains(secret)) }
        }

        // Guessing: a spent allowance hides even the right password, and changing the case or the subdomain does not refill it.
        #expect(await broker.handle(check("wrong")) == .differs)
        #expect(await broker.handle(check("wrong", login: BrowserLogin(site: "https://www.GitHub.com", username: Self.username.uppercased()))) == .differs)
        #expect(await broker.handle(check("wrong")) == .unknown)
        #expect(await broker.handle(check(Self.password)) == .unknown)

        // A person with the right password is never rationed.
        let (_, _, fresh) = try await box()
        for _ in 0..<30 { #expect(await fresh.handle(check(Self.password)) == .same) }

        // A locked box says nothing and asks for nothing.
        let reasons = await host.reasons.count
        await device.vault.lock()
        #expect(await broker.handle(check(Self.password)) == .unknown)
        #expect(await host.reasons.count == reasons)

        // The wire has two verbs. Anything shaped like a read does not decode, so it never reaches the app.
        for type in ["get", "list", "fill", "fill.get", "search", "save.read"] {
            let message = Data(#"{"v":1,"id":"1","type":"\#(type)","site":"https://github.com","username":"a"}"#.utf8)
            #expect(throws: DecodingError.self) { try JSONDecoder().decode(BrowserEnvelope.self, from: message) }
        }
    }
}
#endif
