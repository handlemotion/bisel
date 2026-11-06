#if BISEL_SOFTWARE_KEYS
import Foundation
import Synchronization
import Testing
import BiselCore
import BiselLaneContract

// The agent CLI's guarantees (docs/AGENT-CLI.md), against the real store and crypto. Touch ID is the fake host's answer.
@Suite("Agent access", .serialized)
struct AgentFlowTests {

    private actor FakeHost: AgentHost {
        var allowed = true
        var answer: AgentError?
        var reasons: [String] = []
        func set(allowed: Bool) { self.allowed = allowed }
        func set(answer: AgentError?) { self.answer = answer }
        func isAllowed() async -> Bool { allowed }
        func isUnlocked() async -> Bool { true }
        func approve(_ reason: String) async throws {
            reasons.append(reason)
            if let answer { throw answer }
        }
        func fill(_ item: Item, login: Bool, submit: Bool) async throws {}
        func didChange(_ reason: String) async {}
    }

    private static let password = "correct-horse-battery"

    private func box() async throws -> (Device, FakeHost, AgentBroker, Item) {
        let device = try Device("agent")
        _ = try await device.vault.bootstrapLocal(deviceName: "agent")
        var draft = ItemDraft(type: .login)
        draft.title = "GitHub"
        draft.urls = ["https://github.com"]
        draft.username = "someone@example.com"
        draft.password = Self.password
        draft.notes = "private note"
        let item = try await device.vault.createItem(draft)
        let host = FakeHost()
        return (device, host, AgentBroker(vault: device.vault, host: host), item)
    }

    private func secrets(_ result: AgentResult) -> [AgentSecret]? {
        if case .secrets(let values) = result { return values }
        return nil
    }

    private func code(_ result: AgentResult) -> AgentCode? {
        if case .refused(let code) = result { return code }
        return nil
    }

    @Test("a denied or unanswered prompt, agents off or a locked box return no secret")
    func noApprovalNoSecret() async throws {
        let (device, host, broker, item) = try await box()
        let request = AgentRequest.run(refs: [AgentSecretRef(item: item.id)], command: ["/usr/bin/true"])

        await host.set(answer: AgentError(.denied))
        #expect(code(await broker.handle(request)) == .denied)
        await host.set(answer: AgentError(.timeout))
        #expect(code(await broker.handle(request)) == .timeout)

        await host.set(answer: nil)
        #expect(secrets(await broker.handle(request))?.first?.bytes == Data(Self.password.utf8), "control: an approved run does get it")

        await host.set(allowed: false)
        #expect(code(await broker.handle(request)) == .agentsOff)
        await host.set(allowed: true)
        await device.vault.lock()
        #expect(code(await broker.handle(request)) == .locked)
    }

    @Test("a command the prompt can't show in full is refused before any prompt, and the prompt names what it gives to what")
    func promptIsTruthful() async throws {
        let (_, host, broker, item) = try await box()
        let refs = [AgentSecretRef(item: item.id)]
        for command in [["/bin/echo", "safe\u{202E}evil"], ["/bin/echo", "line\nhidden"], ["echo", "relative"], ["/bin/echo", String(repeating: "x", count: 500)]] {
            #expect(code(await broker.handle(.run(refs: refs, command: command))) == .commandRefused)
        }
        #expect(await host.reasons.isEmpty)

        _ = await broker.handle(.run(refs: refs, command: ["/bin/sh", "-c", "curl x"]))
        #expect(await host.reasons == ["give GitHub password to /bin/sh -c 'curl x'"])
    }

    @Test("search never carries a secret, username or note, and asks again after the box locks")
    func searchIsMetadataOnly() async throws {
        let (_, host, broker, item) = try await box()
        let result = await broker.handle(.search("git"))
        guard case .items(let items) = result else { Issue.record("no items"); return }
        #expect(items.map(\.id) == [item.id])
        #expect(items.first?.has == ["password"])
        let text = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
        for hidden in [Self.password, "someone@example.com", "private note"] { #expect(!text.contains(hidden)) }

        _ = await broker.handle(.search("hub"))
        #expect(await host.reasons.count == 1, "one prompt covers the window")
        await broker.resetSearchWindow()
        _ = await broker.handle(.search("hub"))
        #expect(await host.reasons.count == 2)
    }

    @Test("a denied edit or trash changes nothing, and a new address shows in the prompt")
    func writesNeedApproval() async throws {
        let (device, host, broker, item) = try await box()
        await host.set(answer: AgentError(.denied))
        #expect(code(await broker.handle(.edit(id: item.id, AgentItemFields(url: "https://evil.example")))) == .denied)
        #expect(code(await broker.handle(.trash(id: item.id))) == .denied)
        #expect(code(await broker.handle(.add(AgentItemFields(title: "New"), password: nil))) == .denied)
        let after = try await device.vault.item(id: item.id)
        #expect(after.urls == ["https://github.com"])
        #expect(try await device.vault.items().items.count == 1)
        #expect(await host.reasons.first?.contains("https://evil.example") == true)
        #expect(!device.gate.calls.contains { $0.hasPrefix("Edit") || $0 == "Delete item" }, "the agent's prompt replaced the core's, it did not add a second one")
    }

    @Test("a client without the tool's signature gets nothing, and the handler never runs")
    func wrongSignatureIsRefused() async throws {
        let directory = "/tmp/bisel-agent-\(UUID().uuidString.prefix(8))"
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let calls = Calls()
        let handler: AgentListener.Handler = { _ in
            await calls.add()
            return .secrets([AgentSecret("leaked")])
        }
        let strict = directory + "/strict.sock", open = directory + "/open.sock"
        try AgentListener(path: strict, clientRequirement: AgentPeer.toolRequirement, handler: handler).start()
        try AgentListener(path: open, clientRequirement: nil, handler: handler).start()

        #expect(throws: AgentError(.failed)) { try AgentSocket.send(.status, path: strict, serverRequirement: nil) }
        #expect(await calls.count == 0)
        #expect(throws: AgentError(.untrustedApp)) { try AgentSocket.send(.status, path: open, serverRequirement: AgentPeer.appRequirement) }

        _ = try AgentSocket.send(.status, path: open, serverRequirement: nil)
        #expect(await calls.count == 1, "control: the transport works, so the refusal above is the signature check")

        // The same check guards the AutoFill socket: only the signed extension may ask it for a password.
        let autofill = directory + "/autofill.sock"
        try SocketListener<AutoFillRequest, AutoFillResult>(path: autofill, clientRequirement: AgentPeer.autoFillRequirement) { _ in
            await calls.add()
            return .credential(username: "u", password: AgentSecret("leaked"))
        }.start()
        #expect(throws: AgentError(.failed)) {
            let _: AutoFillResult = try AgentSocket.exchange(AutoFillRequest.list(services: ["github.com"]), path: autofill, serverRequirement: nil)
        }
        #expect(await calls.count == 1, "the handler never ran for an unsigned caller")
    }

    private actor Calls {
        var count = 0
        func add() { count += 1 }
    }

    @Test("a secret in a child's output is masked in every form, even split across reads")
    func maskingHoldsAcrossReads() {
        let secret = "p@ss word/1?"
        let data = Data(secret.utf8)
        let forms = [secret, data.base64EncodedString(), data.map { String(format: "%02x", $0) }.joined(),
                     data.map { String(format: "%02X", $0) }.joined(), "p%40ss%20word%2F1%3F"]
        for form in forms {
            var masker = SecretMasker(secrets: [data])
            var out: [UInt8] = []
            for byte in Array("before \(form) after".utf8) { out += masker.push([byte]) }
            out += masker.finish()
            let text = String(decoding: out, as: UTF8.self)
            #expect(!text.contains(form))
            #expect(text.hasPrefix("before [hidden by bisel]") && text.hasSuffix(" after"))
        }
        var masker = SecretMasker(secrets: [data])
        var out = masker.push(Array("ends with p@ss".utf8))
        out += masker.finish()
        #expect(String(decoding: out, as: UTF8.self) == "ends with p@ss", "a tail that never became the secret is still delivered")
    }

    @Test("an agent's fill refuses a wrong page, an unreadable address, a plain field, an item without a URL and any non-browser")
    func fillRefusesWithoutProof() {
        func refusal(browser: Bool = true, terminal: Bool = false, text: Bool = true, secure: Bool = true, code: Bool = false,
                     page: String? = "github.com", hosts: [String] = ["github.com"], login: Bool = false) -> AgentCode? {
            AgentFillPolicy.refusal(.init(isBrowser: browser, isTerminal: terminal, isTextInput: text, isSecure: secure, isCode: code, pageHost: page),
                                    itemHosts: hosts, login: login) { SiteMatch.matches(page: $0, item: $1, isPublicSuffix: { _ in false }) }
        }
        #expect(refusal() == nil)
        #expect(refusal(secure: false, code: true) == nil, "a code field")
        #expect(refusal(secure: false, login: true) == nil, "--login starts on the username field")
        #expect(refusal(page: "github.com.evil.net") == .wrongSite)
        #expect(refusal(page: nil) == .wrongSite)
        #expect(refusal(hosts: []) == .wrongSite)
        #expect(refusal(browser: false) == .wrongSite)
        #expect(refusal(terminal: true) == .wrongSite)
        #expect(refusal(secure: false) == .notPasswordField)
        #expect(refusal(login: true) == .notPasswordField, "--login must not type a username into the password field")
    }
}
// System AutoFill (docs/SPEC.md §8, "AutoFill"), against the real store and crypto. Touch ID is the fake host's answer.
@Suite("AutoFill", .serialized)
struct AutoFillFlowTests {

    private actor FakeHost: AutoFillHost {
        let vault: Vault
        var prompts = 0
        var answer: AgentError?
        var passkeyChanges = 0
        init(vault: Vault) { self.vault = vault }
        func set(answer: AgentError?) { self.answer = answer }
        func passkeysChanged() async { passkeyChanges += 1 }
        func authenticate(_ reason: String) async throws {
            prompts += 1
            if let answer { throw answer }
            if await !vault.isUnlocked { try await vault.unlock() }
        }
    }

    private static let password = "correct-horse-battery"
    private static let suffixes: Set<String> = ["com", "io", "github.io", "co.uk"]

    private func box() async throws -> (Device, FakeHost, AutoFillBroker, Item) {
        let device = try Device("autofill")
        _ = try await device.vault.bootstrapLocal(deviceName: "autofill")
        var draft = ItemDraft(type: .login)
        draft.title = "GitHub"
        draft.urls = ["https://github.com/login"]
        draft.username = "someone@example.com"
        draft.password = Self.password
        let item = try await device.vault.createItem(draft)
        let host = FakeHost(vault: device.vault)
        return (device, host, AutoFillBroker(vault: device.vault, host: host, isPublicSuffix: { Self.suffixes.contains($0) }), item)
    }

    private func password(_ result: AutoFillResult) -> String? {
        if case .credential(_, let secret) = result { return String(decoding: secret.bytes, as: UTF8.self) }
        return nil
    }

    private func code(_ result: AutoFillResult) -> AgentCode? {
        if case .refused(let code) = result { return code }
        return nil
    }

    @Test("a password never goes to a site that only looks like the login's address")
    func lookalikeSitesGetNothing() async throws {
        let (_, host, broker, item) = try await box()
        for site in ["github.com.evil.net", "evilgithub.com", "https://github.com.evil.net/login", "github.co.uk", "hub.com"] {
            #expect(code(await broker.handle(.credential(id: item.id, services: [site]))) == .wrongSite, "\(site)")
        }
        #expect(await host.prompts == 0, "nothing to approve: no Touch ID sheet for a request that would be refused")
        #expect(password(await broker.handle(.credential(id: item.id, services: ["https://login.github.com/x"]))) == Self.password, "control: a real subdomain")

        // A login saved for a shared-hosting name does not reach the tenants under it, and a login without an address reaches nothing.
        var draft = ItemDraft(type: .login)
        draft.title = "Pages"
        draft.urls = ["github.io"]
        draft.password = Self.password
        let device = try Device("autofill-tenants")
        _ = try await device.vault.bootstrapLocal(deviceName: "tenants")
        let tenant = try await device.vault.createItem(draft)
        draft.urls = []
        let noAddress = try await device.vault.createItem(draft)
        let other = AutoFillBroker(vault: device.vault, host: FakeHost(vault: device.vault), isPublicSuffix: { Self.suffixes.contains($0) })
        #expect(code(await other.handle(.credential(id: tenant.id, services: ["attacker.github.io"]))) == .wrongSite)
        #expect(code(await other.handle(.credential(id: noAddress.id, services: ["github.com"]))) == .wrongSite)
        guard case .candidates(let listed) = await other.handle(.list(services: ["attacker.github.io"])) else { Issue.record("no list"); return }
        #expect(listed.isEmpty)
    }

    @Test("without Touch ID there is no password, on an open box or a locked one")
    func noTouchIDNoPassword() async throws {
        let (device, host, broker, item) = try await box()
        let request = AutoFillRequest.credential(id: item.id, services: ["github.com"])

        await host.set(answer: AgentError(.denied))
        #expect(code(await broker.handle(request)) == .denied, "an open box still asks")
        await device.vault.lock()
        #expect(code(await broker.handle(request)) == .denied)
        #expect(await !device.vault.isUnlocked)

        await host.set(answer: nil)
        #expect(password(await broker.handle(request)) == Self.password, "Touch ID unlocks a locked box for the request")
    }

    @Test("one Touch ID for a list pays for one password, of a login on that list")
    func aListPaysForOnePassword() async throws {
        let (_, host, broker, item) = try await box()
        guard case .candidates(let listed) = await broker.handle(.list(services: ["github.com"])) else { Issue.record("no list"); return }
        #expect(listed == [AutoFillCandidate(id: item.id, title: "GitHub", username: "someone@example.com")])
        #expect(await host.prompts == 1)

        #expect(password(await broker.handle(.credential(id: item.id, services: ["github.com"]))) == Self.password)
        #expect(await host.prompts == 1, "choosing from the list does not ask twice")
        #expect(password(await broker.handle(.credential(id: item.id, services: ["github.com"]))) == Self.password)
        #expect(await host.prompts == 2, "the next password asks again")
    }

    private static let hash = Data(repeating: 7, count: 32)

    private func registered(_ broker: AutoFillBroker, rpID: String = "github.com") async throws -> Data {
        let request = AutoFillPasskeyRegistration(rpID: rpID, userHandle: Data([1, 2, 3]), userName: "someone@example.com", userDisplayName: "Someone",
                                                  algorithms: [PasskeyAuthenticator.es256], excludedCredentialIDs: [])
        guard case .registered(let id, _) = await broker.handle(.passkeyRegistration(request)) else { throw AgentError(.failed) }
        return id
    }

    private func signed(_ result: AutoFillResult) -> Bool {
        if case .assertion = result { return true }
        return false
    }

    @Test("a passkey signs through the extension without Touch ID, or for another site")
    func passkeyNeedsTouchIDAndItsOwnSite() async throws {
        let (device, host, broker, _) = try await box()
        let id = try await registered(broker)
        #expect(await host.prompts == 1)
        #expect(await host.passkeyChanges == 1, "a passkey made behind the app's back has to reach its list and sync")
        let request = AutoFillRequest.passkeyAssertion(rpID: "github.com", credentialID: id, clientDataHash: Self.hash)

        for site in ["github.com.evil.net", "evilgithub.com", "login.github.com"] {
            #expect(code(await broker.handle(.passkeyAssertion(rpID: site, credentialID: id, clientDataHash: Self.hash))) == .notFound, "\(site)")
        }
        #expect(code(await broker.handle(.passkeyAssertion(rpID: "github.io", credentialID: id, clientDataHash: Self.hash))) == .badRequest)
        #expect(await host.prompts == 1, "no Touch ID sheet for a request that would be refused")

        await host.set(answer: AgentError(.denied))
        #expect(code(await broker.handle(request)) == .denied, "an open box still asks")
        await device.vault.lock()
        #expect(code(await broker.handle(request)) == .denied)
        #expect(await !device.vault.isUnlocked)

        await host.set(answer: nil)
        #expect(signed(await broker.handle(request)), "Touch ID unlocks a locked box for the request")
    }

    @Test("one Touch ID for a passkey list pays for one signature")
    func aListPaysForOneSignature() async throws {
        let (_, host, broker, _) = try await box()
        let id = try await registered(broker)
        let before = await host.prompts
        guard case .passkeys(let listed) = await broker.handle(.passkeys(rpID: "github.com", allowList: [])) else { Issue.record("no list"); return }
        #expect(listed == [AutoFillPasskey(credentialID: id, userName: "someone@example.com")])
        #expect(await host.prompts == before + 1)

        let request = AutoFillRequest.passkeyAssertion(rpID: "github.com", credentialID: id, clientDataHash: Self.hash)
        #expect(signed(await broker.handle(request)))
        #expect(await host.prompts == before + 1, "choosing from the list does not ask twice")
        #expect(signed(await broker.handle(request)))
        #expect(await host.prompts == before + 2, "the next signature asks again")

        guard case .passkeys(let none) = await broker.handle(.passkeys(rpID: "gitlab.com", allowList: [])) else { Issue.record("no list"); return }
        #expect(none.isEmpty)
        #expect(await host.prompts == before + 2, "no sheet for a site with no passkeys: passwords ask for themselves")
    }

    @Test("a site's excluded passkey is duplicated, or a passkey is made without Touch ID")
    func registrationIsGuarded() async throws {
        let (device, host, broker, _) = try await box()
        let id = try await registered(broker)
        let again = AutoFillPasskeyRegistration(rpID: "github.com", userHandle: Data([9]), userName: "other", userDisplayName: "Other",
                                                algorithms: [PasskeyAuthenticator.es256], excludedCredentialIDs: [id])
        #expect(code(await broker.handle(.passkeyRegistration(again))) == .excludedCredential)

        await host.set(answer: AgentError(.denied))
        var fresh = again
        fresh.excludedCredentialIDs = []
        #expect(code(await broker.handle(.passkeyRegistration(fresh))) == .denied)
        #expect(try await device.vault.passkeys(rpID: "github.com").count == 1)
    }

    @Test("the identity store gets a passkey's private key, or a passkey on a public suffix")
    func passkeyIdentitiesCarryTheMinimum() async throws {
        let (device, _, broker, _) = try await box()
        let id = try await registered(broker)
        let items = try await device.vault.items().items
        let passkeys = AutoFillIdentity.all(in: items, isPublicSuffix: { Self.suffixes.contains($0) }).filter { $0.passkey != nil }
        #expect(passkeys.map(\.domain) == ["github.com"])
        #expect(passkeys.first?.passkey == AutoFillIdentity.Passkey(credentialID: id, userHandle: Data([1, 2, 3])))
        #expect(AutoFillIdentity.all(in: items, isPublicSuffix: { $0 == "github.com" }).allSatisfy { $0.passkey == nil })
    }

    @Test("the plaintext identity store gets no secret, no title and no public suffix")
    func identitiesCarryTheMinimum() async throws {
        let (device, _, _, item) = try await box()
        var draft = ItemDraft(type: .login)
        draft.title = "Pages"
        draft.urls = ["github.io", "www.example.co.uk"]
        draft.username = "me"
        draft.password = Self.password
        let second = try await device.vault.createItem(draft)
        draft.password = ""
        draft.urls = ["no-password.example.com"]
        _ = try await device.vault.createItem(draft)

        let identities = AutoFillIdentity.all(in: try await device.vault.items().items, isPublicSuffix: { Self.suffixes.contains($0) })
        #expect(identities == [AutoFillIdentity(domain: "example.co.uk", username: "me", recordID: second.id),
                               AutoFillIdentity(domain: "github.com", username: "someone@example.com", recordID: item.id)])
    }

    private final class SlowSink: AutoFillIdentitySink {
        let held = Mutex<[AutoFillIdentity]>([AutoFillIdentity(domain: "stale.example", username: "old", recordID: "x")])
        let enabled = Mutex(true)
        func isEnabled() async -> Bool { enabled.withLock { $0 } }
        func replace(_ identities: [AutoFillIdentity]) async throws {
            try await Task.sleep(for: .milliseconds(50))
            held.withLock { $0 = identities }
        }
        func clear() async throws { held.withLock { $0 = [] } }
    }

    @Test("a lock during a slow write leaves nothing of the box in the identity store")
    func lockBeatsAWriteInFlight() async throws {
        let sink = SlowSink(), sync = AutoFillIdentitySync(sink: sink)
        let identity = AutoFillIdentity(domain: "github.com", username: "me", recordID: "1")

        sync.publish([identity])
        try await Task.sleep(for: .milliseconds(10))   // the write is under way
        sync.clear()
        await sync.settled()
        #expect(sink.held.withLock { $0 }.isEmpty)

        // Not turned on in AutoFill settings: nothing is written, and it goes in once the person does.
        sink.enabled.withLock { $0 = false }
        sync.publish([identity])
        await sync.settled()
        #expect(sink.held.withLock { $0 }.isEmpty)
        sink.enabled.withLock { $0 = true }
        sync.refresh()
        await sync.settled()
        #expect(sink.held.withLock { $0 } == [identity])
    }
}
#endif
