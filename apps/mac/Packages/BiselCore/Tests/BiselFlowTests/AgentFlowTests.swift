#if BISEL_SOFTWARE_KEYS
import Foundation
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
#endif
