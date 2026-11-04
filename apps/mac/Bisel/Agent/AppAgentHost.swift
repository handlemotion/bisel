import AppKit
import BiselCore

/// The app's side of `AgentBroker`: the switch, the Touch ID prompt and the fill (docs/AGENT-CLI.md).
@MainActor
final class AppAgentHost: AgentHost {
    private static let promptTimeout: Duration = .seconds(60)

    private let service: VaultService

    init(service: VaultService) { self.service = service }

    func isAllowed() async -> Bool { AgentAccess.isAllowed }
    func isUnlocked() async -> Bool { service.isUnlocked }
    func didChange(_ reason: String) async { await service.didChangeLocally(reason: reason) }

    /// Always a real prompt: strict mode does not apply, and it neither spends nor grants the panel's single-use credit.
    func approve(_ reason: String) async throws {
        let start = ContinuousClock.now
        do {
            try await BiometricGate.authenticate(reason: reason, grantsCredit: false, timeout: Self.promptTimeout)
        } catch {
            throw AgentError(ContinuousClock.now - start >= Self.promptTimeout ? .timeout : .denied)
        }
    }

    func fill(_ item: Item, login: Bool, submit: Bool) async throws {
        guard AccessibilityInspector.isTrusted() else { throw AgentError(.noAccessibility) }
        guard let target = NSWorkspace.shared.frontmostApplication, target.processIdentifier != getpid() else {
            throw AgentError(.wrongSite)
        }
        let hosts = FillOrigin.hosts(of: item.urls)
        let front = await Self.inspect(target)
        let facts = AgentFillPolicy.Field(isBrowser: FillOrigin.isBrowser(front.field.bundleID), isTerminal: front.field.isTerminal,
                                          isTextInput: front.field.isTextInput, isSecure: front.field.isSecure,
                                          isCode: front.field.kind == .totp, pageHost: front.page)
        if let code = AgentFillPolicy.refusal(facts, itemHosts: hosts, login: login, matches: { page, host in
            FillOrigin.matches(page: FillOrigin.normalized(page), item: host)
        }) { throw AgentError(code) }

        let what = login ? "login" : (front.field.kind == .totp ? "one-time code" : "password")
        let app = AgentPrompt.clean(target.localizedName ?? "this browser", limit: 30)
        try await approve("fill \(AgentPrompt.clean(item.title, limit: 40)) \(what) on \(front.page ?? "") in \(app)")
        // The Touch ID sheet can take key focus; typing starts only once the same field is back in front.
        guard await Self.waitForFocus(front.field, target) else { throw AgentError(.fillFailed) }

        // Never `.explicit`: that plan is a person's override and skips the site check.
        let outcome = await FillEngine.shared.fill(login ? .userTabPassword : .auto, into: target, itemHosts: hosts) { kind in
            try Self.value(kind, of: item)
        }
        switch outcome {
        case .filled:
            if submit, NSWorkspace.shared.frontmostApplication?.processIdentifier == target.processIdentifier {
                KeyEventTyper.press(KeyEventTyper.returnKey)
            }
        case .needsAccessibility: throw AgentError(.noAccessibility)
        case .notATextField: throw AgentError(.notPasswordField)
        case .failed: throw AgentError(.fillFailed)
        }
    }

    private nonisolated static func value(_ kind: SecretKind, of item: Item) throws -> String {
        let value: String?
        switch kind {
        case .username: value = item.username
        case .password: value = item.password
        case .totp: value = try item.totp.map { try TOTPGenerator.code($0).code }
        }
        guard let value, !value.isEmpty else { throw AgentError(.noSuchField) }
        return value
    }

    /// Off the main actor: Accessibility calls into a slow app can block. Chromium builds its tree lazily, so give it a moment.
    @concurrent
    private static func inspect(_ target: NSRunningApplication) async -> (field: FocusedField, page: String?) {
        AccessibilityInspector.enableChromiumAccessibilityIfNeeded(app: target)
        var field = AccessibilityInspector.focusedField(of: target)
        for _ in 0..<5 where !field.isTextInput && !field.isTerminal && !field.isClearlyNotText {
            try? await Task.sleep(for: .milliseconds(120))
            field = AccessibilityInspector.focusedField(of: target)
        }
        return (field, AccessibilityInspector.pageURL(of: target, field: field)?.host())
    }

    @concurrent
    private static func waitForFocus(_ field: FocusedField, _ target: NSRunningApplication) async -> Bool {
        for _ in 0..<20 {
            if AccessibilityInspector.isStillFocused(field, target: target) { return true }
            try? await Task.sleep(for: .milliseconds(100))
        }
        return false
    }
}
