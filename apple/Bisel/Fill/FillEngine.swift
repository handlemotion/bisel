import AppKit
import Carbon.HIToolbox

enum FillPlan: Sendable {
    /// Enter: infer the focused field (secure → password, code-ish label → TOTP, else username).
    case auto
    /// ⌥Enter: username, Tab, password.
    case userTabPassword
    /// ⌘K actions: force one kind.
    case explicit(SecretKind)
}

enum FillOutcome: Sendable {
    case filled(String)
    case needsAccessibility
    case notATextField(String)
    case failed(String)
}

enum DeliveryMethod: String, Sendable { case keyEvents, paste }

typealias SecretFetch = @Sendable (SecretKind) async throws -> String

/// Fills secrets into the focused input of the app that was frontmost when the panel opened (SPEC.md §8).
/// Needs the Accessibility permission for both reading the focused element and posting key events.
@MainActor
final class FillEngine {
    static let shared = FillEngine()
    private init() {}

    /// Per-app delivery override, filled in from the compatibility matrix (FILL-MATRIX.md). Anything not listed
    /// uses key events first and falls back to a temporary paste when the field's value did not change.
    nonisolated static let preferredMethod: [String: DeliveryMethod] = [:]

    /// Call when the panel opens so Chromium/Electron apps have time to build their web AX tree before the fill.
    func warmUp(target: NSRunningApplication?) {
        guard let target, AccessibilityInspector.isTrusted() else { return }
        Task.detached(priority: .userInitiated) {
            AccessibilityInspector.enableChromiumAccessibilityIfNeeded(app: target)
            // Touch the focused element once so lazy trees start building.
            _ = AccessibilityInspector.focusedField(of: target)
        }
    }

    /// `itemHosts`: the hosts of the chosen login's addresses; the page in front must match one of them unless the fill is forced.
    func fill(_ plan: FillPlan, into target: NSRunningApplication, itemHosts: [String] = [], fetch: @escaping SecretFetch) async -> FillOutcome {
        guard AccessibilityInspector.isTrusted() else { return .needsAccessibility }
        return await Self.perform(plan, target: target, itemHosts: itemHosts, fetch: fetch)
    }

    /// Why this field must not receive this kind of secret (security review M9), or nil. A password goes only into a secure field
    /// (macOS then also turns on secure event input) or, when the user forced it from ⌘K, into any field, but never into a terminal
    /// unless secure input is on (shell history, `sudo` prompts).
    nonisolated static func refusal(for kind: SecretKind, in field: FocusedField, forced: Bool) -> String? {
        guard kind == .password else { return nil }
        guard field.ref != nil else { return "Can't verify the focused field in this app, so the password was not typed" }
        if field.isTerminal && !IsSecureEventInputEnabled() {
            return "This terminal isn't in secure input mode, so the password was not typed"
        }
        if !field.isSecure && !forced { return "That isn't a password field. Use ⌘K → Fill password to type it anyway" }
        return nil
    }

    /// Asked before each typed chunk: the target is still frontmost and focus is still on the element that was classified.
    private nonisolated static func stillThere(_ field: FocusedField, _ target: NSRunningApplication) -> Bool {
        if field.ref == nil { return NSWorkspace.shared.frontmostApplication?.processIdentifier == target.processIdentifier }
        return AccessibilityInspector.isStillFocused(field, target: target)
    }

    @concurrent
    private static func perform(_ plan: FillPlan, target: NSRunningApplication, itemHosts: [String], fetch: SecretFetch) async -> FillOutcome {
        await KeyEventTyper.waitForModifierRelease()
        // Let the window server hand key focus back to the target after the panel went away.
        try? await Task.sleep(for: .milliseconds(80))

        AccessibilityInspector.enableChromiumAccessibilityIfNeeded(app: target)
        var field = AccessibilityInspector.focusedField(of: target)
        var attempts = 0
        while !field.isTextInput, !field.isTerminal, !field.isClearlyNotText, attempts < 5 {
            attempts += 1
            try? await Task.sleep(for: .milliseconds(120))
            field = AccessibilityInspector.focusedField(of: target)
        }
        Log.fill.notice("target \(target.bundleIdentifier ?? "?"): \(field.describe) secureInput=\(IsSecureEventInputEnabled())")
        if field.isClearlyNotText {
            return .notATextField("Focus is on a \(field.role ?? "control"), not a text field")
        }
        guard NSWorkspace.shared.frontmostApplication?.processIdentifier == target.processIdentifier else {
            return .failed("The app you were in is no longer in front, nothing was typed")
        }

        if case .explicit = plan {} else if !itemHosts.isEmpty {
            let page = AccessibilityInspector.pageURL(of: target, field: field)?.host()
            let isBrowser = field.bundleID.map(FillOrigin.browserBundleIDs.contains) ?? false
            if let why = FillOrigin.refusal(pageHost: page, isBrowser: isBrowser, itemHosts: itemHosts) { return .failed(why) }
        }

        let method = field.bundleID.flatMap { preferredMethod[$0] } ?? .keyEvents
        let stopped = FillOutcome.failed("Focus moved while filling, typing stopped")
        do {
            switch plan {
            case .auto, .explicit:
                let kind: SecretKind, forced: Bool
                if case .explicit(let k) = plan { kind = k; forced = true } else { kind = field.kind; forced = false }
                if let why = refusal(for: kind, in: field, forced: forced) { return .failed(why) }
                let value = try await fetch(kind)
                guard await deliver(value, field: field, target: target, method: method) != nil else { return stopped }
                return .filled("Filled \(kind.rawValue)")
            case .userTabPassword:
                let user = try await fetch(.username)
                guard await deliver(user, field: field, target: target, method: method) != nil else { return stopped }
                try? await Task.sleep(for: .milliseconds(60))
                guard stillThere(field, target) else { return stopped }
                KeyEventTyper.press(KeyEventTyper.tabKey)
                try? await Task.sleep(for: .milliseconds(180))
                // After Tab the focus moved: re-read it. The password only goes into a secure field (never read before that).
                let next = AccessibilityInspector.focusedField(of: target)
                if let why = refusal(for: .password, in: next, forced: false) { return .failed("Username typed. " + why) }
                let pass = try await fetch(.password)
                guard await deliver(pass, field: next, target: target, method: method) != nil else { return stopped }
                return .filled("Filled username, Tab, password")
            }
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    /// Delivers one value; returns the method that actually carried it, or nil if it was stopped because focus moved.
    @concurrent
    private static func deliver(_ text: String, field: FocusedField, target: NSRunningApplication, method: DeliveryMethod) async -> DeliveryMethod? {
        if method == .paste {
            guard stillThere(field, target) else { return nil }
            await pasteTemporarily(text)
            return .paste
        }
        // Only verify where a changed AX value is a reliable signal: not terminals (no echo at password prompts),
        // and only when the value is readable before and after.
        let canVerify = field.isTextInput && !field.isTerminal && !text.isEmpty
        let before = canVerify ? AccessibilityInspector.focusedValueLength(of: target) : nil
        guard KeyEventTyper.type(text, proceed: { stillThere(field, target) }) else { return nil }
        guard canVerify, let before else { return .keyEvents }
        // The AX value can lag the keystrokes. Wait for it, and fall back to paste only if it is readable and truly unchanged
        // after 500 ms (never when it merely can't be read, so a slow app can't receive the secret twice).
        for _ in 0..<10 {
            try? await Task.sleep(for: .milliseconds(50))
            guard let after = AccessibilityInspector.focusedValueLength(of: target) else { return .keyEvents }
            if after != before { return .keyEvents }
        }
        guard stillThere(field, target) else { return nil }
        Log.fill.notice("key events did not change the field value; falling back to paste")
        await pasteTemporarily(text)
        return .paste
    }

    @concurrent
    private static func pasteTemporarily(_ text: String) async {
        let (snap, count) = await MainActor.run {
            let clip = SecureClipboard.shared
            return (clip.snapshot(), clip.stageForPaste(text))
        }
        KeyEventTyper.press(KeyEventTyper.vKey, flags: .maskCommand)
        try? await Task.sleep(for: .milliseconds(250))
        await MainActor.run { SecureClipboard.shared.restore(snap, ifChangeCountIs: count) }
    }
}
