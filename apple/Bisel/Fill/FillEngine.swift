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

    func fill(_ plan: FillPlan, into target: NSRunningApplication, fetch: @escaping SecretFetch) async -> FillOutcome {
        guard AccessibilityInspector.isTrusted() else { return .needsAccessibility }
        return await Self.perform(plan, target: target, fetch: fetch)
    }

    @concurrent
    private static func perform(_ plan: FillPlan, target: NSRunningApplication, fetch: SecretFetch) async -> FillOutcome {
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
        Log.fill.notice("target \(target.bundleIdentifier ?? "?", privacy: .public): \(field.describe, privacy: .public) secureInput=\(IsSecureEventInputEnabled())")
        if field.isClearlyNotText {
            return .notATextField("Focus is on a \(field.role ?? "control"), not a text field")
        }

        let method = field.bundleID.flatMap { preferredMethod[$0] } ?? .keyEvents
        do {
            switch plan {
            case .auto:
                let value = try await fetch(field.kind)
                let used = await deliver(value, field: field, target: target, method: method)
                return .filled("Filled \(field.kind.rawValue) (\(used.rawValue))")
            case .explicit(let kind):
                let value = try await fetch(kind)
                let used = await deliver(value, field: field, target: target, method: method)
                return .filled("Filled \(kind.rawValue) (\(used.rawValue))")
            case .userTabPassword:
                let user = try await fetch(.username)
                _ = await deliver(user, field: field, target: target, method: method)
                try? await Task.sleep(for: .milliseconds(60))
                KeyEventTyper.press(KeyEventTyper.tabKey)
                try? await Task.sleep(for: .milliseconds(180))
                // After Tab the focus moved: re-read it so verification looks at the password field.
                let next = AccessibilityInspector.focusedField(of: target)
                let pass = try await fetch(.password)
                let used = await deliver(pass, field: next, target: target, method: method)
                return .filled("Filled username, Tab, password (\(used.rawValue))")
            }
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    /// Delivers one value; returns the method that actually carried it.
    @concurrent
    private static func deliver(_ text: String, field: FocusedField, target: NSRunningApplication, method: DeliveryMethod) async -> DeliveryMethod {
        if method == .paste {
            await pasteTemporarily(text)
            return .paste
        }
        // Only verify where a changed AX value is a reliable signal: not terminals (no echo at password prompts),
        // and only when the value is readable before and after.
        let canVerify = field.isTextInput && !field.isTerminal && !text.isEmpty
        let before = canVerify ? AccessibilityInspector.focusedValueLength(of: target) : nil
        KeyEventTyper.type(text)
        guard canVerify, let before else { return .keyEvents }
        try? await Task.sleep(for: .milliseconds(120))
        if let after = AccessibilityInspector.focusedValueLength(of: target), after == before {
            Log.fill.notice("key events did not change the field value; falling back to paste")
            await pasteTemporarily(text)
            return .paste
        }
        return .keyEvents
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
