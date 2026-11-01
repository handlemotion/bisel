import AppKit
import Observation
import SwiftUI

/// The Accessibility trust state, polled: the person grants it in System Settings, which does not notify us.
@MainActor
@Observable
final class AccessibilityMonitor {
    private(set) var trusted = AccessibilityInspector.isTrusted()
    @ObservationIgnored private var timer: Timer?

    /// Polls for the life of the app (one cheap call a second): the panel's pill, the Fill page and the set-up step all read it.
    func start() {
        refresh()
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    func refresh() {
        #if DEBUG
        if ProcessInfo.processInfo.environment["BISEL_DEV_AX_OFF"] == "1" { trusted = false; return }   // screenshots of the "off" states
        #endif
        trusted = AccessibilityInspector.isTrusted()
    }
}

extension AccessibilityInspector {
    static let settingsURL = URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility")!

    /// From an explicit click only: puts Bisel in the Accessibility list (the system prompt) and opens that pane, where the
    /// person turns it on. It grants nothing by itself.
    @MainActor
    static func requestAccess() {
        _ = isTrusted(prompt: true)
        NSWorkspace.shared.open(settingsURL)
    }
}

/// The set-up step after the recovery phrase: the Accessibility permission, which filling needs (copying does not).
/// Skipped when it is already on; the panel shows a warning pill while it is off.
struct OnboardingAccessibilityView: View {
    let monitor: AccessibilityMonitor
    var onFinish: () -> Void
    private let theme = Theme.biselDark

    var body: some View {
        OnboardingFrame(progress: 0.7, title: monitor.trusted ? "Bisel can type for you" : "Let Bisel type for you",
                        message: "To fill usernames, passwords and codes into the app you're in, Bisel needs the Accessibility permission. It only reads which field has focus, and only you can turn it on.") {
            HStack(spacing: theme.spacing.s) {
                Image(systemName: monitor.trusted ? "checkmark.circle.fill" : "circle.dashed")
                Text(monitor.trusted ? "Allowed" : "Turn on Bisel in System Settings, Accessibility. This screen updates by itself.")
                    .fixedSize(horizontal: false, vertical: true)
            }
            .font(theme.font(theme.fonts.search))
            .foregroundStyle(monitor.trusted ? theme.colors.success.color : theme.colors.secondaryText.color)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("onboarding.status")
        } actions: {
            if !monitor.trusted {
                Button("Skip for now", action: onFinish).buttonStyle(PillButtonStyle(primary: false))
            }
            Spacer(minLength: 0)
            if monitor.trusted {
                Button("Continue", action: onFinish).buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
            } else {
                Button("Open System Settings") { AccessibilityInspector.requestAccess() }
                    .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
            }
        }
    }
}
