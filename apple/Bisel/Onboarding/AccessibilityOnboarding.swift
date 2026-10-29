import AppKit
import Observation
import SwiftUI

/// Polls the Accessibility trust state while the onboarding window is open (the user grants it in System Settings,
/// which does not notify us).
@MainActor
@Observable
final class AccessibilityMonitor {
    private(set) var trusted = AccessibilityInspector.isTrusted()
    @ObservationIgnored private var timer: Timer?

    func start() {
        refresh()
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func stop() { timer?.invalidate(); timer = nil }

    func refresh() { trusted = AccessibilityInspector.isTrusted() }
}

@MainActor
final class OnboardingWindowController {
    private var window: NSWindow?
    private let monitor: AccessibilityMonitor

    init(monitor: AccessibilityMonitor) { self.monitor = monitor }

    func show() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 470),
                             styleMask: [.titled, .closable, .fullSizeContentView],
                             backing: .buffered, defer: false)
            w.titlebarAppearsTransparent = true
            w.titleVisibility = .hidden
            w.isReleasedWhenClosed = false
            w.center()
            w.contentView = NSHostingView(rootView: AccessibilityOnboardingView(monitor: monitor) { [weak self] in
                self?.window?.close()
            }.environment(\.theme, ThemeStore.shared.current))
            window = w
        }
        monitor.start()
        NSApp.activate()
        window?.makeKeyAndOrderFront(nil)
    }
}

struct AccessibilityOnboardingView: View {
    let monitor: AccessibilityMonitor
    let done: () -> Void
    @Environment(\.theme) private var theme

    private static let settingsURL = URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility")!

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            Image(systemName: monitor.trusted ? "checkmark.shield.fill" : "hand.raised.fill")
                .font(.system(size: 34))
                .foregroundStyle(monitor.trusted ? theme.colors.accent.color : theme.colors.warning.color)
            Text(monitor.trusted ? "You're all set" : "Let Bisel type for you")
                .font(theme.font(24, weight: .semibold))
            Text("To fill usernames, passwords and codes into the app you're using, Bisel needs the Accessibility permission. macOS only lets you grant it yourself.")
                .font(theme.font(theme.fonts.title))
                .foregroundStyle(theme.colors.secondaryText.color)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: theme.spacing.s) {
                point("Bisel reads only which field has focus, so it knows whether to type a username, password or code.")
                point("It types by posting key presses. It never records what you type.")
                point("Passwords are never shown in the command panel.")
            }

            if !monitor.trusted {
                VStack(alignment: .leading, spacing: theme.spacing.s) {
                    step(1, "Click “Open Accessibility Settings”.")
                    step(2, "Turn on the switch next to Bisel. If Bisel is not listed, click “Add Bisel to the list” first, or press + and choose Bisel.app.")
                    step(3, "Come back here. This window updates by itself.")
                }
                .padding(theme.spacing.m)
                .background(theme.colors.field.color, in: RoundedRectangle(cornerRadius: theme.radii.field, style: .continuous))
            }

            HStack {
                Image(systemName: monitor.trusted ? "checkmark.circle.fill" : "circle.dashed")
                Text(monitor.trusted ? "Accessibility permission granted" : "Waiting for permission…")
                    .font(theme.font(theme.fonts.subtitle, weight: .medium))
            }
            .foregroundStyle(monitor.trusted ? theme.colors.accent.color : theme.colors.secondaryText.color)
            .accessibilityIdentifier("onboarding.status")

            Spacer(minLength: 0)

            HStack {
                if monitor.trusted {
                    Spacer()
                    Button("Done", action: done).keyboardShortcut(.defaultAction)
                } else {
                    Button("Add Bisel to the list") { _ = AccessibilityInspector.isTrusted(prompt: true) }
                    Spacer()
                    Button("Open Accessibility Settings") { NSWorkspace.shared.open(Self.settingsURL) }
                        .keyboardShortcut(.defaultAction)
                }
            }
            #if DEBUG
            Text("Debug build is ad-hoc signed: macOS ties the permission to this exact build, so you must re-grant after every rebuild (remove Bisel with “−”, then add it again).")
                .font(theme.font(theme.fonts.caption))
                .foregroundStyle(theme.colors.tertiaryText.color)
            #endif
        }
        .padding(theme.spacing.m * 3)
        .frame(width: 520, height: 470, alignment: .topLeading)
        .foregroundStyle(theme.colors.text.color)
        .background(.background)
    }

    private func point(_ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: theme.spacing.s) {
            Image(systemName: "checkmark").font(.caption.bold()).foregroundStyle(theme.colors.accent.color)
            Text(text).font(theme.font(theme.fonts.subtitle)).fixedSize(horizontal: false, vertical: true)
        }
    }

    private func step(_ n: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: theme.spacing.s) {
            Text("\(n)").font(theme.font(theme.fonts.caption, weight: .bold))
                .frame(width: 18, height: 18)
                .background(theme.colors.accent.color, in: Circle())
                .foregroundStyle(theme.colors.accentText.color)
            Text(text).font(theme.font(theme.fonts.subtitle)).fixedSize(horizontal: false, vertical: true)
        }
    }
}
