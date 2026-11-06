import AppKit
import SwiftUI

/// Gives SwiftUI views a handle on their NSWindow (capture exclusion, background).
struct WindowAccessor: NSViewRepresentable {
    let configure: (NSWindow) -> Void
    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        DispatchQueue.main.async { if let w = v.window { configure(w) } }
        return v
    }
    func updateNSView(_ v: NSView, context: Context) {
        DispatchQueue.main.async { if let w = v.window { configure(w) } }
    }
}

extension View {
    /// `opaque: false` leaves the background to the content (the onboarding screens draw the glass themselves).
    func themedPage(_ theme: Theme, opaque: Bool = true) -> some View {
        self.foregroundStyle(theme.colors.text.color)
            .background(opaque ? theme.colors.background.color : .clear)
            .tint(theme.colors.accent.color)
            .preferredColorScheme(theme.colorScheme)
    }
}

/// Bisel is a menu-bar app (no Dock icon) until one of its windows is on screen; then it gets a Dock icon (AppIcon.icon),
/// and goes back to the menu bar when the last window closes.
@MainActor
enum DockPresence {
    private static var observers: [NSObjectProtocol] = []

    /// Runs on every view update, and a closed SwiftUI `Window` keeps updating: only a window on screen may bring the icon back.
    static func windowAppeared(_ window: NSWindow) {
        observe()
        if window.isVisible { showIcon() }
    }

    private static func showIcon() {
        guard NSApp.activationPolicy() != .regular else { return }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }

    private static func counts(_ window: NSWindow) -> Bool { !(window is NSPanel) && window.styleMask.contains(.titled) }

    private static func observe() {
        guard observers.isEmpty else { return }
        let center = NotificationCenter.default
        // A window that was not on screen yet when `windowAppeared` ran, or that reopens with no view update.
        observers.append(center.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { note in
            let window = note.object as? NSWindow
            MainActor.assumeIsolated { if let window, counts(window) { showIcon() } }
        })
        observers.append(center.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { note in
            let closing = note.object as? NSWindow
            MainActor.assumeIsolated {
                guard let closing, !(closing is NSPanel) else { return }
                let others = NSApp.windows.contains { $0 !== closing && $0.isVisible && counts($0) }
                if !others { NSApp.setActivationPolicy(.accessory) }
            }
        })
    }
}

/// Section header / caption styles from Theme tokens.
struct Caption: View {
    let text: String
    @Environment(\.theme) private var theme
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.secondaryText.color)
    }
}

struct ErrorLine: View {
    let text: String?
    @Environment(\.theme) private var theme
    var body: some View {
        if let text {
            Text(text).font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.danger.color)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("error-line")
        }
    }
}

enum ServerURLCheck {
    /// https anywhere, plain http only for the local dev server.
    static func parse(_ raw: String) -> (URL?, String?) {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return (nil, "Enter the server URL") }
        guard var c = URLComponents(string: t.contains("://") ? t : "https://\(t)"), let host = c.host, !host.isEmpty else {
            return (nil, "That doesn't look like a URL")
        }
        let local = ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host)
        if c.scheme == "http" && !local { return (nil, "Use https:// (plain http is only allowed for localhost)") }
        guard c.scheme == "https" || c.scheme == "http" else { return (nil, "The URL must start with https://") }
        if c.path == "/" { c.path = "" }
        return (c.url, nil)
    }
}
