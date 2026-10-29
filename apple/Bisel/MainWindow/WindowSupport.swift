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
    /// Excludes the hosting window (sheet, popover, panel) from screenshots and screen sharing where the OS honours
    /// `NSWindow.sharingType` (the "Hide from screenshots and screen sharing" setting; default on in Release), or always when `force`.
    func hiddenFromCapture(force: Bool = false) -> some View {
        background(WindowAccessor { w in w.sharingType = (force || PanelCapture.hidden) ? .none : .readOnly })
    }

    /// Themed page background + text color for main-window screens.
    func themedPage(_ theme: Theme) -> some View {
        self.foregroundStyle(theme.colors.text.color)
            .background(theme.colors.background.color)
            .tint(theme.colors.accent.color)
            .preferredColorScheme(theme.colorScheme)
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
