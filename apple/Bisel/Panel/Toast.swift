import AppKit
import SwiftUI

/// Small non-activating HUD for results after the command panel has gone (fill failed, copied, …).
@MainActor
final class Toast {
    static let shared = Toast()
    private var panel: NSPanel?
    private var hideTask: Task<Void, Never>?

    func show(_ text: String, isError: Bool = false, duration: Duration = .seconds(2.2)) {
        let theme = ThemeStore.shared.current
        let host = NSHostingView(rootView: ToastView(text: text, isError: isError).environment(\.theme, theme))
        host.setFrameSize(host.fittingSize)
        let p = panel ?? {
            let p = NSPanel(contentRect: .zero, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
            p.isFloatingPanel = true
            p.level = .statusBar
            p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
            p.isOpaque = false
            p.backgroundColor = .clear
            p.hasShadow = true
            p.ignoresMouseEvents = true
            p.animationBehavior = .none
            p.isReleasedWhenClosed = false
            panel = p
            return p
        }()
        p.appearance = NSAppearance(named: theme.appearance == .dark ? .darkAqua : .aqua)
        p.contentView = host
        let size = host.fittingSize
        let screen = NSScreen.screens.first { $0.frame.contains(NSEvent.mouseLocation) } ?? NSScreen.main
        let vf = screen?.visibleFrame ?? .zero
        p.setFrame(NSRect(x: vf.midX - size.width / 2, y: vf.maxY - size.height - 56, width: size.width, height: size.height), display: true)
        p.orderFrontRegardless()
        hideTask?.cancel()
        hideTask = Task { [weak p] in
            try? await Task.sleep(for: duration)
            if !Task.isCancelled { p?.orderOut(nil) }
        }
    }
}

private struct ToastView: View {
    let text: String
    let isError: Bool
    @Environment(\.theme) private var theme

    var body: some View {
        HStack(spacing: theme.spacing.s) {
            Image(systemName: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(isError ? theme.colors.warning.color : theme.colors.accent.color)
            Text(text).font(theme.font(theme.fonts.title, weight: .medium))
        }
        .foregroundStyle(theme.colors.text.color)
        .padding(.horizontal, theme.spacing.m)
        .padding(.vertical, theme.spacing.m)
        .background { CardSurface() }
        .environment(\.colorScheme, theme.colorScheme)
        .fixedSize()
        .padding(theme.spacing.s)
    }
}
