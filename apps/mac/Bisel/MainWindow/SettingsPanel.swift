import AppKit
import SwiftUI
import BiselCore

/// Settings as a floating card, the command panel's look without its title bar or traffic lights. Unlike the command
/// panel it activates Bisel (pickers, the shortcut recorder, sheets and save panels need a normal key window), and it
/// closes on Esc, a click outside it, or Bisel losing the front.
@MainActor
final class SettingsPanelController {
    private let panel = SettingsPanel()
    private let service: VaultService
    private var monitors: [Any] = []
    private var observers: [NSObjectProtocol] = []
    private var menuTracking = false
    /// True while the Touch ID sheet is up: it takes the front from Bisel, which must not read as "clicked away".
    private var authenticating = false

    var isVisible: Bool { panel.isVisible }

    init(service: VaultService) {
        self.service = service
        panel.title = String(localized: "Bisel Settings")
        let host = NSHostingView(rootView: SettingsPanelView(service: service) { [weak self] in self?.unlock() })
        host.sizingOptions = []
        panel.contentView = host
        NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.menuTracking = true }
        }
        NotificationCenter.default.addObserver(forName: NSMenu.didEndTrackingNotification, object: nil, queue: .main) { [weak self] _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { MainActor.assumeIsolated { self?.menuTracking = false } }
        }
    }

    func show() {
        if !panel.isVisible {
            place()
            installMonitors()
        }
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        // Locked: ask for Touch ID right away, like the command panel. Return is the retry.
        if service.phase == .locked { unlock() }
    }

    func hide() {
        guard panel.isVisible else { return }
        removeMonitors()
        panel.orderOut(nil)
    }

    private func unlock() {
        guard service.phase == .locked, !authenticating else { return }
        authenticating = true
        Task {
            defer {
                authenticating = false
                if panel.isVisible { panel.makeKeyAndOrderFront(nil) }
            }
            do { try await service.unlock(reason: "Unlock your box to change its settings") }
            catch KeyStoreError.userCancelled {}
            catch BiometricGate.Failure.denied {}
            catch { Toast.shared.show(describe(error), isError: true) }
        }
    }

    /// Centred on the display that has the pointer, raised a little like the command panel's default spot.
    private func place() {
        let size = SettingsLayout.size
        guard let screen = NSScreen.screens.first(where: { $0.frame.contains(NSEvent.mouseLocation) }) ?? NSScreen.main else { return }
        let vf = screen.visibleFrame
        let y = min(vf.midY - size.height / 2 + vf.height * 0.06, vf.maxY - size.height)
        panel.setFrame(NSRect(x: vf.midX - size.width / 2, y: max(y, vf.minY), width: size.width, height: size.height), display: false)
    }

    /// A sheet, a save panel, an open menu or the Touch ID prompt is up: none of them is the person leaving Settings.
    private var busy: Bool { menuTracking || authenticating || panel.attachedSheet != nil || NSApp.modalWindow != nil }

    private func installMonitors() {
        removeMonitors()
        let mouse: NSEvent.EventTypeMask = [.leftMouseDown, .rightMouseDown, .otherMouseDown]
        // Clicks in Bisel's other windows (the set-up window, a toast) outside the card.
        if let m = NSEvent.addLocalMonitorForEvents(matching: mouse, handler: { [weak self] e in
            nonisolated(unsafe) let e = e
            MainActor.assumeIsolated {
                guard let self, !self.busy, e.window !== self.panel, e.window?.sheetParent !== self.panel,
                      !self.panel.frame.contains(NSEvent.mouseLocation) else { return }
                self.hide()
            }
            return e
        }) { monitors.append(m) }
        if let m = NSEvent.addLocalMonitorForEvents(matching: .keyDown, handler: { [weak self] e in
            nonisolated(unsafe) let e = e
            let consumed = MainActor.assumeIsolated { self?.handle(e) ?? false }
            return consumed ? nil : e
        }) { monitors.append(m) }
        // Clicks in other apps, the desktop or the Dock bring another app to the front.
        observers.append(NotificationCenter.default.addObserver(forName: NSApplication.didResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { if let self, !self.busy { self.hide() } }
        })
        observers.append(NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.activeSpaceDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.hide() }
        })
    }

    private func removeMonitors() {
        monitors.forEach { NSEvent.removeMonitor($0) }
        monitors = []
        for o in observers {
            NotificationCenter.default.removeObserver(o)
            NSWorkspace.shared.notificationCenter.removeObserver(o)
        }
        observers = []
    }

    /// Esc closes (the shortcut recorder keeps its own Esc while recording); Return unlocks a locked box. Returns true
    /// when the event was consumed.
    private func handle(_ event: NSEvent) -> Bool {
        guard event.window === panel, panel.attachedSheet == nil else { return false }
        let mods = event.modifierFlags.intersection(.deviceIndependentFlagsMask).subtracting([.capsLock, .numericPad, .function])
        switch event.keyCode {
        case 53:  // esc
            if let editor = panel.firstResponder as? NSTextView, String(describing: type(of: editor.delegate as Any)).contains("Recorder") { return false }
            hide()
            return true
        case 36 where mods.isEmpty && service.phase == .locked, 76 where mods.isEmpty && service.phase == .locked:  // return, keypad enter
            unlock()
            return true
        case 13 where mods == [.command]:  // ⌘W
            hide()
            return true
        default:
            return false
        }
    }

    #if DEBUG
    /// Bitmap of the card's SwiftUI content. The behind-window blur is not in it (see `CommandPanelController.debugSnapshot`).
    func debugSnapshot(to path: String) {
        guard let view = panel.contentView, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
        Log.app.notice("settings snapshot written")
    }
    #endif
}

/// Borderless, floating, and able to become key so its fields and recorder take typing.
private final class SettingsPanel: NSPanel {
    init() {
        super.init(contentRect: NSRect(origin: .zero, size: SettingsLayout.size), styleMask: [.borderless], backing: .buffered, defer: true)
        isFloatingPanel = true
        level = .floating
        collectionBehavior = [.fullScreenAuxiliary, .moveToActiveSpace]
        hidesOnDeactivate = false
        isOpaque = false
        backgroundColor = .clear
        hasShadow = false   // like the command panel: one 1 pt border, no shadow
        isMovableByWindowBackground = false
        sharingType = .readOnly   // nothing is hidden from screenshots; sensitive values are masked in the UI instead
        animationBehavior = .none
        isReleasedWhenClosed = false
    }

    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
    override func cancelOperation(_ sender: Any?) { /* Esc is handled by the controller's key monitor */ }
}

/// The card: the command panel's fill, radius and border, holding the settings, or the panel's locked state.
private struct SettingsPanelView: View {
    let service: VaultService
    let unlock: () -> Void
    @State private var themes = ThemeStore.shared
    @State private var a11y = AccessibilityStore.shared

    var body: some View {
        let theme = themes.current.adjusted(for: a11y.preferences)
        SettingsCardSurface(service: service, unlock: unlock)
            .panelMaterial()
            .environment(\.theme, theme)
            .environment(\.accessibilityPreferences, a11y.preferences)
            // AppKit controls (pickers, switches, the recorder) take the window's appearance, not SwiftUI's color scheme.
            .background(WindowAccessor { $0.appearance = NSAppearance(named: theme.appearance == .dark ? .darkAqua : .aqua) })
    }
}

private struct SettingsCardSurface: View {
    let service: VaultService
    let unlock: () -> Void
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: theme.radii.card, style: .continuous)
        ZStack {
            if service.phase == .locked {
                BoxLockedState(unlock: unlock).transition(.opacity)
            } else {
                SettingsShell(service: service).transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: service.phase == .locked)
        .frame(width: SettingsLayout.size.width, height: SettingsLayout.size.height)
        .background { CardFill() }
        .clipShape(shape)
        .overlay(shape.strokeBorder(theme.borderColor(glass: glass), lineWidth: theme.card.hairline).allowsHitTesting(false))
        .themedPage(theme, opaque: false)
        .environment(\.colorScheme, theme.colorScheme)
    }
}
