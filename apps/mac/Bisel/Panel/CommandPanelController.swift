import AppKit
import KeyboardShortcuts
import SwiftUI

extension KeyboardShortcuts.Name {
    /// ⌘⇧Space by default; user-configurable in Settings.
    static let commandPanel = Self("commandPanel", initial: .init(.space, modifiers: [.command, .shift]))
}

/// Owns the panel, the global hotkey, and the in-panel key handling.
@MainActor
final class CommandPanelController {
    let model: CommandPanelModel
    private let panel = CommandPanel()
    #if DEBUG
    var debugPanel: NSPanel { panel }
    var debugHost: NSView { host }
    /// Verification drivers run the panel invisibly: fully transparent and click-through, so a run never flashes on the
    /// user's screen. (Window server still treats it as shown, so layout, timing and monitors are the real ones.)
    var debugStealth = false
    #endif
    /// True while the Touch ID sheet is up: it takes key from the panel, which must not read as "click away".
    var authenticating = false {
        // The sheet took key; give it back so typing goes to the search field once it is gone.
        didSet { if oldValue, !authenticating, state == .shown { panel.makeKeyAndOrderFront(nil) } }
    }
    private var stealth: Bool {
        #if DEBUG
        debugStealth
        #else
        false
        #endif
    }
    private let host: NSHostingView<AnyView>
    private var keyMonitor: Any?
    private var target: NSRunningApplication?
    private var openedAt: ContinuousClock.Instant?
    private let themeStore: ThemeStore
    private let accessibilityStore: AccessibilityStore

    init(model: CommandPanelModel, themeStore: ThemeStore = .shared, accessibilityStore: AccessibilityStore = .shared) {
        self.model = model
        self.themeStore = themeStore
        self.accessibilityStore = accessibilityStore
        // A borderless panel has no title bar, but assistive technologies still name the window by its title.
        panel.title = String(localized: "Bisel command panel")
        panel.setAccessibilityLabel(String(localized: "Bisel command panel"))
        host = NSHostingView(rootView: AnyView(EmptyView()))
        host.sizingOptions = []
        panel.contentView = host
        // A native menu ("···") is open: its clicks land outside the card and must not dismiss the panel.
        NotificationCenter.default.addObserver(forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.menuTracking = true }
        }
        NotificationCenter.default.addObserver(forName: NSMenu.didEndTrackingNotification, object: nil, queue: .main) { [weak self] _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { MainActor.assumeIsolated { self?.menuTracking = false } }
        }
        panel.onResignKey = { [weak self] in
            // Defer one turn: a spurious resign while the panel is still becoming key must not close it.
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    guard let self, self.state == .shown, !self.panel.isKeyWindow, !self.menuTracking, !self.authenticating,
                          ContinuousClock.now - self.shownAt > .milliseconds(150) else { return }
                    self.hide("resignKey")
                }
            }
        }
        panel.handleMouseDown = { [weak self] p in
            guard let self else { return .passThrough }
            return MainActor.assumeIsolated {
                self.state == .shown && self.model.click(at: self.topLeftPoint(fromWindow: p)) ? .consumed : .passThrough
            }
        }
        renderRoot()
        KeyboardShortcuts.onKeyDown(for: .commandPanel) { [weak self] in self?.toggle() }
        trackTheme()
        #if DEBUG
        PanelDebugDriver.startIfRequested(controller: self)
        #endif
        model.resetPosition = { [weak self] in self?.resetDragOffset() }
        panel.onDragBegan = { [weak self] in MainActor.assumeIsolated { self?.beginDrag() } }
        panel.dragFilter = { [weak self] p in MainActor.assumeIsolated { self?.filterDrag(p) ?? p } }
        panel.onDragEnded = { [weak self] in MainActor.assumeIsolated { self?.endDrag() } }
        NotificationCenter.default.addObserver(forName: NSWindow.didMoveNotification, object: panel, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.panelMoved() }
        }
        #if DEBUG
        NotificationCenter.default.addObserver(forName: NSWindow.didResizeNotification, object: panel, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { Log.panel.notice("DID RESIZE -> \(NSStringFromRect(self?.panel.frame ?? .zero), privacy: .public) content=\(NSStringFromRect(self?.panel.contentView?.frame ?? .zero), privacy: .public) \(Thread.callStackSymbols.prefix(14).joined(separator: " | "), privacy: .public)") }
        }
        #endif
    }

    // MARK: show / hide state machine

    /// hidden → shown → hiding → hidden. One place decides; every dismissal path funnels into `hide(_:)`.
    private enum State { case hidden, shown, hiding }
    private var state: State = .hidden
    private var hideWork: DispatchWorkItem?
    private var confirmWork: DispatchWorkItem?
    private var monitors: [Any] = []
    private var observers: [NSObjectProtocol] = []
    private var shownAt: ContinuousClock.Instant = .now
    private var menuTracking = false

    var isVisible: Bool { state != .hidden }

    @MainActor static var reduceMotion: Bool { AccessibilityStore.shared.preferences.reduceMotion }

    /// Open/close animations are off: the panel appears and disappears instantly. Flip to bring them back.
    static let animated = false

    func toggle() { state == .shown ? hide("hotkey") : show() }

    func show() {
        hideWork?.cancel(); hideWork = nil
        confirmWork?.cancel(); confirmWork = nil
        if state == .shown { return }
        removeMonitors()
        openedAt = ContinuousClock.now
        let front = NSWorkspace.shared.frontmostApplication
        target = (front?.processIdentifier == ProcessInfo.processInfo.processIdentifier) ? nil : front
        FillEngine.shared.warmUp(target: target)

        themeStore.reload()
        // Fully reset BEFORE the window can be seen: no stale query/results/selection/confirmation, and the content
        // starts in its "not presented" (scaled, transparent) state so nothing flashes.
        model.reset(targetName: target?.localizedName)
        clearEditingHistory()
        model.presented = true  // instant open: no animation (user preference, like Raycast)
        renderRoot()
        if !trackingAccessTab { trackAccessTab() }
        layoutPanel(animated: false, reposition: true)
        panel.ignoresMouseEvents = false
        #if DEBUG
        panel.alphaValue = debugStealth ? 0 : 1
        if debugStealth { panel.ignoresMouseEvents = true }
        #endif
        host.layoutSubtreeIfNeeded()
        panel.displayIfNeeded()
        state = .shown
        shownAt = .now
        installMonitors()
        startPointerTracking()
        panel.makeKeyAndOrderFront(nil)
        // Locked: ask for Touch ID right away (no set-up yet: go straight to set-up). Return stays as the retry.
        if !model.isUnlocked, !stealth { model.runUnlock?() }
        Log.panel.notice("STATE shown (visible=\(self.panel.isVisible) key=\(self.panel.isKeyWindow))")
        // Next runloop turn: animate to presented (ease in from the anchor).
        DispatchQueue.main.async { [weak self] in
            guard let self, self.state == .shown else { return }
            if let t = self.openedAt {
                Log.panel.notice("panel shown in \((ContinuousClock.now - t).ms, format: .fixed(precision: 1)) ms with \(self.model.results.count) results")
            }
        }
    }

    /// Every dismissal path calls this: Esc, hotkey, outside click (global/local), app switch, Space change, key loss,
    /// fill/copy completion. Idempotent; cancels a pending confirmation; a later `show()` cancels the hide.
    func hide(_ reason: String, immediate: Bool = false) {
        guard state == .shown else { return }
        #if DEBUG
        if reason == "resignKey", ProcessInfo.processInfo.environment["BISEL_DEV_STICKY"] == "1" { return }
        #endif
        Log.panel.notice("STATE hide reason=\(reason, privacy: .public) hoverStats=\(self.model.hoverStats.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ","), privacy: .public)")
        model.hoverStats = [:]
        state = .hiding
        confirmWork?.cancel(); confirmWork = nil
        removeMonitors()
        stopPointerTracking()
        if immediate || !Self.animated {
            // Instant dismiss (also the fill path): the window must be gone before keystrokes are synthesized into the target app.
            model.presented = false
            panel.orderOut(nil)
            state = .hidden
            model.reset(targetName: nil)
            clearEditingHistory()
            Log.panel.notice("STATE hidden (immediate)")
            return
        }
        withAnimation(Self.reduceMotion ? .easeIn(duration: 0.08) : .snappy(duration: 0.11, extraBounce: 0)) { model.presented = false }
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.state == .hiding else { return }
            self.panel.orderOut(nil)
            self.state = .hidden
            self.model.reset(targetName: nil)  // clear everything while hidden: next show cannot flash old state
            Log.panel.notice("STATE hidden")
        }
        hideWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.12, execute: work)
    }

    /// The search field's undo stack would otherwise grow with every edit for the life of the app (and keep what was
    /// typed in memory). A fresh panel has nothing to undo.
    private func clearEditingHistory() {
        (panel.fieldEditor(false, for: nil) as? NSTextView)?.undoManager?.removeAllActions()
        panel.undoManager?.removeAllActions()
    }

    func hide() { hide("api") }

    /// After a successful copy the Values row shows "✓ Copied" for ~0.5 s; then the panel dismisses (fast animation).
    func hideAfterCopy() {
        guard state == .shown else { return }
        confirmWork?.cancel()
        hide("copied")  // instant: shortcut copies close the panel immediately, no confirmation delay
    }

    // MARK: dismissal monitors

    /// True when a screen point lies outside the panel's final (non-animating) frame. The window is fixed-size, so
    /// `panel.frame` is the final frame; the content's scale animation never changes it.
    private func isOutside(_ screenPoint: NSPoint) -> Bool { !panel.frame.contains(screenPoint) }

    private func installMonitors() {
        removeMonitors()
        let mouse: NSEvent.EventTypeMask = [.leftMouseDown, .rightMouseDown, .otherMouseDown]
        // Clicks in OTHER apps, the desktop, the menu bar and the Dock never reach this app: global monitor.
        if let g = NSEvent.addGlobalMonitorForEvents(matching: mouse, handler: { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, !self.menuTracking, self.isOutside(NSEvent.mouseLocation) else { return }
                self.hide("outsideClick")
            }
        }) { monitors.append(g) }
        // Clicks in this app's own other windows (main window, toast): local monitor; clicks inside the panel stay.
        if let l = NSEvent.addLocalMonitorForEvents(matching: mouse, handler: { [weak self] e in
            nonisolated(unsafe) let e = e
            MainActor.assumeIsolated {
                // Own windows other than the panel (main window, toast). Judged by pointer position against the panel's
                // fixed screen frame, never by event.window or an animating frame.
                if let self, !self.menuTracking, e.window !== self.panel, self.isOutside(NSEvent.mouseLocation) { self.hide("outsideClickLocal") }
            }
            return e
        }) { monitors.append(l) }
        // The list only scrolls vertically: strip any horizontal component from trackpad scrolls over the panel so
        // the rows can't be pushed left or right.
        if let sc = NSEvent.addLocalMonitorForEvents(matching: .scrollWheel, handler: { [weak self] e in
            nonisolated(unsafe) let e = e
            nonisolated(unsafe) var out: NSEvent? = e
            MainActor.assumeIsolated {
                guard let self, e.window === self.panel, e.scrollingDeltaX != 0, let cg = e.cgEvent?.copy() else { return }
                cg.setIntegerValueField(.scrollWheelEventDeltaAxis2, value: 0)
                cg.setIntegerValueField(.scrollWheelEventPointDeltaAxis2, value: 0)
                cg.setDoubleValueField(.scrollWheelEventFixedPtDeltaAxis2, value: 0)
                out = NSEvent(cgEvent: cg) ?? e
            }
            return out
        }) { monitors.append(sc) }
        installKeyMonitor()
        let ws = NSWorkspace.shared.notificationCenter
        observers.append(ws.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main) { [weak self] n in
            let app = n.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
            MainActor.assumeIsolated {
                // The Touch ID sheet is its own process and comes to the front: not a switch either.
                guard let self, let app, !self.authenticating, app.processIdentifier != ProcessInfo.processInfo.processIdentifier,
                      app.processIdentifier != self.target?.processIdentifier else { return }  // bisel itself / the app we are filling: not a switch
                Log.panel.notice("frontmost app changed to \(app.bundleIdentifier ?? "?", privacy: .private)")
                self.hide("appActivated")
            }
        })
        observers.append(ws.addObserver(forName: NSWorkspace.activeSpaceDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.hide("spaceChanged") }
        })
        // The panel shows secrets: never leave it up across sleep, a sleeping display or a fast-user switch.
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            observers.append(ws.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.hide("sleepOrSessionChange") }
            })
        }
        // A display was added, removed or rearranged while the panel is up: put it back on a screen that exists.
        screenObserver = NotificationCenter.default.addObserver(forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.state == .shown else { return }
                self.layoutPanel(animated: false, reposition: true)
            }
        }
    }

    private var screenObserver: NSObjectProtocol?

    private func removeMonitors() {
        monitors.forEach { NSEvent.removeMonitor($0) }
        monitors = []
        observers.forEach { NSWorkspace.shared.notificationCenter.removeObserver($0) }
        observers = []
        if let o = screenObserver { NotificationCenter.default.removeObserver(o) }
        screenObserver = nil
        removeKeyMonitor()
    }

    // MARK: pointer

    /// Hover is driven by polling the global pointer position (~30 Hz, only while the panel is visible) instead of
    /// tracking areas: the panel never activates the app, and tracking-area / SwiftUI `.onHover` delivery for an
    /// inactive app's non-activating panel proved unreliable. Selection changes only when the pointer actually
    /// moved, so keyboard scrolling under a resting pointer never steals the selection.
    private var pointerTimer: Timer?
    private var lastPointer = NSPoint(x: -1, y: -1)

    private func startPointerTracking() {
        stopPointerTracking()
        lastPointer = NSEvent.mouseLocation
        let t = Timer(timeInterval: 1.0 / 30.0, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.pollPointer() }
        }
        RunLoop.main.add(t, forMode: .common)
        pointerTimer = t
    }

    private func stopPointerTracking() { pointerTimer?.invalidate(); pointerTimer = nil }

    private func pollPointer() {
        #if DEBUG
        if ProcessInfo.processInfo.environment["BISEL_DEV_NOHOVER"] == "1" { return }
        #endif
        let p = NSEvent.mouseLocation
        guard p != lastPointer else { return }
        lastPointer = p
        guard state == .shown, panel.frame.contains(p) else { return }
        model.hover(at: topLeftPoint(fromWindow: panel.convertPoint(fromScreen: p)))
    }

    /// Window coordinates (bottom-left origin) → SwiftUI "panelRoot" space (top-left origin).
    private func topLeftPoint(fromWindow p: NSPoint) -> CGPoint {
        CGPoint(x: p.x, y: (panel.contentView?.bounds.height ?? 0) - p.y)
    }

    /// The app that was frontmost when the panel opened (the fill target).
    var fillTarget: NSRunningApplication? { target }

    // MARK: rendering

    private var renderedTheme: Theme?
    private var renderedPreferences: AccessibilityPreferences?

    /// Installs the SwiftUI root for the current theme and accessibility switches. Skipped when neither changed: the
    /// hosted view graph (and its `@AppStorage` observers) then lives for the app's lifetime instead of being rebuilt on
    /// every show.
    private func renderRoot() {
        let prefs = accessibilityStore.preferences
        let theme = themeStore.current.adjusted(for: prefs)
        guard theme != renderedTheme || prefs != renderedPreferences else { return }
        renderedTheme = theme
        renderedPreferences = prefs
        host.rootView = AnyView(CommandPanelView(model: model)
            .environment(\.theme, theme)
            .environment(\.accessibilityPreferences, prefs))
        let name: NSAppearance.Name = switch (theme.appearance, prefs.increaseContrast) {
        case (.dark, true): .accessibilityHighContrastDarkAqua
        case (.dark, false): .darkAqua
        case (.light, true): .accessibilityHighContrastAqua
        case (.light, false): .aqua
        }
        panel.appearance = NSAppearance(named: name)
    }

    /// Re-renders when the theme (system light/dark, family) or a system accessibility switch changes, also while the
    /// panel is open.
    private func trackTheme() {
        withObservationTracking {
            _ = themeStore.current
            _ = accessibilityStore.preferences
        } onChange: { [weak self] in
            Task { @MainActor in
                self?.renderRoot()
                self?.trackTheme()
            }
        }
    }

    /// Fill turned on (or off) while the panel is up: the window gains or loses the tab's room. The trust poll writes every
    /// second, so only an actual height change lays the panel out again. Started from the first `show()`, not `init`
    /// (`AppModel.shared` is still being built then).
    private var trackingAccessTab = false
    private func trackAccessTab() {
        trackingAccessTab = true
        withObservationTracking {
            _ = AppModel.shared.accessibility.trusted
        } onChange: { [weak self] in
            Task { @MainActor in
                guard let self else { return }
                let theme = self.themeStore.current
                let want = theme.card.height + CommandPanelView.accessTabHeight(theme, trusted: AppModel.shared.accessibility.trusted)
                if self.state == .shown, self.panel.frame.height != want { self.layoutPanel(animated: false) }
                self.trackAccessTab()
            }
        }
    }

    /// The display that has the pointer, else the main one, else any; nil only while no display is attached.
    private static var screenUnderPointer: NSScreen? {
        NSScreen.screens.first { $0.frame.contains(NSEvent.mouseLocation) } ?? NSScreen.main ?? NSScreen.screens.first
    }

    /// Fixed-size card in a screen corner (setting `PanelPosition`), on the screen that has the mouse, inset by the
    /// spacing token from `visibleFrame` so it clears the Dock and the menu bar. The window never resizes.
    private func layoutPanel(animated: Bool, reposition: Bool = false) {
        let theme = themeStore.current
        // While Fill is off the window also holds the tab below the card; the card stays where it would be.
        let tab = CommandPanelView.accessTabHeight(theme, trusted: AppModel.shared.accessibility.trusted)
        let size = CGSize(width: theme.card.width, height: theme.card.height + tab)
        // No screen at all (every display asleep or mid-reconfiguration): keep the current frame; the screen-change
        // observer lays the panel out again as soon as one is back.
        guard let screen = Self.screenUnderPointer else { return }
        let vf = screen.visibleFrame
        let inset = theme.spacing.l
        let card = CGSize(width: theme.card.width, height: theme.card.height)
        let cardBase: CGPoint = switch PanelPosition.current {
        // Raycast-style: horizontally centered, card centre raised ~8% of the usable height above the screen centre.
        case .center: CGPoint(x: vf.midX - card.width / 2, y: vf.midY - card.height / 2 + vf.height * 0.08)
        case .bottomRight: CGPoint(x: vf.maxX - card.width - inset, y: vf.minY + inset)
        case .topRight: CGPoint(x: vf.maxX - card.width - inset, y: vf.maxY - card.height - inset)
        case .bottomCenter: CGPoint(x: vf.midX - card.width / 2, y: vf.minY + inset)
        }
        // At the bottom positions the card rises by the tab's height so the tab keeps the inset above the Dock.
        let base = CGPoint(x: cardBase.x, y: max(cardBase.y - tab, vf.minY + inset))
        baseOrigin = base
        panel.dragBarHeight = theme.card.topBarHeight
        panel.dragHandleWidth = theme.spacing.l + theme.card.searchIconBox + theme.spacing.xs
        let off = Self.dragOffset
        let origin = CGPoint(x: min(max(base.x + off.width, vf.minX), vf.maxX - size.width),
                             y: min(max(base.y + off.height, vf.minY), vf.maxY - size.height))
        laying = true
        panel.setFrame(NSRect(origin: origin, size: size), display: true, animate: false)
        laying = false
        Log.panel.notice("layout: want \(NSStringFromRect(NSRect(origin: origin, size: size)), privacy: .public) got \(NSStringFromRect(self.panel.frame), privacy: .public) screen=\(NSStringFromRect(vf), privacy: .public)")
    }

    // MARK: dragging

    /// Where `layoutPanel` last put the undragged card, and whether a programmatic move is in progress.
    private var baseOrigin: CGPoint = .zero
    private var laying = false

    static let dragKey = "panel.dragOffset"
    /// How far the user dragged the card from the position setting's spot (persisted, applied on every show).
    static var dragOffset: CGSize {
        guard let a = UserDefaults.standard.array(forKey: dragKey) as? [Double], a.count == 2 else { return .zero }
        return CGSize(width: a[0], height: a[1])
    }

    private func panelMoved() {
        guard !laying, state == .shown else { return }
        let off = CGSize(width: panel.frame.origin.x - baseOrigin.x, height: panel.frame.origin.y - baseOrigin.y)
        UserDefaults.standard.set([off.width, off.height], forKey: Self.dragKey)
    }

    /// Like Raycast: while dragging, guide lines mark the default spot (brighter the closer the card is) and the card
    /// locks onto it, with the guides turning blue and an alignment tick on the trackpad, when it comes close.
    private let guides = DragGuides()
    private var snapLocked = false

    private func beginDrag() {
        snapLocked = false
        guard let screen = panel.screen ?? Self.screenUnderPointer else { return }
        guides.show(on: screen, below: panel)
        updateGuides(origin: panel.frame.origin, locked: false)
    }

    private func filterDrag(_ proposed: NSPoint) -> NSPoint {
        let locked = hypot(proposed.x - baseOrigin.x, proposed.y - baseOrigin.y) <= Self.snapDistance
        if locked && !snapLocked {
            NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .now)
        }
        snapLocked = locked
        let origin = locked ? baseOrigin : proposed
        updateGuides(origin: origin, locked: locked)
        return origin
    }

    private func updateGuides(origin: NSPoint, locked: Bool) {
        let half = CGSize(width: panel.frame.width / 2, height: panel.frame.height / 2)
        guides.update(guide: CGPoint(x: baseOrigin.x + half.width, y: baseOrigin.y + half.height),
                      panelCenter: CGPoint(x: origin.x + half.width, y: origin.y + half.height),
                      locked: locked)
    }

    private func endDrag() {
        guides.hide()
        let dx = panel.frame.origin.x - baseOrigin.x, dy = panel.frame.origin.y - baseOrigin.y
        if hypot(dx, dy) < 0.5 { UserDefaults.standard.removeObject(forKey: Self.dragKey) }  // locked: back to the default
        snapLocked = false
    }
    static let snapDistance: CGFloat = 40

    private func resetDragOffset() {
        UserDefaults.standard.removeObject(forKey: Self.dragKey)
        layoutPanel(animated: false, reposition: true)
    }

    // MARK: keys

    private func installKeyMonitor() {
        removeKeyMonitor()
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            nonisolated(unsafe) let event = event  // delivered on the main thread
            let consumed = MainActor.assumeIsolated {
                guard let self, event.window === self.panel else { return false }
                return self.handle(event)
            }
            return consumed ? nil : event
        }
    }

    private func removeKeyMonitor() {
        if let m = keyMonitor { NSEvent.removeMonitor(m) }
        keyMonitor = nil
    }

    /// Returns true when the event was consumed.
    private func handle(_ event: NSEvent) -> Bool {
        if let tv = panel.firstResponder as? NSTextView, tv.hasMarkedText() { return false }  // IME composing
        let mods = event.modifierFlags.intersection(.deviceIndependentFlagsMask).subtracting([.capsLock, .numericPad, .function])
        switch event.keyCode {
        case 53:  // esc: leave actions → clear query → close
            if model.escape() { hide("esc") }
            return true
        case 125: model.moveSelection(1); return true  // down
        case 126: model.moveSelection(-1); return true  // up
        case 36, 76:  // return, keypad enter
            if mods == [.command] { model.activate(.command) }
            else if mods == [.option] { model.activate(.option) }
            else if mods == [.shift] { model.activate(.shift) }
            else if mods == [.command, .option] { model.activate(.commandOption) }
            else if mods.isEmpty { model.activate(.plain) }
            else { return false }
            return true
        case 43 where mods == [.command]:  // ⌘,
            model.runOpenSettings?(.general)
            return true
        case 40 where mods == [.command]:  // ⌘K
            model.toggleActions()
            return true
        case 45 where mods == [.control], 38 where mods == [.control]:  // ⌃N / ⌃J
            model.moveSelection(1); return true
        case 35 where mods == [.control], 40 where mods == [.control]:  // ⌃P / ⌃K
            model.moveSelection(-1); return true
        default:
            return false
        }
    }
}

/// Where the panel card sits. Setting in Settings → Command panel.
enum PanelPosition: String, CaseIterable, Identifiable {
    case center, bottomCenter, topRight, bottomRight
    var id: String { rawValue }
    var label: String {
        switch self {
        case .center: String(localized: "Center (slightly raised)")
        case .bottomRight: String(localized: "Bottom right")
        case .topRight: String(localized: "Top right")
        case .bottomCenter: String(localized: "Bottom center")
        }
    }
    static let defaultsKey = "panel.position"
    static var current: PanelPosition {
        UserDefaults.standard.string(forKey: defaultsKey).flatMap(PanelPosition.init(rawValue:)) ?? .center
    }
}

