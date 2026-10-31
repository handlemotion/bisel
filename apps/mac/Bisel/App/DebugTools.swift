#if DEBUG
import AppKit

/// DEBUG-ONLY verification aids. Compiled out of Release. Nothing here runs on a normal launch: everything is
/// opt-in through an explicit environment variable or the "Debug:" menu item.
enum DebugTools {
    /// Debug builds: a distributed notification `app.bisel.dev.snapshot` (userInfo `path`) writes a PNG of the main window's
    /// contents rendered in-process (works with the screen locked or the window behind others). Never compiled into Release.
    /// BISEL_DEV_TOUR=1: creates a box, waits for the recovery phrase screen to settle, then presses Back (discards it), so
    /// the transitions can be captured from outside. Throwaway stores only.
    @MainActor
    static func runOnboardingTourIfRequested(_ service: VaultService) {
        guard ProcessInfo.processInfo.environment["BISEL_DEV_TOUR"] != nil else { return }
        Task {
            try? await Task.sleep(for: .seconds(4))
            try? await service.createBoxOnThisMacOnly(deviceName: "tour")
            try? await Task.sleep(for: .seconds(4))
            if ProcessInfo.processInfo.environment["BISEL_DEV_TOUR"] == "continue" {
                NotificationCenter.default.post(name: .init("app.bisel.dev.tour.continue"), object: nil)   // MainWindowView presses Continue
                return
            }
            await service.discardNewBox()
        }
    }

    @MainActor
    static func installSnapshotListener() {
        // `app.bisel.dev.snapshot.<pid>` reaches one process when several debug builds run at once.
        for name in ["app.bisel.dev.snapshot", "app.bisel.dev.snapshot.\(getpid())"] {
            DistributedNotificationCenter.default().addObserver(forName: Notification.Name(name), object: nil, queue: .main) { note in
                guard let path = note.userInfo?["path"] as? String else { return }
                MainActor.assumeIsolated {
                    guard let w = NSApp.windows.first(where: { $0.title.hasPrefix("Bisel") && $0.isVisible && !($0 is NSPanel) }),
                          let v = w.contentView, let rep = v.bitmapImageRepForCachingDisplay(in: v.bounds) else {
                        Log.app.notice("snapshot: no main window"); return
                    }
                    v.cacheDisplay(in: v.bounds, to: rep)
                    try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
                    Log.app.notice("snapshot written")
                }
            }
        }
    }

    /// Gives you 3 s to focus a field in another app, then logs how the fill engine classifies it
    /// (role/subrole/kind only; never text). Read with:  log stream --predicate 'subsystem == "app.bisel.mac"'
    @MainActor
    static func logFocusedFieldAfterDelay() {
        Task {
            try? await Task.sleep(for: .seconds(3))
            guard let app = NSWorkspace.shared.frontmostApplication else { return }
            let f = await Task.detached { () -> FocusedField in
                AccessibilityInspector.enableChromiumAccessibilityIfNeeded(app: app)
                return AccessibilityInspector.focusedField(of: app)
            }.value
            Log.fill.notice("DEBUG inspect \(app.bundleIdentifier ?? "?", privacy: .public): \(f.describe, privacy: .public)")
        }
    }

    /// Scripted run of the real panel code path for headless verification.
    ///   BISEL_DEV_TARGET=<bundle id>   bring that app to the front first (stands in for "the app you were using")
    ///   BISEL_DEV_AUTOPILOT=<delay>:<query>:<plain|option|copy|actions|none>
    ///   BISEL_DEV_SNAPSHOT=<png path>  bitmap of the panel after results appear (+ ".<n>.png" per BISEL_DEV_MOVES)
    ///   BISEL_DEV_MOVES="3,5"          move the selection to those indexes (what ↓ does) and snapshot each
    ///   BISEL_DEV_QUERIES="a|b|c" + BISEL_DEV_QUERYLOG=<path>   write the observed result order per query
    /// It calls `CommandPanelController.show()` (what the hotkey calls) and `CommandPanelModel` methods (what the
    /// keys call). It does NOT exercise the global hotkey or the key monitor.
    @MainActor
    static func runAutopilotIfRequested() {
        let env = ProcessInfo.processInfo.environment
        guard let spec = env["BISEL_DEV_AUTOPILOT"] else { return }
        Log.app.fault("BISEL_DEV_AUTOPILOT active (debug build only)")
        let parts = spec.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        let delay = Double(parts.first ?? "3") ?? 3
        let query = parts.count > 1 ? parts[1] : ""
        let plan = parts.count > 2 ? parts[2] : "plain"
        Task {
            if let id = env["BISEL_DEV_TARGET"] {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
                p.arguments = ["-b", id]
                try? p.run()
                try? await Task.sleep(for: .seconds(1.5))
            }
            try? await Task.sleep(for: .seconds(delay))
            let c = AppModel.shared.panelController
            let m = AppModel.shared.panelModel
            c.show()
            if env["BISEL_DEV_BACKDROP"] == "1" { showBusyBackdrop(behind: c.debugPanel.frame) }
            try? await Task.sleep(for: .milliseconds(400))
            let snap = env["BISEL_DEV_SNAPSHOT"]
            if let snap { c.debugSnapshot(to: snap + ".open.png") }

            if let qs = env["BISEL_DEV_QUERIES"], let outPath = env["BISEL_DEV_QUERYLOG"] {
                var out = ""
                for q in qs.split(separator: "|", omittingEmptySubsequences: false).map(String.init) {
                    m.query = q
                    let titles = m.results.prefix(10).map { r in "\(r.title) [\(r.domain)]" }
                    out += "QUERY \"\(q)\" -> \(m.results.count) results, selected=\(m.selected)\n  " + titles.joined(separator: "\n  ") + "\n"
                }
                try? out.write(toFile: outPath, atomically: true, encoding: .utf8)
            }

            m.query = query
            try? await Task.sleep(for: .milliseconds(800))
            Log.panel.notice("autopilot: window=\(NSStringFromRect(c.debugPanel.frame), privacy: .public) key=\(c.debugIsKey) frontmost=\(NSWorkspace.shared.frontmostApplication?.bundleIdentifier ?? "?", privacy: .public) results=\(m.results.count) selected=\(m.selected)")
            if let snap { c.debugSnapshot(to: snap) }
            if let moves = env["BISEL_DEV_MOVES"], let snap {
                for n in moves.split(separator: ",").compactMap({ Int($0) }) {
                    m.moveSelection(n - m.selected)
                    try? await Task.sleep(for: .milliseconds(500))
                    c.debugSnapshot(to: snap + ".sel\(n).png")
                }
            }
            // BISEL_DEV_ROLL=1: snapshot every 2 s from 4 s before the next 30 s boundary to 8 s after it.
            if env["BISEL_DEV_ROLL"] == "1", let snap {
                let now = Date().timeIntervalSince1970
                let toBoundary = 30 - now.truncatingRemainder(dividingBy: 30)
                try? await Task.sleep(for: .seconds(max(toBoundary - 4, 0)))
                for i in 0..<7 {
                    c.debugSnapshot(to: snap + ".roll\(i).png")
                    try? await Task.sleep(for: .seconds(2))
                }
            }
            // BISEL_DEV_CLICKLOOP=N: N rounds of mouse-downs (through NSApp.sendEvent, so local monitors run) on the search
            // field, list rows, the detail pane's empty area, the border and the Values label column; panel must stay open.
            if let n = env["BISEL_DEV_CLICKLOOP"].flatMap(Int.init) {
                let h = c.debugPanel.contentView?.bounds.height ?? 460
                let pts: [(String, NSPoint)] = [
                    ("search", NSPoint(x: 120, y: h - 24)), ("row0", NSPoint(x: 100, y: h - 73)), ("row2", NSPoint(x: 100, y: h - 171)),
                    ("row4", NSPoint(x: 100, y: h - 269)), ("detailEmpty", NSPoint(x: 600, y: 30)), ("border", NSPoint(x: 1, y: 200)),
                    ("listEmptyBelow", NSPoint(x: 130, y: 2)), ("title", NSPoint(x: 400, y: h - 130)),
                ]
                var unintended = 0, clicks = 0
                for round in 0..<n {
                    if !c.isVisible { c.show(); try? await Task.sleep(for: .milliseconds(350)) }
                    for (name, p) in pts {
                        let ev = NSEvent.mouseEvent(with: .leftMouseDown, location: p, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                                    windowNumber: c.debugPanel.windowNumber, context: nil, eventNumber: round * 100 + clicks, clickCount: 1, pressure: 1)
                        if let ev { NSApp.sendEvent(ev) }
                        clicks += 1
                        try? await Task.sleep(for: .milliseconds(40))
                        if !c.isVisible { unintended += 1; Log.panel.notice("CLICKLOOP unintended close after \(name, privacy: .public) round \(round)") ; c.show(); try? await Task.sleep(for: .milliseconds(350)) }
                    }
                }
                Log.panel.notice("CLICKLOOP done: clicks=\(clicks) unintendedCloses=\(unintended)")
            }
            // BISEL_DEV_CLICKROW=n: click the center of list row n through model.click(at:) (must only select).
            if let n = env["BISEL_DEV_CLICKROW"].flatMap(Int.init) {
                let before = NSPasteboard.general.changeCount
                let y = m.listFrame.minY + 24.5 + Double(n) * m.rowPitch - m.scrollOffset
                let handled = m.click(at: CGPoint(x: m.listFrame.midX, y: y))
                try? await Task.sleep(for: .milliseconds(400))
                Log.panel.notice("autopilot click row \(n): handled=\(handled) selected=\(m.selected) panelVisible=\(c.isVisible) pasteboardChanged=\(NSPasteboard.general.changeCount != before)")
            }
            // BISEL_DEV_CLICKVALUE=username|otp|password|website: push a click at the CENTER of that row's tracked frame
            // through the same entry point a real mouse-down uses (CommandPanel.sendEvent -> model.click(at:)).
            if let name = env["BISEL_DEV_CLICKVALUE"], let row = ValueRowID(rawValue: name), let fr = m.valueFrames[row] {
                Log.panel.notice("autopilot click at value row \(name, privacy: .public) frame=\(NSStringFromRect(fr), privacy: .public)")
                _ = m.click(at: CGPoint(x: fr.midX, y: fr.midY))
                // Frames of the copy confirmation: +40, +100, +200, +400 ms.
                var last = 0
                for ms in [40, 100, 200, 400] {
                    try? await Task.sleep(for: .milliseconds(ms - last)); last = ms
                    if let snap { c.debugSnapshot(to: snap + ".click-\(name)-\(ms)ms.png") }
                }
            }
            // BISEL_DEV_VALUES="username,otp,otp": click those Values rows (model.activateValue) and snapshot each.
            if let vals = env["BISEL_DEV_VALUES"], let snap {
                for (i, name) in vals.split(separator: ",").map(String.init).enumerated() {
                    if name == "hover-username" { m.hoveredValue = .username }
                    else if let row = ValueRowID(rawValue: name) { m.activateValue(row) }
                    try? await Task.sleep(for: .milliseconds(450))
                    c.debugSnapshot(to: snap + ".val\(i)-\(name).png")
                }
            }
            closeBusyBackdrop()  // never leave the debug window on screen
            switch plan {
            case "plain": m.activate(.plain)
            case "option": m.activate(.option)
            case "copy": m.activate(.command)
            case "actions":
                m.toggleActions()
                try? await Task.sleep(for: .milliseconds(400))
                if let snap { c.debugSnapshot(to: snap + ".actions.png") }
            default: break
            }
        }
    }
}

@MainActor private var backdropWindow: NSWindow?
@MainActor func closeBusyBackdrop() { backdropWindow?.orderOut(nil); backdropWindow = nil }

/// A deliberately busy window (large lorem-ipsum text over saturated stripes) placed behind the panel to judge
/// translucency. Own-process window; only created when BISEL_DEV_BACKDROP=1 and closed when the run ends.
@MainActor
private func showBusyBackdrop(behind f: NSRect) {
    let r = f.insetBy(dx: -60, dy: -40)
    let w = NSWindow(contentRect: r, styleMask: [.borderless], backing: .buffered, defer: false)
    w.level = .normal
    w.isReleasedWhenClosed = false
    w.backgroundColor = .systemOrange
    let host = NSView(frame: NSRect(origin: .zero, size: r.size))
    for i in 0..<14 {
        let t = NSTextField(labelWithString: "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor \(i)")
        t.font = .boldSystemFont(ofSize: 24)
        t.textColor = i % 2 == 0 ? .black : .white
        t.frame = NSRect(x: 0, y: CGFloat(i) * 40, width: r.width, height: 30)
        host.addSubview(t)
    }
    for i in 0..<12 {
        let v = NSView(frame: NSRect(x: CGFloat(i) * 80, y: 0, width: 30, height: r.height))
        v.wantsLayer = true
        v.layer?.backgroundColor = (i % 2 == 0 ? NSColor.black : NSColor.systemYellow).withAlphaComponent(0.7).cgColor
        host.addSubview(v)
    }
    w.contentView = host
    w.orderFront(nil)
    backdropWindow = w
}

extension CommandPanelController {
    var debugIsKey: Bool { debugPanel.isKeyWindow }

    /// Bitmap of the panel's SwiftUI content (tint/rows/text). The system blur layer is NOT in it (window-server
    /// composition cannot be captured from inside the app without Screen Recording permission).
    func debugSnapshot(to path: String) {
        guard let view = debugPanel.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        if let png = rep.representation(using: .png, properties: [:]) {
            try? png.write(to: URL(fileURLWithPath: path))
            Log.panel.notice("view snapshot written \(view.bounds.width)x\(view.bounds.height)")
        }
    }
}
#endif
