#if DEBUG
import AppKit
import SwiftUI

/// DEBUG-ONLY: what a launch, the panel and the settings pages cost on a real box, measured inside one launch of the app
/// (AGENTS.md: never a launch loop, never UI automation). The panel runs invisible and click-through; the settings window is
/// transparent and never takes focus. It calls the entry points the hotkey and the key monitor call and synthesizes no events.
@MainActor
enum PanelBoxPerf {
    private static var samples: [String: [Double]] = [:]

    private static func record(_ label: String, _ ms: Double) { samples[label, default: []].append(ms) }

    /// Milliseconds since the kernel started this process, so what runs before `main` counts too.
    private static var sinceProcessStart: Double {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return -1 }
        let t = info.kp_proc.p_un.__p_starttime
        return (Date().timeIntervalSince1970 - (Double(t.tv_sec) + Double(t.tv_usec) / 1e6)) * 1000
    }

    static func mark(_ label: String) { record(label, sinceProcessStart) }

    /// One turn of the main queue, so SwiftUI's own update pass lands inside the time measured.
    private static func settle() async {
        await withCheckedContinuation { c in DispatchQueue.main.async { c.resume() } }
    }

    private static func timed(_ label: String, _ host: NSView, _ body: () -> Void) async {
        let t = ContinuousClock.now
        body()
        let model = ContinuousClock.now
        host.layoutSubtreeIfNeeded()
        let layout = ContinuousClock.now
        host.displayIfNeeded()
        let display = ContinuousClock.now
        await settle()
        let end = ContinuousClock.now
        record(label, (end - t).ms)
        record("\(label) · model", (model - t).ms)
        record("\(label) · layout", (layout - model).ms)
        record("\(label) · display", (display - layout).ms)
        record("\(label) · settle", (end - display).ms)
    }

    /// `BISEL_DEV_PERF_SOAK=<seconds>`: types and moves the selection for that long, for `sample <pid>` to attach to. A profiler on
    /// a steady loop shows what one keystroke costs; the run stays one launch.
    private static func soak(_ model: CommandPanelModel, _ host: NSView, seconds: Double, marker: String?) async {
        if let marker { FileManager.default.createFile(atPath: marker, contents: Data()) }
        let queries = ["g", "gi", "git", "gith", "githu", "github", "", "cl", "clo", "cloud", ""]
        let end = ContinuousClock.now + .seconds(seconds)
        var i = 0
        while ContinuousClock.now < end {
            await timed("soak.keystroke", host) { model.query = queries[i % queries.count] }
            await timed("soak.arrow", host) { model.moveSelection(1) }
            try? await Task.sleep(for: .milliseconds(1))
            i += 1
        }
    }

    private static func scrollView(in view: NSView) -> NSScrollView? {
        if let s = view as? NSScrollView, (s.documentView?.frame.height ?? 0) > s.contentSize.height { return s }
        for sub in view.subviews { if let s = scrollView(in: sub) { return s } }
        return nil
    }

    /// A jump that is fast and lands nowhere is no result: the row must be there and inside the list.
    private static func onScreen(_ model: CommandPanelModel, row: Int) -> Bool {
        guard let frame = model.rowFrames["row.\(row)"] ?? model.rowFrames[model.results[row].id] else { return false }
        return model.listFrame.insetBy(dx: 0, dy: -1).contains(frame)
    }

    /// `BISEL_DEV_SHOT=<path prefix>`: a picture of the panel at this point.
    private static func shot(_ c: CommandPanelController, _ name: String) {
        guard let prefix = ProcessInfo.processInfo.environment["BISEL_DEV_SHOT"] else { return }
        c.debugSnapshot(to: "\(prefix)-\(name).png")
    }

    static func run(_ c: CommandPanelController, out: String?) async {
        let service = AppModel.shared.service
        while !(service.isUnlocked && !service.rows.isEmpty) { try? await Task.sleep(for: .milliseconds(2)) }
        mark("launch.list ready")
        try? await Task.sleep(for: .seconds(1))   // what a launch starts in the background settles first

        let model = c.model
        let host = c.debugHost
        await timed("panel.open first", host) { c.show() }
        try? await Task.sleep(for: .milliseconds(150))
        await timed("panel.close", host) { c.hide("perf") }
        for _ in 0..<15 {
            await timed("panel.open", host) { c.show() }
            try? await Task.sleep(for: .milliseconds(120))
            await timed("panel.close", host) { c.hide("perf") }
            try? await Task.sleep(for: .milliseconds(40))
        }
        await timed("panel.open", host) { c.show() }
        try? await Task.sleep(for: .milliseconds(150))

        for q in ["g", "gi", "git", "gith", "githu", "github", "", "cl", "clo", "cloud", "", "user1", ""] {
            await timed("panel.keystroke", host) { model.query = q }
            try? await Task.sleep(for: .milliseconds(30))
        }
        for _ in 0..<60 {
            await timed("panel.arrow down", host) { model.moveSelection(1) }
            try? await Task.sleep(for: .milliseconds(16))
        }
        await timed("panel.jump to last row", host) { model.selected = model.results.count - 1 }
        try? await Task.sleep(for: .milliseconds(300))
        let reached = onScreen(model, row: model.results.count - 1)
        shot(c, "last")
        await timed("panel.jump to first row", host) { model.selected = 0 }
        try? await Task.sleep(for: .milliseconds(300))
        let back = onScreen(model, row: 0)
        shot(c, "first")

        if let s = scrollView(in: host) {
            let clip = s.contentView
            for i in 1...240 {
                await timed("panel.scroll frame", host) {
                    clip.scroll(to: NSPoint(x: 0, y: CGFloat(i) * 37))
                    s.reflectScrolledClipView(clip)
                }
            }
        } else { record("panel.scroll view not found", 1) }
        if let seconds = ProcessInfo.processInfo.environment["BISEL_DEV_PERF_SOAK"].flatMap(Double.init) {
            await soak(model, host, seconds: seconds, marker: out.map { $0 + ".soak" })
        }
        // Timings of an empty list or a locked box say nothing: no result rather than a wrong one.
        let valid = service.isUnlocked && model.results.count == service.rows.count && reached && back
        c.hide("perf")

        await settings()
        if valid { write(to: out) }
        NSApp.terminate(nil)
    }

    /// The settings window as a person gets it, in a window nobody sees.
    private static func settings() async {
        let remembered = UserDefaults.standard.string(forKey: SettingsPage.defaultsKey)
        defer { UserDefaults.standard.set(remembered, forKey: SettingsPage.defaultsKey) }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 760, height: 560), styleMask: [.titled, .closable, .fullSizeContentView],
                              backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.alphaValue = 0
        window.ignoresMouseEvents = true
        let t = ContinuousClock.now
        let host = NSHostingView(rootView: SettingsView(service: AppModel.shared.service))
        window.contentView = host
        window.orderFrontRegardless()
        host.layoutSubtreeIfNeeded()
        host.displayIfNeeded()
        await settle()
        record("settings.open window", (ContinuousClock.now - t).ms)
        try? await Task.sleep(for: .milliseconds(200))
        for _ in 0..<3 {
            for page in SettingsPage.main + SettingsPage.more + [.account] {
                await timed("settings.page \(page.rawValue)", host) {
                    NotificationCenter.default.post(name: SettingsPage.showNotification, object: page)
                }
                try? await Task.sleep(for: .milliseconds(60))
            }
        }
        window.orderOut(nil)
    }

    private static func write(to path: String?) {
        var json: [String: Double] = [:]
        for (label, s) in samples {
            let sorted = s.sorted()
            json[label] = sorted[sorted.count / 2]
            if sorted.count >= 20 {
                json[label + " p95"] = sorted[Int(Double(sorted.count - 1) * 0.95)]
                json[label + " max"] = sorted[sorted.count - 1]
            }
        }
        guard let path, let data = try? JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys]) else { return }
        try? data.write(to: URL(fileURLWithPath: path))
    }
}
#endif
