#if DEBUG
import AppKit
import OSLog

/// DEBUG-ONLY verification drivers for the command panel's accessibility, memory and performance. Inert unless an
/// environment variable asks for it; compiled out of Release. They call the same entry points the hotkey and the key
/// monitor call (`show()`, `hide()`, `CommandPanelModel`), never synthesize events and never touch other apps.
///
/// All drivers keep the panel fully transparent and click-through unless BISEL_DEV_VISIBLE=1.
///   BISEL_DEV_AXHOLD=1|actions         show the panel (optionally in the ⌘K list, query from BISEL_DEV_AXHOLD_QUERY) and
///                                      keep it open for an external AXUIElement dump (use with BISEL_DEV_STICKY=1)
///   BISEL_DEV_PANEL_CYCLES=<n>         n open/type/close cycles; logs memory, threads and monitor counts every n/10
///   BISEL_DEV_PANEL_PERF=<items>       build an index of <items> synthetic logins; time open, typing, ↓ moves and
///                                      full layout, with signposts (category "panel-perf")
@MainActor
enum PanelDebugDriver {
    static let signposter = OSSignposter(subsystem: "app.bisel.mac", category: "panel-perf")

    private static var started = false

    static func startIfRequested(controller: CommandPanelController) {
        guard !started else { return }  // the perf driver builds a second controller
        started = true
        let env = ProcessInfo.processInfo.environment
        // Only the debug drivers run invisible (BISEL_DEV_VISIBLE=1 opts into a visible panel, for screenshots only).
        // A normal launch must show the panel.
        let driving = env["BISEL_DEV_AXHOLD"] != nil || env["BISEL_DEV_PANEL_CYCLES"] != nil || env["BISEL_DEV_PANEL_PERF"] != nil
        controller.debugStealth = driving && env["BISEL_DEV_VISIBLE"] == nil
        if env["BISEL_DEV_AXHOLD"] != nil {
            Task { await hold(controller, query: env["BISEL_DEV_AXHOLD_QUERY"] ?? "", actions: env["BISEL_DEV_AXHOLD"] == "actions", dumpPath: env["BISEL_DEV_AXHOLD_DUMP"]) }
        }
        if let n = env["BISEL_DEV_PANEL_CYCLES"].flatMap(Int.init) { Task { await cycles(controller, count: n) } }
        if let n = env["BISEL_DEV_PANEL_PERF"].flatMap(Int.init) { Task { await perf(items: n) } }
    }

    // MARK: AX tree

    /// Opens the panel in the requested state and leaves it open (run with BISEL_DEV_STICKY=1 so losing key status does
    /// not close it). With BISEL_DEV_AXHOLD_DUMP=<path> it also writes the in-process accessibility tree (see `tree(of:)`).
    private static func hold(_ c: CommandPanelController, query: String, actions: Bool, dumpPath: String?) async {
        try? await Task.sleep(for: .seconds(2.5))
        c.show()
        try? await Task.sleep(for: .milliseconds(600))
        if !query.isEmpty { c.model.query = query; try? await Task.sleep(for: .milliseconds(900)) }
        if actions { c.model.toggleActions() }
        try? await Task.sleep(for: .milliseconds(600))
        if let dumpPath {
            // SwiftUI materializes its accessibility nodes lazily, as clients ask for them: dump repeatedly and keep every
            // round (the last one is the fullest).
            for i in 0..<8 {
                try? tree(of: c.debugPanel).write(toFile: dumpPath + ".\(i)", atomically: true, encoding: .utf8)
                try? await Task.sleep(for: .seconds(2))
            }
        }
        Log.panel.notice("AXHOLD ready pid=\(ProcessInfo.processInfo.processIdentifier)")
    }

    /// The panel's accessibility tree as `NSAccessibility` serves it in-process (the objects VoiceOver talks to).
    private static func tree(of window: NSWindow) -> String {
        "key=\(window.isKeyWindow)\n" + node(window, 0)
    }

    private static func node(_ o: Any, _ depth: Int) -> String {
        guard depth < 24, let e = o as? NSAccessibilityProtocol, let obj = o as? NSObject else { return "" }
        var line = String(repeating: "  ", count: depth) + (e.accessibilityRole()?.rawValue ?? "?")
        if let sub = e.accessibilitySubrole()?.rawValue { line += "/\(sub)" }
        if let l = e.accessibilityLabel(), !l.isEmpty { line += " label='\(l)'" }
        for key in ["accessibilityTitle", "accessibilityValue", "accessibilityHelp", "accessibilityIdentifier"] {
            if let v = obj.value(forKey: key), "\(v)" != "" { line += " \(key.dropFirst(13).lowercased())='\(v)'" }
        }
        if (obj.value(forKey: "accessibilitySelected") as? Bool) == true { line += " SELECTED" }
        let f = e.accessibilityFrame()
        if f != .zero { line += " \(Int(f.width))x\(Int(f.height))" }
        if let customs = obj.value(forKey: "accessibilityCustomActions") as? [NSAccessibilityCustomAction], !customs.isEmpty { line += " actions=\(customs.map(\.name))" }
        var out = line + "\n"
        for child in e.accessibilityChildren() ?? [] { out += node(child, depth + 1) }
        return out
    }

    // MARK: memory

    private static func footprintMB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
        }
        return kr == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576 : -1
    }

    private static func threadCount() -> Int {
        var list: thread_act_array_t?
        var n: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &list, &n) == KERN_SUCCESS, let list else { return -1 }
        vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: list)), vm_size_t(Int(n) * MemoryLayout<thread_t>.size))
        return Int(n)
    }

    private static func cycles(_ c: CommandPanelController, count: Int) async {
        try? await Task.sleep(for: .seconds(3))
        let queries = ["", "git", "goo", "ama", "x", "cloud", "no-such-thing-zzz"]
        let step = max(count / 10, 1)
        Log.panel.notice("CYCLES start n=\(count) footprint=\(footprintMB(), format: .fixed(precision: 1)) MB threads=\(threadCount())")
        for i in 1...count {
            c.show()
            try? await Task.sleep(for: .milliseconds(20))
            let mode = ProcessInfo.processInfo.environment["BISEL_DEV_PANEL_CYCLES_MODE"] ?? "full"
            if mode != "showhide" { c.model.query = queries[i % queries.count] }
            if mode == "full" {
                c.model.moveSelection(1)
                c.model.toggleActions(); c.model.toggleActions()
            }
            try? await Task.sleep(for: .milliseconds(20))
            c.hide("cycle")
            try? await Task.sleep(for: .milliseconds(10))
            if i % step == 0 {
                Log.panel.notice("CYCLES i=\(i) footprint=\(footprintMB(), format: .fixed(precision: 1)) MB threads=\(threadCount()) visible=\(c.isVisible)")
            }
        }
        Log.panel.notice("CYCLES done n=\(count) footprint=\(footprintMB(), format: .fixed(precision: 1)) MB threads=\(threadCount())")
    }

    // MARK: performance

    /// Synthetic vault: the real FuzzySearchIndex over `items` made-up logins, no secrets.
    @MainActor
    private final class SyntheticVault: VaultSearchSource, VaultSecretProvider {
        let isUnlocked = true
        let provenanceLabel: String? = "PERF"
        let index: FuzzySearchIndex
        init(items: Int) {
            let words = ["Git", "Cloud", "Mail", "Bank", "Shop", "Pay", "Media", "Photo", "Dev", "Travel", "Chat", "Music", "Maps", "Docs", "Cal"]
            let tlds = ["com", "io", "app", "net", "dev"]
            var records: [SearchRecord] = []
            records.reserveCapacity(items)
            for i in 0..<items {
                let w = words[i % words.count] + words[(i / words.count) % words.count].lowercased() + String(i)
                records.append(SearchRecord(id: "perf-\(i)", title: w, username: "user\(i)@example.com",
                                            urls: ["https://www.\(w.lowercased()).\(tlds[i % tlds.count])/login"], tags: ["t\(i % 40)"],
                                            lastUsed: Date(timeIntervalSince1970: Double(i)), useCount: i % 7))
            }
            index = FuzzySearchIndex(records: records)
        }
        func search(_ query: String, limit: Int) -> [VaultSearchResult] {
            index.search(query, limit: limit).map { VaultSearchResult(id: $0.id, title: $0.title, username: $0.username, domain: $0.domain, tags: $0.tags) }
        }
        func recordUse(id: String) {}
        func secret(_ kind: SecretKind, for id: String) async throws -> String { "x" }
        func url(for id: String) -> URL? { nil }
    }

    private static func ms(_ d: Duration) -> String { String(format: "%.2f", d.ms) }

    private static func perf(items: Int) async {
        try? await Task.sleep(for: .seconds(3))
        let t0 = ContinuousClock.now
        let vault = SyntheticVault(items: items)
        Log.panel.notice("PERF index of \(items) built in \(ms(ContinuousClock.now - t0), privacy: .public) ms")
        let model = CommandPanelModel(source: vault, secrets: vault)
        let c = CommandPanelController(model: model)
        c.debugStealth = ProcessInfo.processInfo.environment["BISEL_DEV_VISIBLE"] == nil
        func timed(_ label: String, _ body: () -> Void) -> Duration {
            let state = signposter.beginInterval("op", id: signposter.makeSignpostID(), "\(label, privacy: .public)")
            let t = ContinuousClock.now
            body()
            c.debugHost.layoutSubtreeIfNeeded()
            c.debugHost.displayIfNeeded()
            let d = ContinuousClock.now - t
            signposter.endInterval("op", state)
            return d
        }
        var open: [Duration] = []
        for _ in 0..<5 {
            c.hide("perf")
            open.append(timed("open") { c.show() })
            try? await Task.sleep(for: .milliseconds(150))
        }
        Log.panel.notice("PERF items=\(items) open(show+layout+draw) ms=\(open.map(ms).joined(separator: ","), privacy: .public)")
        var typing: [String] = []
        for q in ["g", "gi", "git", "gith", "githu", "github", "github 12", "zzzzz", "", "cl", "clo", "cloud"] {
            let t = ContinuousClock.now
            _ = vault.search(q, limit: CommandPanelModel.resultLimit)
            let searchOnly = ContinuousClock.now - t
            let d = timed("type") { model.query = q }
            typing.append("'\(q)' search=\(ms(searchOnly)) total=\(ms(d))(\(model.results.count))")
        }
        Log.panel.notice("PERF items=\(items) type+layout ms: \(typing.joined(separator: " "), privacy: .public)")
        model.query = ""
        _ = timed("reset") {}
        var moves: [Duration] = []
        for _ in 0..<40 { moves.append(timed("down") { model.moveSelection(1) }) }
        let sorted = moves.map(\.ms).sorted()
        Log.panel.notice("PERF items=\(items) ↓ x40 median=\(String(format: "%.2f", sorted[sorted.count / 2]), privacy: .public) max=\(String(format: "%.2f", sorted.last ?? 0), privacy: .public) ms")
        c.hide("perf")
    }
}
#endif
