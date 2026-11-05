import BiselCore
import Foundation

// bisel-bench [--items 5000] [--runs 9] [--json out.json]   (run with BISEL_ALLOW_SOFTWARE_KEYS=1, in release)
// The box is seeded once per size under BISEL_BENCH_DIR (default: the temporary directory) and reused. Each run opens it from
// scratch, so `open` and `phase` are what a launch pays, and `reload` is what an unlock pays before the list can show.

func option(_ name: String, _ fallback: String) -> String {
    let args = CommandLine.arguments
    guard let i = args.firstIndex(of: name), i + 1 < args.count else { return fallback }
    return args[i + 1]
}

let itemCount = Int(option("--items", "5000")) ?? 5000
let runs = Int(option("--runs", "9")) ?? 9
let root = URL(fileURLWithPath: ProcessInfo.processInfo.environment["BISEL_BENCH_DIR"] ?? NSTemporaryDirectory(), isDirectory: true)
    .appendingPathComponent("bisel-bench-\(itemCount)", isDirectory: true)

func configuration() -> Vault.Configuration { .software(location: StoreLocation(directory: root), deviceKind: "mac", fillWindow: 3600) }

/// Made-up logins shaped like a real box: most with a site and username, a fifth with a one-time code, some with notes and tags.
func seed() async throws {
    let words = ["Git", "Cloud", "Mail", "Bank", "Shop", "Pay", "Media", "Photo", "Dev", "Travel", "Chat", "Music", "Maps", "Docs", "Cal",
                 "Café", "Zürich", "Örebro", "Señal", "Nube"]
    let tlds = ["com", "io", "app", "net", "dev"]
    let vault = try Vault(configuration())
    let setup = BoxSetup(vault: vault, home: nil)
    _ = await setup.start()
    _ = try await setup.createOnThisMacOnly(deviceName: "Bench Mac")
    let totp = try TOTPSetup.parse("JBSWY3DPEHPK3PXP").params
    for i in 0..<itemCount {
        let w = words[i % words.count] + words[(i / words.count) % words.count].lowercased() + " \(i)"
        let host = w.folding(options: .diacriticInsensitive, locale: nil).lowercased().replacingOccurrences(of: " ", with: "")
        var item = Item(title: w, urls: ["https://www.\(host).\(tlds[i % tlds.count])/login"], username: "user\(i)@example.com",
                        password: "correct-horse-battery-\(i)")
        if i % 5 == 0 { item.totp = totp }
        if i % 3 == 0 { item.notes = String(repeating: "A recovery note, not a secret. ", count: 4) }
        if i % 4 == 0 { item.tags = ["t\(i % 40)"] }
        try await vault.save(item)
    }
    await vault.lock()
}

var samples: [String: [Double]] = [:]
var order: [String] = []
@MainActor func record(_ label: String, _ ms: Double) {
    if samples[label] == nil { order.append(label) }
    samples[label, default: []].append(ms)
}
func ms(_ d: Duration) -> Double { Double(d.components.seconds) * 1_000 + Double(d.components.attoseconds) / 1e15 }

@MainActor @discardableResult
func timed<T>(_ label: String, _ body: () async throws -> T) async rethrows -> T {
    let t = ContinuousClock.now
    let out = try await body()
    record(label, ms(ContinuousClock.now - t))
    return out
}

func footprintMB() -> Double {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
    let kr = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
    }
    return kr == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576 : -1
}

@MainActor
func run() async throws {
    if !FileManager.default.fileExists(atPath: root.appendingPathComponent("bisel.sqlite").path) {
        let t = ContinuousClock.now
        try await seed()
        print("seeded \(itemCount) items in \(Int(ms(ContinuousClock.now - t))) ms at \(root.path)")
    }
    let typed = ["g", "gi", "git", "gith", "githu", "github", "zzzzz", "cl", "clo", "cloud", "user12"]
    for _ in 0..<runs {
        let vault = try await timed("launch.open store") { try Vault(configuration()) }
        let setup = BoxSetup(vault: vault, home: nil)
        await timed("launch.set-up state") { _ = await setup.start() }
        try await timed("launch.phase") {
            _ = try await vault.identity()
            _ = try await vault.laneStatus()
            _ = await vault.isConfigured
            _ = await vault.isUnlocked
            _ = try await vault.pendingChanges()
        }
        let unlocked = ContinuousClock.now
        try await timed("unlock.keys") { try await vault.unlock(reason: "bench") }
        try await timed("unlock.backup status") { _ = try await vault.backupStatus() }
        let listing = try await timed("unlock.decrypt") { try await vault.items() }
        let built = await timed("unlock.build") {
            await Task.detached(priority: .userInitiated) { BoxIndex.build(listing.items, usage: [:]) }.value
        }
        let index = BoxIndex()
        await timed("unlock.install") { index.install(built) }
        record("unlock.TOTAL to list", ms(ContinuousClock.now - unlocked))

        let all = await timed("panel.open list") { index.search("", limit: .max) }
        for q in typed { await timed("panel.keystroke") { _ = index.search(q, limit: .max) } }
        let ids = stride(from: 0, to: all.count, by: max(all.count / 40, 1)).map { all[$0].id }
        for id in ids {
            try await timed("panel.select item") {
                _ = try await vault.item(id: id)   // password
                _ = try await vault.item(id: id)   // one-time code
            }
        }
        try await timed("settings.trash") { _ = try await vault.recentlyDeleted() }
        record("memory MB", footprintMB())
        await vault.lock()
    }
    var lines: [String] = []
    var json: [String: Double] = [:]
    for label in order {
        let s = samples[label]!.sorted()
        let median = s[s.count / 2]
        json[label] = median
        lines.append(String(format: "%-26@ %10.3f   min %10.3f   max %10.3f   n=%d", label as NSString, median, s[0], s[s.count - 1], s.count))
    }
    print("items=\(itemCount) runs=\(runs)   (ms, median)")
    print(lines.joined(separator: "\n"))
    let out = option("--json", "")
    if !out.isEmpty {
        try JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: out))
    }
}

try await run()
