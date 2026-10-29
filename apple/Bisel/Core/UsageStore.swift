import Foundation

/// Which items you open most / last, for the panel's empty-query ordering. Keyed by opaque item id; no titles.
/// Local only (never synced), `~/Library/Application Support/bisel/usage.json`.
@MainActor
final class UsageStore {
    struct Entry: Codable { var last: Date; var count: Int }
    private(set) var entries: [String: Entry] = [:]
    private let url: URL
    private var saveTask: Task<Void, Never>?

    init(directory: URL) {
        url = directory.appendingPathComponent("usage.json")
        if let data = try? Data(contentsOf: url), let e = try? JSONDecoder().decode([String: Entry].self, from: data) { entries = e }
    }

    func record(_ id: String) {
        var e = entries[id] ?? Entry(last: .distantPast, count: 0)
        e.last = Date(); e.count += 1
        entries[id] = e
        saveTask?.cancel()
        saveTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled, let self else { return }
            if let data = try? JSONEncoder().encode(self.entries) { try? data.write(to: self.url, options: .atomic) }
        }
    }

    func forget(_ id: String) { entries[id] = nil }
}
