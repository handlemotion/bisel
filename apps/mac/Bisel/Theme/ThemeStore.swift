import AppKit
import Observation

/// Holds the available themes (built-in + JSON files), the selected family, and the system appearance.
/// `current` is the variant of the selected family that matches the system light/dark appearance.
@MainActor
@Observable
final class ThemeStore {
    static let shared = ThemeStore()

    private(set) var themes: [Theme] = Theme.all
    private(set) var loadErrors: [String] = []
    private(set) var systemIsDark: Bool
    var selectedFamily: String {
        didSet { UserDefaults.standard.set(selectedFamily, forKey: Self.defaultsKey) }
    }

    private static let defaultsKey = "theme.family"
    @ObservationIgnored private var appearanceObservation: NSKeyValueObservation?

    /// One entry per family, for pickers.
    var families: [(id: String, name: String)] {
        var seen = Set<String>()
        return themes.compactMap { seen.insert($0.family).inserted ? ($0.family, $0.name) : nil }
    }

    var current: Theme {
        let want: Theme.Appearance = systemIsDark ? .dark : .light
        let inFamily = themes.filter { $0.family == selectedFamily }
        return inFamily.first { $0.appearance == want } ?? inFamily.first
            ?? (want == .dark ? Theme.biselDark : Theme.biselLight)
    }

    static var themesDirectory: URL {
        URL.applicationSupportDirectory.appending(path: "bisel/themes", directoryHint: .isDirectory)
    }

    private init() {
        selectedFamily = UserDefaults.standard.string(forKey: Self.defaultsKey) ?? "bisel"
        let app = NSApplication.shared
        systemIsDark = Self.isDark(app.effectiveAppearance)
        appearanceObservation = app.observe(\.effectiveAppearance, options: [.new]) { [weak self] app, _ in
            MainActor.assumeIsolated { self?.systemIsDark = Self.isDark(app.effectiveAppearance) }
        }
        reload()
    }

    private static func isDark(_ a: NSAppearance) -> Bool {
        a.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
    }

    /// Re-reads `~/Library/Application Support/bisel/themes/*.json`. A file whose `id` matches a
    /// built-in replaces it. Bad files are skipped and reported in `loadErrors` (file name only).
    func reload() {
        var result = Theme.all
        var errors: [String] = []
        let dir = Self.themesDirectory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        for url in files where url.pathExtension.lowercased() == "json" {
            do {
                let theme = try JSONDecoder().decode(Theme.self, from: Data(contentsOf: url))
                if let i = result.firstIndex(where: { $0.id == theme.id }) { result[i] = theme } else { result.append(theme) }
            } catch {
                errors.append("\(url.lastPathComponent): \(error.localizedDescription)")
                Log.app.error("Theme file failed to load: \(url.lastPathComponent, privacy: .public)")
            }
        }
        themes = result
        loadErrors = errors
    }

    /// Writes the built-in themes as JSON templates (`*.json.example`) so users can copy, rename and edit them.
    func exportTemplates() {
        let dir = Self.themesDirectory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        for t in Theme.all {
            let url = dir.appending(path: "\(t.id).json.example")
            if let data = try? enc.encode(t) { try? data.write(to: url) }
        }
    }
}
