import Foundation

/// Text that reaches the Touch ID prompt. The prompt is the real boundary, so it must show what will happen, in full and unspoofed.
public enum AgentPrompt {
    public static let maxCommandLength = 200

    /// False for control, format (text direction, zero width) and line or paragraph separator characters, which could hide part of
    /// a command or make it read as something else.
    public static func isPrintable(_ text: String) -> Bool {
        text.unicodeScalars.allSatisfy {
            switch $0.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate, .privateUse, .unassigned: false
            default: true
            }
        }
    }

    /// Stored text (item titles) shown as data: unprintable characters dropped, capped at `limit`.
    public static func clean(_ text: String, limit: Int = 60) -> String {
        let kept = String(String.UnicodeScalarView(text.unicodeScalars.filter { isPrintable(String($0)) }))
        return kept.count > limit ? String(kept.prefix(limit)) + "…" : kept
    }

    /// The command as a person would read it, or nil when it can't be shown truthfully in full.
    public static func command(_ argv: [String]) -> String? {
        guard let path = argv.first, path.hasPrefix("/"), argv.allSatisfy(isPrintable) else { return nil }
        let shown = argv.map(quoted).joined(separator: " ")
        return shown.count <= maxCommandLength ? shown : nil
    }

    private static func quoted(_ arg: String) -> String {
        let plain = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-")
        if !arg.isEmpty, arg.unicodeScalars.allSatisfy(plain.contains) { return arg }
        return "'" + arg.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
