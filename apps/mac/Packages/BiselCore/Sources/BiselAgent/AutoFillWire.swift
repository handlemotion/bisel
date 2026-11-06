import Foundation

/// What travels between the AutoFill extension and the app (docs/SPEC.md §8, "AutoFill"). The extension links only this module: it
/// holds no keys and opens no store, and gets one password at a time, after Touch ID in the app.

public enum AutoFillSocket {
    /// macOS-style, so it needs no entry on the developer website; the Mac provisioning profiles authorise `<team>.*`.
    public static let appGroup = "ZVGTVNUPVA.app.bisel"

    /// Inside the App Group container, the one place a sandboxed extension may reach a socket. Debug builds have their own, so a
    /// dev build and the installed app can run side by side.
    public static func path(container: URL, debug: Bool) -> String {
        container.appendingPathComponent("autofill/\(debug ? "s-dev" : "s").sock").path
    }
}

public enum AutoFillRequest: Codable, Sendable {
    /// The logins for these sites, after one Touch ID. `services` are what the system asked for: domains or URLs.
    case list(services: [String])
    /// One login's password. Answers after Touch ID, unless the same login just came from a `.list`, which already asked.
    case credential(id: String, services: [String])
}

/// No secret: what the extension shows so the person can choose.
public struct AutoFillCandidate: Codable, Sendable, Equatable {
    public var id: String
    public var title: String
    public var username: String
    public init(id: String, title: String, username: String) { self.id = id; self.title = title; self.username = username }
}

public enum AutoFillResult: Codable, Sendable {
    case candidates([AutoFillCandidate])
    case credential(username: String, password: AgentSecret)
    case refused(AgentCode)
}
