import OSLog

/// All logging goes through these loggers. SPEC.md §8 "Security details": no secrets in logs.
/// Never interpolate a username, password, TOTP code, query text or item title: log ids/sizes/timings only.
/// Dynamic strings are `.private` by default in os.Logger; keep it that way (do not use `privacy: .public`
/// for anything derived from vault data).
enum Log {
    static let app = Logger(subsystem: "app.bisel.mac", category: "app")
    static let panel = Logger(subsystem: "app.bisel.mac", category: "panel")
    static let fill = Logger(subsystem: "app.bisel.mac", category: "fill")
    static let clipboard = Logger(subsystem: "app.bisel.mac", category: "clipboard")
    static let search = Logger(subsystem: "app.bisel.mac", category: "search")
    static let icons = Logger(subsystem: "app.bisel.mac", category: "icons")
}

extension Duration {
    /// Milliseconds as a Double, for timing logs.
    var ms: Double { Double(components.seconds) * 1000 + Double(components.attoseconds) / 1e15 }
}
