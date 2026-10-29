import AppKit

/// Item URLs are data from imports and sync, so they are never handed to the system blindly (security review M10): only https
/// opens, http opens after a warning, everything else (file://, smb://, vnc://, x-apple.systempreferences:, custom schemes,
/// javascript:, data:) is refused.
enum URLPolicy {
    enum Decision: Equatable {
        case open(URL)
        case confirmHTTP(URL)
        case refuse(String)
    }

    static func decide(_ raw: String) -> Decision {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, !t.contains(where: { $0.isNewline || $0.unicodeScalars.contains { $0.properties.generalCategory == .control } }) else {
            return .refuse("That isn't a web address")
        }
        let withScheme: String
        if let r = t.range(of: "://") {
            let scheme = t[..<r.lowerBound].lowercased()
            guard scheme == "https" || scheme == "http" else { return .refuse("Only https and http links are opened (this one is \(scheme)://)") }
            withScheme = t
        } else if t.contains(":"), !t.contains("/"), t.split(separator: ":").last.map({ Int($0) != nil }) == false {
            // "javascript:alert(1)", "mailto:x", "tel:…": a scheme without "//"
            return .refuse("Only https and http links are opened")
        } else {
            withScheme = "https://" + t
        }
        guard let url = URL(string: withScheme), let host = url.host(), !host.isEmpty else { return .refuse("That isn't a web address") }
        return url.scheme?.lowercased() == "https" ? .open(url) : .confirmHTTP(url)
    }

    /// Opens an item URL after the policy (and, for http, an explicit confirmation). Returns the refusal text, if any.
    @MainActor
    @discardableResult
    static func openWithPolicy(_ raw: String) -> String? {
        switch decide(raw) {
        case .refuse(let why): return why
        case .open(let url): NSWorkspace.shared.open(url); return nil
        case .confirmHTTP(let url):
            let alert = NSAlert()
            alert.messageText = "Open an unencrypted link?"
            alert.informativeText = "\(url.host() ?? "This site") would be opened over http, so anything you type there can be read on the network."
            alert.addButton(withTitle: "Cancel")
            alert.addButton(withTitle: "Open Anyway")
            NSApp.activate()
            if alert.runModal() == .alertSecondButtonReturn { NSWorkspace.shared.open(url) }
            return nil
        }
    }

    /// The URL the panel may open, or nil.
    static func allowed(_ raw: String) -> URL? {
        switch decide(raw) { case .open(let u), .confirmHTTP(let u): u; case .refuse: nil }
    }
}
