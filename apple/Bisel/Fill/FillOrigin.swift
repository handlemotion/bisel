import Foundation

/// Does the page the cursor is in belong to the login being typed? Without this check, choosing "Bank" while a phishing page is
/// in front types the bank password into the phishing page (security audit). Applies to Enter and ⌥Enter; ⌘K "Fill …" is the
/// deliberate override.
enum FillOrigin {
    nonisolated static let browserBundleIDs: Set<String> = [
        "com.apple.Safari", "com.apple.SafariTechnologyPreview", "com.google.Chrome", "com.google.Chrome.canary", "org.chromium.Chromium",
        "com.microsoft.edgemac", "com.brave.Browser", "company.thebrowser.Browser", "com.vivaldi.Vivaldi", "com.operasoftware.Opera",
        "org.mozilla.firefox", "app.zen-browser.zen", "com.kagi.kagimacOS",
    ]

    nonisolated static func normalized(_ host: String) -> String {
        var h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if h.hasPrefix("www.") { h.removeFirst(4) }
        return h
    }

    /// Hosts of an item's addresses (scheme optional), normalised.
    nonisolated static func hosts(of urls: [String]) -> [String] {
        urls.compactMap { raw in
            let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let host = (URL(string: t.contains("://") ? t : "https://" + t))?.host(), !host.isEmpty else { return nil }
            return normalized(host)
        }
    }

    /// Same site, or a subdomain of one: `login.bank.com` fits `bank.com` and the other way round; `bank.com.evil.net` fits neither.
    nonisolated static func matches(page: String, item: String) -> Bool {
        page == item || page.hasSuffix("." + item) || item.hasSuffix("." + page)
    }

    /// Why the secret must not be typed here, or nil. `pageHost` is nil when the app does not expose one.
    nonisolated static func refusal(pageHost: String?, isBrowser: Bool, itemHosts: [String]) -> String? {
        guard let want = itemHosts.first else { return nil }   // a login without an address: the user's choice
        guard let page = pageHost.map(normalized), !page.isEmpty else {
            return isBrowser ? "Can't read this page’s address, so nothing was typed. Use ⌘K → Fill to type it anyway" : nil
        }
        if itemHosts.contains(where: { matches(page: page, item: $0) }) { return nil }
        return "This page is \(page) but the login is for \(want), so nothing was typed. Use ⌘K → Fill to type it anyway"
    }
}
