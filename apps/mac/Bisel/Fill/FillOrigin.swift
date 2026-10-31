import AppKit
import BiselCore

/// Does the page the cursor is in belong to the login being typed? Without this check, choosing "Bank" while a phishing page is
/// in front types the bank password into the phishing page (security audit). Applies to Enter and ⌥Enter; ⌘K "Fill …" is the
/// deliberate override.
enum FillOrigin {
    nonisolated static let browserBundleIDs: Set<String> = [
        "com.apple.Safari", "com.apple.SafariTechnologyPreview", "com.google.Chrome", "com.google.Chrome.canary", "org.chromium.Chromium",
        "com.microsoft.edgemac", "com.brave.Browser", "company.thebrowser.Browser", "com.vivaldi.Vivaldi", "com.operasoftware.Opera",
        "org.mozilla.firefox", "app.zen-browser.zen", "com.kagi.kagimacOS",
    ]

    /// Every app that can open an https link: a browser missing from the list above (a beta channel, a new one) still counts.
    private nonisolated static let httpsHandlers: Set<String> = {
        guard let probe = URL(string: "https://example.com") else { return [] }
        return Set(NSWorkspace.shared.urlsForApplications(toOpen: probe).compactMap { Bundle(url: $0)?.bundleIdentifier })
    }()

    /// A browser refuses a fill when its page address can't be read; a native app has none to read.
    nonisolated static func isBrowser(_ bundleID: String?) -> Bool {
        guard let bundleID else { return false }
        return browserBundleIDs.contains(bundleID) || httpsHandlers.contains(bundleID)
    }

    nonisolated static func normalized(_ host: String) -> String { SiteMatch.normalized(host) }

    /// Hosts of an item's addresses (scheme optional), normalised.
    nonisolated static func hosts(of urls: [String]) -> [String] { SiteMatch.hosts(of: urls) }

    /// Same site, or a subdomain of one: `login.bank.com` fits `bank.com` and the other way round; `bank.com.evil.net` fits neither,
    /// and neither does `evil.github.io` for a login saved for `github.io` (a public suffix is not a site, see `SiteMatch`).
    nonisolated static func matches(page: String, item: String) -> Bool {
        SiteMatch.matches(page: page, item: item, isPublicSuffix: DomainName.isPublicSuffix)
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
