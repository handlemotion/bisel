import Foundation

/// Whether the page in front belongs to a login's address, before a secret is typed into it (the fill origin check).
///
/// Same host, or one host inside the other (`login.bank.com` and `bank.com`), but only when the outer host is a site of its own.
/// A public suffix is not: `github.io`, `myshopify.com`, `vercel.app` or `co.uk` hold unrelated tenants, so a login saved for one
/// of them must not be typed into `attacker.github.io`. IP addresses match only exactly. `isPublicSuffix` is the Public Suffix List
/// (the app passes its bundled copy; the private section is what covers the shared-hosting names).
public enum SiteMatch {
    /// Lowercased, without surrounding dots or a leading `www.`.
    public static func normalized(_ host: String) -> String {
        var h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if h.hasPrefix("www.") { h.removeFirst(4) }
        return h
    }

    /// Hosts of an item's addresses (scheme optional), normalised; addresses without a host are dropped.
    public static func hosts(of urls: [String]) -> [String] {
        urls.compactMap { raw in
            let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let host = (URL(string: t.contains("://") ? t : "https://" + t))?.host(), !host.isEmpty else { return nil }
            let h = normalized(host)
            return h.isEmpty ? nil : h
        }
    }

    /// `page` and `item` are normalised hosts.
    public static func matches(page: String, item: String, isPublicSuffix: (String) -> Bool) -> Bool {
        guard !page.isEmpty, !item.isEmpty else { return false }
        if page == item { return true }
        if isIPAddress(page) || isIPAddress(item) { return false }
        let outer: String
        if page.hasSuffix("." + item) { outer = item }
        else if item.hasSuffix("." + page) { outer = page }
        else { return false }
        return outer.contains(".") && !isPublicSuffix(outer)
    }

    /// IPv6, or IPv4 in any spelling: the last label of a real name is never all digits or hex (`127.1`, `0x7f.0.0.1`).
    private static func isIPAddress(_ host: String) -> Bool {
        guard !host.contains(":"), let last = host.split(separator: ".").last else { return true }
        return last.allSatisfy { $0.isASCII && $0.isNumber } || last.hasPrefix("0x")
    }
}
