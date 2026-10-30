import Foundation

/// Registrable domain ("eTLD+1") from the Public Suffix List (https://publicsuffix.org, MPL-2.0), bundled as
/// `Resources/PublicSuffix/public_suffix_list.dat` (pinned: VERSION 2026-10-28_13-15-55_UTC, commit 9dfbe81931367b3f0af21035c36ae7eeb830dd88,
/// sha256 1f96bae4…ebd9). Includes the private section, so `a.github.io` and `b.github.io` are different sites.
/// Update by replacing the file and these three lines; nothing is fetched at runtime.
enum DomainName {
    private struct Rules: Sendable {
        var exact = Set<String>()
        var wildcard = Set<String>()     // "*.ck" stored as "ck"
        var exception = Set<String>()   // "!www.ck" stored as "www.ck"
    }

    private static let rules: Rules = {
        var r = Rules()
        guard let url = Bundle.main.url(forResource: "public_suffix_list", withExtension: "dat"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            Log.icons.error("public suffix list missing from the bundle: icon scoping falls back to two labels")
            return r
        }
        for line in text.split(whereSeparator: \.isNewline) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.isEmpty || t.hasPrefix("//") { continue }
            let rule = String(t.split(whereSeparator: \.isWhitespace).first ?? "")
            if rule.hasPrefix("!") { r.exception.insert(String(rule.dropFirst())) }
            else if rule.hasPrefix("*.") { r.wildcard.insert(String(rule.dropFirst(2))) }
            else { r.exact.insert(rule) }
        }
        return r
    }()

    /// Number of trailing labels that form the public suffix of `labels` (PSL algorithm: exception rules win, else the longest
    /// matching rule, else the implicit "*" rule = 1 label).
    private static func suffixLength(_ labels: [String]) -> Int {
        let n = labels.count
        var best = 1
        for i in 0..<n {
            let s = labels[i...].joined(separator: ".")
            if rules.exception.contains(s) { return n - i - 1 }
            if rules.exact.contains(s) { best = max(best, n - i) }
            if i + 1 < n, rules.wildcard.contains(labels[(i + 1)...].joined(separator: ".")) { best = max(best, n - i) }
        }
        return best
    }

    /// "www.accounts.example.co.uk" → "example.co.uk". A host that is itself a public suffix is returned as is.
    static func registrable(_ host: String) -> String {
        let labels = host.lowercased().split(separator: ".").map(String.init)
        guard labels.count > 1 else { return labels.joined(separator: ".") }
        let take = min(suffixLength(labels) + 1, labels.count)
        return labels.suffix(take).joined(separator: ".")
    }

    /// True when `host` is exactly a public suffix ("co.uk", "github.io"): no site of its own to fetch an icon from.
    static func isPublicSuffix(_ host: String) -> Bool {
        let labels = host.lowercased().split(separator: ".").map(String.init)
        return !labels.isEmpty && suffixLength(labels) >= labels.count
    }
}
