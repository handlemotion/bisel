import Foundation

enum DomainName {
    private static let secondLevelLabels: Set<String> = ["co", "com", "org", "net", "gob", "gov", "edu", "ac", "or", "ne"]

    /// Registrable domain without a Public Suffix List: last two labels, or three when the TLD is a two-letter ccTLD
    /// under a generic second level ("nu.com.mx", "bbc.co.uk"). Good enough to scope redirects and cache keys; a
    /// wrong guess only makes the scope stricter or looser by one label.
    static func registrable(_ host: String) -> String {
        let labels = host.lowercased().split(separator: ".").map(String.init)
        guard labels.count > 2 else { return labels.joined(separator: ".") }
        let tld = labels[labels.count - 1], sld = labels[labels.count - 2]
        let n = (tld.count == 2 && secondLevelLabels.contains(sld)) ? 3 : 2
        return labels.suffix(n).joined(separator: ".")
    }
}
