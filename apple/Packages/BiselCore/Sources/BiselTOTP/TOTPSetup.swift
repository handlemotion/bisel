import Foundation

/// What a user types or pastes into a "one-time code" field: a bare base32 secret or an `otpauth://totp/...` URI (QR payload).
public enum TOTPSetup {
    public enum Problem: Error, Sendable, Equatable {
        case empty
        /// `otpauth://hotp/...` (counter based) and anything else that is not `totp`.
        case unsupportedType
        case missingSecret
        case notBase32
        case tooShort
        /// Unknown algorithm, digits outside 6...8 or a period outside 1...300.
        case badParameters
    }

    public struct Parsed: Sendable, Equatable {
        public var params: TOTPParameters
        public var issuer: String?
        public var account: String?
    }

    public static let minimumSecretLength = 8

    public static func parse(_ raw: String) throws(Problem) -> Parsed {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { throw .empty }
        guard t.lowercased().hasPrefix("otpauth://") else {
            return Parsed(params: TOTPParameters(secret: try cleanSecret(t)), issuer: nil, account: nil)
        }
        guard let c = URLComponents(string: t) else { throw .badParameters }
        guard c.host?.lowercased() == "totp" else { throw .unsupportedType }
        func q(_ n: String) -> String? { c.queryItems?.first { $0.name.lowercased() == n }?.value }
        guard let secret = q("secret"), !secret.isEmpty else { throw .missingSecret }
        var algo = TOTPAlgorithm.sha1
        if let a = q("algorithm") {
            guard let known = TOTPAlgorithm(rawValue: a.uppercased()) else { throw .badParameters }
            algo = known
        }
        var digits = 6, period = 30
        if let d = q("digits") { guard let v = Int(d) else { throw .badParameters }; digits = v }
        if let p = q("period") { guard let v = Int(p) else { throw .badParameters }; period = v }
        guard (6...8).contains(digits), (1...300).contains(period) else { throw .badParameters }
        let p = TOTPParameters(secret: try cleanSecret(secret), algo: algo, digits: digits, period: period)
        guard (try? TOTPGenerator.code(p)) != nil else { throw .notBase32 }
        let label = String(c.path.dropFirst()).removingPercentEncoding
        let parts = label?.split(separator: ":", maxSplits: 1).map(String.init)
        return Parsed(params: p, issuer: q("issuer") ?? (parts?.count == 2 ? parts?.first : nil), account: parts?.last)
    }

    /// Nil instead of a thrown reason, for importers that just skip what they cannot read.
    public static func parsed(_ raw: String) -> Parsed? { try? parse(raw) }

    /// What an edit form shows for stored parameters: the bare secret when everything else is the default, otherwise an
    /// `otpauth://` URI, so a round trip through `parse` loses nothing.
    public static func text(for p: TOTPParameters) -> String {
        if p.algo == .sha1, p.digits == 6, p.period == 30 { return p.secret }
        var c = URLComponents()
        c.scheme = "otpauth"; c.host = "totp"; c.path = "/bisel"
        c.queryItems = [.init(name: "secret", value: p.secret), .init(name: "algorithm", value: p.algo.rawValue),
                        .init(name: "digits", value: String(p.digits)), .init(name: "period", value: String(p.period))]
        return c.string ?? p.secret
    }

    /// Uppercase base32 without spaces, hyphens or padding. Rejects anything that is not base32 or is too short to be a secret.
    private static func cleanSecret(_ s: String) throws(Problem) -> String {
        let cleaned = s.uppercased().filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }
        guard !cleaned.isEmpty else { throw .missingSecret }
        guard cleaned.allSatisfy({ ("A"..."Z").contains($0) || ("2"..."7").contains($0) }) else { throw .notBase32 }
        guard cleaned.count >= minimumSecretLength else { throw .tooShort }
        guard (try? TOTPGenerator.code(TOTPParameters(secret: cleaned))) != nil else { throw .notBase32 }
        return cleaned
    }
}
