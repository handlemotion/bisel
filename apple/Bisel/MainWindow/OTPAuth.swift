import Foundation
import BiselCore

/// TOTP setup input: a bare base32 secret or an `otpauth://totp/...` URI (QR payload).
enum OTPAuth {
    struct Parsed { var params: TOTPParameters; var issuer: String?; var account: String? }

    static func parse(_ raw: String) -> Parsed? {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return nil }
        if t.lowercased().hasPrefix("otpauth://") {
            guard let c = URLComponents(string: t), c.host?.lowercased() == "totp" else { return nil }
            func q(_ n: String) -> String? { c.queryItems?.first { $0.name.lowercased() == n }?.value }
            guard let secret = q("secret"), !secret.isEmpty else { return nil }
            let algo = TOTPAlgorithm(rawValue: (q("algorithm") ?? "SHA1").uppercased()) ?? .sha1
            let p = TOTPParameters(secret: secret, algo: algo, digits: Int(q("digits") ?? "") ?? 6, period: Int(q("period") ?? "") ?? 30)
            guard valid(p) else { return nil }
            let label = String(c.path.dropFirst()).removingPercentEncoding
            let parts = label?.split(separator: ":", maxSplits: 1).map(String.init)
            return Parsed(params: p, issuer: q("issuer") ?? (parts?.count == 2 ? parts?.first : nil), account: parts?.last)
        }
        let p = TOTPParameters(secret: t)
        return valid(p) ? Parsed(params: p, issuer: nil, account: nil) : nil
    }

    static func valid(_ p: TOTPParameters) -> Bool { (try? TOTPGenerator.code(p)) != nil && (6...8).contains(p.digits) && p.period > 0 }
}
