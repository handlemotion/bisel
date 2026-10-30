import Foundation
import SwiftOTP

public enum TOTPAlgorithm: String, Codable, Sendable, CaseIterable {
    case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512"
}

public struct TOTPParameters: Codable, Sendable, Equatable {
    public var secret: String          // base32
    public var algo: TOTPAlgorithm
    public var digits: Int
    public var period: Int

    public init(secret: String, algo: TOTPAlgorithm = .sha1, digits: Int = 6, period: Int = 30) {
        self.secret = secret; self.algo = algo; self.digits = digits; self.period = period
    }
}

// A TOTP secret must not reach logs, `print`, `dump` or crash-time descriptions.
extension TOTPParameters: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "TOTPParameters(\(algo.rawValue), \(digits) digits, \(period) s, secret redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }
}

public struct TOTPCode: Sendable, Equatable {
    public let code: String
    public let secondsRemaining: Int
}

public enum TOTPError: Error, Sendable { case invalidSecret, invalidParameters }

/// RFC 6238 codes via SwiftOTP (HMAC/dynamic truncation are not hand-rolled here).
public enum TOTPGenerator {
    public static func code(_ p: TOTPParameters, at date: Date = Date()) throws -> TOTPCode {
        let cleaned = p.secret.uppercased().filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }
        guard let key = base32DecodeToData(cleaned), !key.isEmpty else { throw TOTPError.invalidSecret }
        let algo: OTPAlgorithm = switch p.algo { case .sha1: .sha1; case .sha256: .sha256; case .sha512: .sha512 }
        guard p.period > 0, let totp = TOTP(secret: key, digits: p.digits, timeInterval: p.period, algorithm: algo),
              let code = totp.generate(time: date) else { throw TOTPError.invalidParameters }
        let elapsed = Int(date.timeIntervalSince1970) % p.period
        return TOTPCode(code: code, secondsRemaining: p.period - elapsed)
    }
}
