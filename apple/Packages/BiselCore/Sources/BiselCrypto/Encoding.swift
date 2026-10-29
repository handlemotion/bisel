import Foundation
import CryptoKit

public extension Data {
    /// RFC 4648 base64url without padding.
    func base64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded string: String) {
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        self.init(base64Encoded: s)
    }

    func hexEncoded() -> String { map { String(format: "%02x", $0) }.joined() }

    init?(hexEncoded string: String) {
        guard string.count % 2 == 0 else { return nil }
        var out = Data(capacity: string.count / 2)
        var idx = string.startIndex
        while idx < string.endIndex {
            let next = string.index(idx, offsetBy: 2)
            guard let b = UInt8(string[idx..<next], radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        self = out
    }

    func sha256Hex() -> String { Data(SHA256.hash(data: self)).hexEncoded() }
}

public enum BiselRandom {
    public static func bytes(_ count: Int) -> Data {
        var d = Data(count: count)
        let status = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return d
    }

    /// Opaque 128-bit identifier (items, devices): 22 base64url characters (the server accepts 16-64 of [A-Za-z0-9_-]).
    public static func identifier() -> String { bytes(16).base64URLEncoded() }

    public static func nonce() -> String { bytes(16).base64URLEncoded() }
}
