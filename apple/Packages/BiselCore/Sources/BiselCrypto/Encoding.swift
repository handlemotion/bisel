import Foundation
import CryptoKit
import Security

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

    /// Best-effort wipe of this buffer in place (`memset_s`, not optimised away). Swift value semantics
    /// can leave other copies behind, so this narrows the exposure window; it is not a guarantee.
    mutating func zeroize() {
        withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress, buffer.count > 0 { _ = memset_s(base, buffer.count, 0, buffer.count) }
        }
    }

    /// Comparison whose duration does not depend on where the first difference is. Use it for anything
    /// secret-derived (MACs, tokens, keys); ordinary `==` is fine for public keys and ciphertext.
    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else { return false }
        var diff: UInt8 = 0
        for (a, b) in zip(self, other) { diff |= a ^ b }
        return diff == 0
    }
}

public enum BiselRandom {
    public static func bytes(_ count: Int) -> Data {
        var d = Data(count: count)
        let status = d.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return errSecSuccess }   // count == 0
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        // A CSPRNG failure is unrecoverable: continuing would mean weak keys.
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed (\(status))")
        return d
    }

    /// Opaque 128-bit identifier (items, devices): 22 base64url characters (the server accepts 16-64 of [A-Za-z0-9_-]).
    public static func identifier() -> String { bytes(16).base64URLEncoded() }

    public static func nonce() -> String { bytes(16).base64URLEncoded() }
}
