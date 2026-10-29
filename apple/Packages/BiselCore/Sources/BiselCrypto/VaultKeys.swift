import Foundation
import CryptoKit

/// Keys and codes derived from the vault key (§4). Everything here needs VK, so producing it needs an unlocked vault.
public enum VaultAdmin {
    /// The vault-admin key: Ed25519 with seed `HKDF(VK, "bisel/v1/admin-sig")`. Its public key is registered at bootstrap
    /// and moves with every rotation. Destructive server routes (rotate, approve, revoke, replace the recovery key)
    /// require a second signature by it, so a stolen device-signing key (which never prompts) cannot destroy the vault.
    public static func signingKey(vaultKey: Data) throws -> Curve25519.Signing.PrivateKey {
        var seed = Aead.hkdf(vaultKey, info: "bisel/v1/admin-sig").withUnsafeBytes { Data($0) }
        defer { seed.zeroize() }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    public static func signingKey(vaultKey: SymmetricKey) throws -> Curve25519.Signing.PrivateKey {
        try signingKey(vaultKey: vaultKey.withUnsafeBytes { Data($0) })
    }

    /// The string the admin signature covers: a domain label, the signing device, and the exact canonical request string
    /// the device signature covers (method, path, query, body hash, timestamp, single-use nonce).
    public static func message(device: String, canonicalRequest: String) -> Data {
        Data("bisel-admin/v1\n\(device)\n\(canonicalRequest)".utf8)
    }

    /// Short code derived from VK, shown on the approving device and on the new one; the human compares them.
    /// 40 bits: an attacker who swapped in a different VK matches it with probability 2^-40 per attempt, and gets one attempt.
    public static func verificationCode(vaultKey: Data) -> String {
        let bytes = [UInt8](Aead.hkdf(vaultKey, info: "bisel/v1/verify", count: 5).withUnsafeBytes { Data($0) })
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        var bits = bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        var chars: [Character] = []
        for _ in 0..<8 { chars.append(alphabet[Int(bits & 31)]); bits >>= 5 }
        let s = String(chars)
        return "\(s.prefix(4))-\(s.suffix(4))"
    }

    public static func verificationCode(vaultKey: SymmetricKey) -> String {
        verificationCode(vaultKey: vaultKey.withUnsafeBytes { Data($0) })
    }
}

public extension Data {
    /// Remove control, format (bidi override, zero width), separator and unassigned scalars from a name that came from outside.
    static func sanitizedName(_ s: String, limit: Int = 100) -> String {
        let bad: Set<Unicode.GeneralCategory> = [.control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .unassigned, .surrogate]
        let cleaned = String(String.UnicodeScalarView(s.unicodeScalars.filter { !bad.contains($0.properties.generalCategory) }))
        let trimmed = cleaned.trimmingCharacters(in: .whitespaces)
        return String(trimmed.prefix(limit))
    }
}
