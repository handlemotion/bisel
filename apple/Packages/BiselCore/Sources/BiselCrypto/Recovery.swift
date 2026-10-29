import Foundation
import CryptoKit
import BIP39

/// 24-word BIP-39 phrase; the 256-bit entropy is RK.
public struct RecoveryPhrase: Sendable, Equatable {
    public let words: [String]

    public var text: String { words.joined(separator: " ") }

    public static func generate() throws -> RecoveryPhrase {
        let entropy = [UInt8](BiselRandom.bytes(32))
        return RecoveryPhrase(words: try Mnemonic.toMnemonic(entropy))
    }

    /// Accepts any whitespace/case; validates wordlist membership, length (24) and checksum.
    public init(_ text: String) throws {
        let words = text.lowercased().split(whereSeparator: { $0.isWhitespace }).map(String.init)
        guard words.count == 24, Mnemonic.isValid(phrase: words) else { throw BiselCryptoError.invalidRecoveryPhrase }
        self.words = words
    }

    private init(words: [String]) { self.words = words }

    /// RK: the 32 bytes of entropy encoded by the phrase.
    public func entropy() throws -> Data {
        do { return Data(try Mnemonic.toEntropy(words)) } catch { throw BiselCryptoError.invalidRecoveryPhrase }
    }
}

/// Everything derived from RK (§4).
public struct RecoveryKeys: Sendable {
    public let wrapKey: SymmetricKey                       // HKDF(RK, "bisel/v1/recovery-wrap")
    public let signingKey: Curve25519.Signing.PrivateKey   // seed = HKDF(RK, "bisel/v1/recovery-sig")

    public init(phrase: RecoveryPhrase) throws {
        let rk = try phrase.entropy()
        wrapKey = Aead.hkdf(rk, info: "bisel/v1/recovery-wrap")
        let seed = Aead.hkdf(rk, info: "bisel/v1/recovery-sig").withUnsafeBytes { Data($0) }
        signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    public var publicKey: Data { signingKey.publicKey.rawRepresentation }

    static let envelopeAAD = Data("bisel/v1|recovery-envelope".utf8)

    /// Recovery envelope: a copy of VK under RK-wrap.
    public func seal(vaultKey: Data) throws -> Data { try Aead.seal(vaultKey, key: wrapKey, aad: Self.envelopeAAD) }

    public func open(envelope: Data) throws -> Data { try Aead.open(envelope, key: wrapKey, aad: Self.envelopeAAD) }
}
