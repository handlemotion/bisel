import Foundation
import CryptoKit
import BIP39

/// 24-word BIP-39 phrase; the 256-bit entropy is RK.
public struct RecoveryPhrase: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let words: [String]

    /// The phrase as typed back by the user. This is the secret itself: only use it to display it once.
    public var text: String { words.joined(separator: " ") }

    // `print(phrase)`, string interpolation, `dump` and error descriptions never show the words.
    public var description: String { "RecoveryPhrase(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }

    public static func generate() throws -> RecoveryPhrase {
        var entropy = [UInt8](BiselRandom.bytes(32))
        defer { for i in entropy.indices { entropy[i] = 0 } }
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
///
/// The recovery envelope is *asymmetric*: VK is HPKE-sealed (X25519, HKDF-SHA256, AES-256-GCM) to a public
/// key derived from RK. Any enrolled device can therefore write a fresh recovery envelope (for example
/// when the vault key rotates) from the public key alone, without ever holding the phrase; only the
/// phrase can open it.
public struct RecoveryKeys: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let encryptionKey: Curve25519.KeyAgreement.PrivateKey   // seed = HKDF(RK, "bisel/v1/recovery-enc")
    public let signingKey: Curve25519.Signing.PrivateKey           // seed = HKDF(RK, "bisel/v1/recovery-sig")

    public var description: String { "RecoveryKeys(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }

    public init(phrase: RecoveryPhrase) throws {
        var rk = try phrase.entropy()
        defer { rk.zeroize() }
        var encSeed = Aead.hkdf(rk, info: "bisel/v1/recovery-enc").withUnsafeBytes { Data($0) }
        var sigSeed = Aead.hkdf(rk, info: "bisel/v1/recovery-sig").withUnsafeBytes { Data($0) }
        defer { encSeed.zeroize(); sigSeed.zeroize() }
        encryptionKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: encSeed)
        signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: sigSeed)
    }

    /// RK-sig public key (Ed25519, 32 bytes): authenticates recovery requests.
    public var publicKey: Data { signingKey.publicKey.rawRepresentation }
    /// RK-enc public key (X25519, 32 bytes): what the recovery envelope is sealed to.
    public var encryptionPublicKey: Data { encryptionKey.publicKey.rawRepresentation }

    private static let suite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
    private static let info = Data("bisel/v1|recovery-envelope".utf8)
    private static let encapsulatedKeyLength = 32

    /// Recovery envelope: a copy of VK sealed to `encryptionPublicKey`. Layout: encapsulated key (32) || ciphertext.
    public static func seal(vaultKey: Data, toEncryptionKey publicKey: Data) throws -> Data {
        do {
            let recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            var sender = try HPKE.Sender(recipientKey: recipient, ciphersuite: suite, info: info)
            return sender.encapsulatedKey + (try sender.seal(vaultKey, authenticating: Data()))
        } catch {
            throw BiselCryptoError.envelopeFailed("recovery envelope: \(type(of: error))")
        }
    }

    /// Seals to this phrase's own public key (bootstrap).
    public func seal(vaultKey: Data) throws -> Data { try Self.seal(vaultKey: vaultKey, toEncryptionKey: encryptionPublicKey) }

    public func open(envelope: Data) throws -> Data {
        guard envelope.count > Self.encapsulatedKeyLength + Aead.overhead - 12 else { throw BiselCryptoError.malformedCiphertext }
        do {
            var recipient = try HPKE.Recipient(privateKey: encryptionKey, ciphersuite: Self.suite, info: Self.info,
                                               encapsulatedKey: envelope.prefix(Self.encapsulatedKeyLength))
            return try recipient.open(envelope.dropFirst(Self.encapsulatedKeyLength), authenticating: Data())
        } catch {
            throw BiselCryptoError.authenticationFailed
        }
    }
}
