import Foundation

public enum BiselCryptoError: Error, Equatable, Sendable {
    /// AEAD authentication failed: wrong key, wrong item id / revision (swap attempt), or tampering.
    case authenticationFailed
    case malformedCiphertext
    case invalidRecoveryPhrase
    /// Not 8 words from the BIP-39 list, or not a pairing QR code.
    case invalidPairingSecret
    case invalidPublicKey
    case envelopeFailed(String)
}
