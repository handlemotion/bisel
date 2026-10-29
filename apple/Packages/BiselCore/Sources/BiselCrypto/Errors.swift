import Foundation

public enum BiselCryptoError: Error, Equatable, Sendable {
    /// AEAD authentication failed: wrong key, wrong item id / revision (swap attempt), or tampering.
    case authenticationFailed
    case malformedCiphertext
    case invalidRecoveryPhrase
    case invalidPublicKey
    case envelopeFailed(String)
}
