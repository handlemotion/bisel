import Foundation
import CryptoKit

/// Item encryption (§4): payload under a fresh per-item key IK, IK wrapped under VK.
/// Both AEAD operations authenticate `bisel/v1|item|<id>|<rev>`, so a blob cannot be moved to
/// another item id or replayed at another revision.
///
/// blob = wrappedIK (60 bytes: nonce || key || tag) || payload (nonce || padded ciphertext || tag)
public enum ItemSealer {
    static let wrappedKeyLength = 32 + Aead.overhead

    public static func aad(id: String, rev: Int) -> Data { Data("bisel/v1|item|\(id)|\(rev)".utf8) }

    public static func seal(payload: Data, id: String, rev: Int, vaultKey: SymmetricKey) throws -> Data {
        let ik = SymmetricKey(size: .bits256)
        let aad = aad(id: id, rev: rev)
        let ikBytes = ik.withUnsafeBytes { Data($0) }
        let wrapped = try Aead.seal(ikBytes, key: vaultKey, aad: aad)
        let body = try Aead.seal(Padding.pad(payload), key: ik, aad: aad)
        return wrapped + body
    }

    public static func open(blob: Data, id: String, rev: Int, vaultKey: SymmetricKey) throws -> Data {
        guard blob.count > wrappedKeyLength + Aead.overhead else { throw BiselCryptoError.malformedCiphertext }
        let aad = aad(id: id, rev: rev)
        let wrapped = blob.prefix(wrappedKeyLength)
        let body = blob.dropFirst(wrappedKeyLength)
        let ik = SymmetricKey(data: try Aead.open(Data(wrapped), key: vaultKey, aad: aad))
        return try Padding.unpad(try Aead.open(Data(body), key: ik, aad: aad))
    }
}
