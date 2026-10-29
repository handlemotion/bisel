import Foundation
import CryptoKit

/// Item encryption (§4): payload under a fresh per-item key IK, IK wrapped under VK.
/// Both AEAD operations authenticate `bisel/v1|item|<id>|<rev>` plus a label of their own (`|wrap`, `|body`), so a blob
/// cannot be moved to another item id or replayed at another revision, and the wrapped key and the payload ciphertext
/// cannot stand in for each other.
///
/// blob = wrappedIK (60 bytes: nonce || key || tag) || payload (nonce || padded ciphertext || tag)
public enum ItemSealer {
    public static let wrappedKeyLength = 32 + Aead.overhead

    /// The id/revision binding shared by everything sealed for one revision of one item.
    public static func aad(id: String, rev: Int) -> Data { Data("bisel/v1|item|\(id)|\(rev)".utf8) }
    private static func wrapAAD(id: String, rev: Int) -> Data { aad(id: id, rev: rev) + Data("|wrap".utf8) }
    private static func bodyAAD(id: String, rev: Int) -> Data { aad(id: id, rev: rev) + Data("|body".utf8) }
    private static func tombstoneAAD(id: String, rev: Int) -> Data { aad(id: id, rev: rev) + Data("|tomb".utf8) }

    public static func seal(payload: Data, id: String, rev: Int, vaultKey: SymmetricKey) throws -> Data {
        let ik = SymmetricKey(size: .bits256)
        var ikBytes = ik.withUnsafeBytes { Data($0) }
        defer { ikBytes.zeroize() }
        let wrapped = try Aead.seal(ikBytes, key: vaultKey, aad: wrapAAD(id: id, rev: rev))
        let body = try Aead.seal(Padding.pad(payload), key: ik, aad: bodyAAD(id: id, rev: rev))
        return wrapped + body
    }

    /// Wrapped item key of a blob, re-wrapped from `old` to `new` with a fresh nonce. The payload part of the
    /// blob is untouched, so an item rotates by replacing the first `wrappedKeyLength` bytes. The AAD (id, rev)
    /// is unchanged: rotation never changes a record's revision.
    public static func rewrapKey(blob: Data, id: String, rev: Int, from old: SymmetricKey, to new: SymmetricKey) throws -> Data {
        guard blob.count > wrappedKeyLength + Aead.overhead else { throw BiselCryptoError.malformedCiphertext }
        let aad = wrapAAD(id: id, rev: rev)
        var ik = try Aead.open(Data(blob.prefix(wrappedKeyLength)), key: old, aad: aad)
        defer { ik.zeroize() }
        return try Aead.seal(ik, key: new, aad: aad)
    }

    public static func open(blob: Data, id: String, rev: Int, vaultKey: SymmetricKey) throws -> Data {
        guard blob.count > wrappedKeyLength + Aead.overhead else { throw BiselCryptoError.malformedCiphertext }
        let wrapped = blob.prefix(wrappedKeyLength)
        let body = blob.dropFirst(wrappedKeyLength)
        var ikBytes = try Aead.open(Data(wrapped), key: vaultKey, aad: wrapAAD(id: id, rev: rev))
        defer { ikBytes.zeroize() }
        return try Padding.unpad(try Aead.open(Data(body), key: SymmetricKey(data: ikBytes), aad: bodyAAD(id: id, rev: rev)))
    }

    // MARK: tombstones

    private static func tombstoneKey(_ vaultKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: vaultKey, salt: Data(), info: Data("bisel/v1/tombstone".utf8), outputByteCount: 32)
    }

    /// The blob a deleted record carries: a short marker only a VK holder can make for exactly this id and revision.
    /// Devices honour a remote delete only if its marker verifies; a delete forged without VK is undone locally.
    public static func sealTombstone(id: String, rev: Int, vaultKey: SymmetricKey) throws -> Data {
        try Aead.seal(Data("tomb".utf8), key: tombstoneKey(vaultKey), aad: tombstoneAAD(id: id, rev: rev))
    }

    public static func verifyTombstone(_ marker: Data, id: String, rev: Int, vaultKey: SymmetricKey) -> Bool {
        guard let plain = try? Aead.open(marker, key: tombstoneKey(vaultKey), aad: tombstoneAAD(id: id, rev: rev)) else { return false }
        return plain == Data("tomb".utf8)
    }
}
