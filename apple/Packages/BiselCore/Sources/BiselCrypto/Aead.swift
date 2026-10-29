import Foundation
import CryptoKit

/// AES-256-GCM helpers. Output is CryptoKit's `combined` form: nonce(12) || ciphertext || tag(16).
public enum Aead {
    public static let overhead = 12 + 16

    public static func seal(_ plaintext: Data, key: SymmetricKey, aad: Data) throws -> Data {
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        guard let combined = box.combined else { throw BiselCryptoError.malformedCiphertext }   // only nil for non-12-byte nonces
        return combined
    }

    public static func open(_ combined: Data, key: SymmetricKey, aad: Data) throws -> Data {
        guard combined.count >= overhead else { throw BiselCryptoError.malformedCiphertext }
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch is CryptoKitError {
            throw BiselCryptoError.authenticationFailed
        }
    }

    public static func hkdf(_ ikm: Data, info: String, count: Int = 32) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: Data(),
                               info: Data(info.utf8), outputByteCount: count)
    }
}

/// ISO/IEC 7816-4 padding up to a multiple of 512 bytes (0x80 then zeros). Always adds at least one byte.
public enum Padding {
    public static let block = 512

    public static func pad(_ data: Data) -> Data {
        var out = data
        out.append(0x80)
        let rem = out.count % block
        if rem != 0 { out.append(Data(count: block - rem)) }
        return out
    }

    public static func unpad(_ data: Data) throws -> Data {
        guard let idx = data.lastIndex(where: { $0 != 0 }), data[idx] == 0x80 else {
            throw BiselCryptoError.malformedCiphertext
        }
        return data.prefix(upTo: idx)
    }
}
