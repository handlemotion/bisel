import Foundation
import Security

/// Device envelope: VK encrypted to a device's DK-enc public key with ECIES
/// (`eciesEncryptionCofactorX963SHA256AESGCM`). Only the sealing half lives here (public key only);
/// opening requires the private key and is part of `DeviceKeyStore`.
public enum DeviceEnvelope {
    public static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM

    public static func publicSecKey(x963 data: Data) throws -> SecKey {
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: 256,
        ]
        var err: Unmanaged<CFError>?
        guard data.count == 65, let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &err) else {
            throw BiselCryptoError.invalidPublicKey
        }
        return key
    }

    public static func seal(vaultKey: Data, toEncryptionKey x963: Data) throws -> Data {
        let pub = try publicSecKey(x963: x963)
        var err: Unmanaged<CFError>?
        guard SecKeyIsAlgorithmSupported(pub, .encrypt, algorithm),
              let out = SecKeyCreateEncryptedData(pub, algorithm, vaultKey as CFData, &err) else {
            throw BiselCryptoError.envelopeFailed(err?.takeRetainedValue().localizedDescription ?? "unsupported")
        }
        return out as Data
    }
}
