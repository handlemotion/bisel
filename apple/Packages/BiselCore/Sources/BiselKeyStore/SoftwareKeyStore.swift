#if BISEL_SOFTWARE_KEYS
import Foundation
import CryptoKit
import Security
import BiselCrypto
import OSLog

/// TEST-ONLY software P-256 key store. Private keys are written UNPROTECTED to a file.
/// Exists so flows can run headless (no Secure Enclave, no signing, no biometrics). It is only
/// compiled when the `SoftwareKeys` package trait defines BISEL_SOFTWARE_KEYS, never for Release.
///
/// DK-enc uses the same Security.framework ECIES algorithm as the Secure Enclave store, so
/// envelopes are byte-compatible between the two implementations.
public final class SoftwareDeviceKeyStore: DeviceKeyStore, @unchecked Sendable {
    public let implementation = "software"

    private struct Stored: Codable { var sig: Data; var enc: Data }   // x963 private representations
    private let url: URL
    private static let log = Logger(subsystem: "app.bisel", category: "keystore")

    public init(directory: URL) {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        url = directory.appendingPathComponent("software-keys.json")
        let message = "BISEL_SOFTWARE_KEYS: SOFTWARE KEY STORE IN USE. Device keys are in a plain file (\(url.path)). TEST ONLY, NOT SECURE."
        Self.log.fault("\(message, privacy: .public)")
        FileHandle.standardError.write(Data("warning: \(message)\n".utf8))
    }

    public func createKeys() throws -> DevicePublicKeys {
        let sig = P256.Signing.PrivateKey()
        let enc = P256.KeyAgreement.PrivateKey()
        let stored = Stored(sig: sig.x963Representation, enc: enc.x963Representation)
        try JSONEncoder().encode(stored).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return DevicePublicKeys(sig: sig.publicKey.x963Representation, enc: enc.publicKey.x963Representation)
    }

    private func load() throws -> Stored? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try JSONDecoder().decode(Stored.self, from: data)
    }

    public func publicKeys() throws -> DevicePublicKeys? {
        guard let s = try load() else { return nil }
        return DevicePublicKeys(sig: try P256.Signing.PrivateKey(x963Representation: s.sig).publicKey.x963Representation,
                                enc: try P256.KeyAgreement.PrivateKey(x963Representation: s.enc).publicKey.x963Representation)
    }

    public func sign(_ message: Data) throws -> Data {
        guard let s = try load() else { throw KeyStoreError.noKeys }
        return try P256.Signing.PrivateKey(x963Representation: s.sig).signature(for: message).rawRepresentation
    }

    public func openEnvelope(_ envelope: Data, reason: String) async throws -> Data {
        guard let s = try load() else { throw KeyStoreError.noKeys }
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                      kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(s.enc as CFData, attrs as CFDictionary, &err),
              let out = SecKeyCreateDecryptedData(key, DeviceEnvelope.algorithm, envelope as CFData, &err) else {
            throw KeyStoreError.failed(err?.takeRetainedValue().localizedDescription ?? "decrypt failed")
        }
        return out as Data
    }

    public func deleteKeys() throws { try? FileManager.default.removeItem(at: url) }
}

/// Auto-approves sensitive actions, loudly. Test only.
public struct SoftwareGate: BiometricGate {
    private static let log = Logger(subsystem: "app.bisel", category: "gate")
    public init() {}
    public func authenticate(reason: String) async throws {
        Self.log.fault("BISEL_SOFTWARE_KEYS: biometric check SKIPPED (\(reason, privacy: .public))")
    }
}
#endif
