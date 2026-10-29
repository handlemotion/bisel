import Foundation
import CryptoKit
import BiselCrypto

/// The public halves of a device's two P-256 keys, as ANSI X9.63 uncompressed points (65 bytes).
public struct DevicePublicKeys: Codable, Sendable, Equatable {
    public let sig: Data   // DK-sig
    public let enc: Data   // DK-enc
    public init(sig: Data, enc: Data) { self.sig = sig; self.enc = enc }

    /// Human-comparable fingerprint for approving an enrollment: 96 bits as six groups of four hex digits.
    public var fingerprint: String {
        let h = Data(SHA256.hash(data: sig + enc)).hexEncoded().prefix(24)
        return stride(from: 0, to: 24, by: 4).map { String(h.dropFirst($0).prefix(4)) }.joined(separator: "-")
    }
}

public enum KeyStoreError: Error, Sendable, Equatable {
    case noKeys
    case unavailable(String)
    case failed(String)
    case userCancelled
}

/// Device key custody (§4). Two P-256 keys per device:
/// - DK-enc opens the device envelope; on Secure Enclave it requires biometrics (`.biometryAny`).
/// - DK-sig signs requests and never prompts.
public protocol DeviceKeyStore: Sendable {
    /// "secure-enclave" or "software". Surfaced in logs and device lists.
    var implementation: String { get }
    /// Generates and persists a fresh key pair, replacing any existing one.
    func createKeys() throws -> DevicePublicKeys
    func publicKeys() throws -> DevicePublicKeys?
    /// ECDSA P-256 / SHA-256, returned as raw `r || s` (64 bytes), the form WebCrypto verifies.
    func sign(_ message: Data) throws -> Data
    /// ECIES-opens a device envelope with DK-enc. May show a biometric prompt (`reason`).
    func openEnvelope(_ envelope: Data, reason: String) async throws -> Data
    /// Opens several envelopes with one authentication (the Secure Enclave store shares one `LAContext`, so the user
    /// sees a single Touch ID sheet). Results are in the order of `envelopes`.
    func openEnvelopes(_ envelopes: [Data], reason: String) async throws -> [Data]
    func deleteKeys() throws
    /// Whether the keys are still usable; never prompts.
    func status() -> DeviceKeyStatus
}

public extension DeviceKeyStore {
    func status() -> DeviceKeyStatus { ((try? publicKeys()) ?? nil) == nil ? .missing : .ok }
    func openEnvelopes(_ envelopes: [Data], reason: String) async throws -> [Data] {
        var out: [Data] = []
        for e in envelopes { out.append(try await openEnvelope(e, reason: reason)) }
        return out
    }
}

/// Why this device's keys cannot be used (Secure Enclave). A new type, so `KeyStoreError` keeps its cases.
public enum DeviceKeyError: Error, Sendable, Equatable, LocalizedError {
    /// A fingerprint was added or removed since the keys were made: DK-enc was invalidated on purpose (`.biometryCurrentSet`).
    /// Nothing is lost: enrol this Mac again from another device or with the recovery phrase.
    case biometryChanged
    /// DK-sig exists but DK-enc does not (it was invalidated or deleted).
    case encryptionKeyMissing

    public var errorDescription: String? {
        switch self {
        case .biometryChanged: return "Touch ID fingerprints changed on this Mac, so this device's vault key is locked for safety. Add this Mac again from another device, or recover with your 24 words."
        case .encryptionKeyMissing: return "This device's vault key is no longer available. Add this Mac again from another device, or recover with your 24 words."
        }
    }
}

public enum DeviceKeyStatus: Sendable, Equatable {
    case ok
    case biometryChanged
    case missing
}

/// Fresh user-presence check for sensitive actions (§4 unlock model, point 3).
public protocol BiometricGate: Sendable {
    func authenticate(reason: String) async throws
}
