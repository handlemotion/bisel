import Foundation
import CryptoKit
import BiselCrypto

/// The public halves of a device's two P-256 keys, as ANSI X9.63 uncompressed points (65 bytes).
public struct DevicePublicKeys: Codable, Sendable, Equatable {
    public let sig: Data   // DK-sig
    public let enc: Data   // DK-enc
    public init(sig: Data, enc: Data) { self.sig = sig; self.enc = enc }

    /// Short human-comparable fingerprint for approving an enrollment.
    public var fingerprint: String {
        let h = Data(SHA256.hash(data: sig + enc)).hexEncoded().prefix(16)
        return stride(from: 0, to: 16, by: 4).map { String(h.dropFirst($0).prefix(4)) }.joined(separator: "-")
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
    func deleteKeys() throws
}

/// Fresh user-presence check for sensitive actions (§4 unlock model, point 3).
public protocol BiometricGate: Sendable {
    func authenticate(reason: String) async throws
}
