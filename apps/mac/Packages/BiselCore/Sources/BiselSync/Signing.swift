import Foundation
import CryptoKit
import BiselCrypto
import BiselKeyStore

/// Produces the `X-Bisel-Device` header value and signs the canonical request string.
public protocol RequestSigner: Sendable {
    var deviceHeader: String { get }
    func sign(_ message: Data) throws -> Data
    /// Headers besides the four signature headers (`X-Bisel-Box` for recovery).
    var extraHeaders: [String: String] { get }
}

public extension RequestSigner {
    var extraHeaders: [String: String] { [:] }
}

/// ECDSA P-256 via the device's DK-sig (Secure Enclave or software).
public struct DeviceSigner: RequestSigner {
    public let deviceID: String
    let keyStore: any DeviceKeyStore
    public init(deviceID: String, keyStore: any DeviceKeyStore) { self.deviceID = deviceID; self.keyStore = keyStore }
    public var deviceHeader: String { deviceID }
    public func sign(_ message: Data) throws -> Data { try keyStore.sign(message) }
}

/// Ed25519 with RK-sig, used only by recovery on a fresh install. `boxID` names the box on a multi-tenant server
/// (`X-Bisel-Box`); without it the server answers for its pre-accounts box.
public struct RecoverySigner: RequestSigner {
    let key: Curve25519.Signing.PrivateKey
    public let boxID: String?
    public init(keys: RecoveryKeys, boxID: String? = nil) { key = keys.signingKey; self.boxID = boxID }
    public var deviceHeader: String { "recovery" }
    public var extraHeaders: [String: String] { boxID.map { ["X-Bisel-Box": $0] } ?? [:] }
    public func sign(_ message: Data) throws -> Data { try key.signature(for: message) }
}

/// The vault-admin signature (SECURITY-REVIEW H1): Ed25519 by a key derived from VK, sent as `X-Bisel-Admin` on the routes
/// that can destroy or re-key the vault. Only an unlocked vault can make one.
public struct AdminSigner: Sendable {
    let key: Curve25519.Signing.PrivateKey
    public init(key: Curve25519.Signing.PrivateKey) { self.key = key }
    public init(vaultKey: Data) throws { key = try VaultAdmin.signingKey(vaultKey: vaultKey) }
    public var publicKey: Data { key.publicKey.rawRepresentation }
    /// Signs a record of a lane that has no server to check the request (control records, `ControlRecords`).
    public func sign(_ message: Data) throws -> Data { try key.signature(for: message) }
    func signature(device: String, canonicalRequest: String) throws -> Data {
        try key.signature(for: VaultAdmin.message(device: device, canonicalRequest: canonicalRequest))
    }
}

enum Canonical {
    private static let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    static func encode(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: unreserved) ?? s }

    /// `name=value` pairs, RFC 3986 percent-encoded, sorted by name then value, joined with `&`.
    static func sortedQuery(_ items: [(String, String)]) -> String {
        var pairs: [(name: String, value: String)] = []
        for (n, v) in items { pairs.append((name: encode(n), value: encode(v))) }
        pairs.sort { a, b in a.name == b.name ? a.value < b.value : a.name < b.name }
        return pairs.map { "\($0.name)=\($0.value)" }.joined(separator: "&")
    }

    static func string(method: String, path: String, query: String, body: Data, ts: String, nonce: String) -> String {
        [method, path, query, body.sha256Hex(), ts, nonce].joined(separator: "\n")
    }
}
