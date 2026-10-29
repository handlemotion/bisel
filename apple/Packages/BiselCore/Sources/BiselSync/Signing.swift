import Foundation
import CryptoKit
import BiselCrypto
import BiselKeyStore

/// Produces the `X-Bisel-Device` header value and signs the canonical request string.
public protocol RequestSigner: Sendable {
    var deviceHeader: String { get }
    func sign(_ message: Data) throws -> Data
}

/// ECDSA P-256 via the device's DK-sig (Secure Enclave or software).
public struct DeviceSigner: RequestSigner {
    public let deviceID: String
    let keyStore: any DeviceKeyStore
    public init(deviceID: String, keyStore: any DeviceKeyStore) { self.deviceID = deviceID; self.keyStore = keyStore }
    public var deviceHeader: String { deviceID }
    public func sign(_ message: Data) throws -> Data { try keyStore.sign(message) }
}

/// Ed25519 with RK-sig, used only by recovery on a fresh install.
public struct RecoverySigner: RequestSigner {
    let key: Curve25519.Signing.PrivateKey
    public init(keys: RecoveryKeys) { key = keys.signingKey }
    public var deviceHeader: String { "recovery" }
    public func sign(_ message: Data) throws -> Data { try key.signature(for: message) }
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
