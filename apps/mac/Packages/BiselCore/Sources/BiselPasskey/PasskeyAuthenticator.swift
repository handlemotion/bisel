import Foundation
import CryptoKit
import BiselCrypto

public enum PasskeyError: Error, Sendable, Equatable {
    /// The site does not accept ES256, the only algorithm Bisel makes.
    case unsupportedAlgorithm
    /// An empty RP ID, a user handle outside 1...64 bytes, or a client data hash that is not 32 bytes.
    case invalidRequest
    /// This box already holds a credential the site listed as excluded.
    case excludedCredential
    case noCredential
}

/// What a registration gives the site. `credential` goes in the box.
public struct PasskeyRegistration: Sendable, Equatable {
    public let credential: PasskeyCredential
    public let attestationObject: Data
    public var credentialID: Data { credential.credentialID }
}

public struct PasskeyAssertion: Sendable, Equatable {
    public let credentialID: Data
    public let userHandle: Data
    public let authenticatorData: Data
    /// ASN.1 DER ECDSA over `authenticatorData || clientDataHash`.
    public let signature: Data
}

/// The WebAuthn authenticator model (Level 3 §6): pure functions, no box access. Keys are software P-256 keys rather than Secure
/// Enclave ones, because a passkey has to reach the person's other devices.
public enum PasskeyAuthenticator {
    /// COSE algorithm ES256.
    public static let es256 = -7
    /// All zeros: `none` attestation makes no claim about what kind of authenticator this is.
    public static let aaguid = Data(count: 16)
    static let credentialIDLengths = 16...1023
    static let userHandleLengths = 1...64

    private enum Flag {
        static let userPresent: UInt8 = 0x01
        static let userVerified: UInt8 = 0x04
        static let backupEligible: UInt8 = 0x08
        static let backedUp: UInt8 = 0x10
        static let attestedCredentialData: UInt8 = 0x40
    }

    public static func normalized(rpID: String) -> String { rpID.lowercased() }

    /// Makes a key and the attestation object for it. The client data hash plays no part: `none` attestation signs nothing.
    /// `backedUp`: the box syncs somewhere, so the key survives losing this device.
    public static func register(rpID: String, userHandle: Data, userName: String, userDisplayName: String,
                                userVerified: Bool, backedUp: Bool, createdAt: Date = Date()) throws -> PasskeyRegistration {
        let rp = normalized(rpID: rpID)
        guard !rp.isEmpty, userHandleLengths.contains(userHandle.count) else { throw PasskeyError.invalidRequest }
        let key = P256.Signing.PrivateKey()
        let credential = PasskeyCredential(credentialID: BiselRandom.bytes(32), rpID: rp, userHandle: userHandle, userName: userName,
                                           userDisplayName: userDisplayName, signCount: 0, createdAt: createdAt,
                                           privateKey: key.rawRepresentation)
        var attested = aaguid
        attested.append(contentsOf: [UInt8(credential.credentialID.count >> 8), UInt8(credential.credentialID.count & 0xff)])
        attested.append(credential.credentialID)
        attested.append(coseKey(key.publicKey))
        let data = authenticatorData(rpID: rp, signCount: 0, userVerified: userVerified, backedUp: backedUp, attested: attested)
        // Keys in CTAP2 canonical order: shorter first.
        let object = CBOR.map([(.text("fmt"), .text("none")), (.text("attStmt"), .map([])), (.text("authData"), .bytes(data))])
        return PasskeyRegistration(credential: credential, attestationObject: object.encoded)
    }

    /// Signs in with `credential`.
    public static func assert(_ credential: PasskeyCredential, clientDataHash: Data, userVerified: Bool, backedUp: Bool) throws -> PasskeyAssertion {
        guard clientDataHash.count == SHA256.byteCount else { throw PasskeyError.invalidRequest }
        let data = authenticatorData(rpID: credential.rpID, signCount: credential.signCount, userVerified: userVerified, backedUp: backedUp, attested: nil)
        let key = try P256.Signing.PrivateKey(rawRepresentation: credential.privateKey)
        let signature = try key.signature(for: data + clientDataHash)
        return PasskeyAssertion(credentialID: credential.credentialID, userHandle: credential.userHandle,
                                authenticatorData: data, signature: signature.derRepresentation)
    }

    /// WebAuthn §6.1: rpIdHash, flags, signCount, then the attested credential data on a registration. Backup eligible is always
    /// set: it may not change over a credential's life, and any box can start syncing later.
    private static func authenticatorData(rpID: String, signCount: UInt32, userVerified: Bool, backedUp: Bool, attested: Data?) -> Data {
        var flags = Flag.userPresent | Flag.backupEligible
        if userVerified { flags |= Flag.userVerified }
        if backedUp { flags |= Flag.backedUp }
        if attested != nil { flags |= Flag.attestedCredentialData }
        var out = Data(SHA256.hash(data: Data(rpID.utf8)))
        out.append(flags)
        withUnsafeBytes(of: signCount.bigEndian) { out.append(contentsOf: $0) }
        if let attested { out.append(attested) }
        return out
    }

    /// RFC 9053 EC2 key: kty 2, alg ES256, crv P-256, x, y.
    private static func coseKey(_ key: P256.Signing.PublicKey) -> Data {
        let point = key.rawRepresentation
        return CBOR.map([(.int(1), .int(2)), (.int(3), .int(es256)), (.int(-1), .int(1)),
                         (.int(-2), .bytes(point.prefix(32))), (.int(-3), .bytes(point.suffix(32)))]).encoded
    }
}

/// The few CBOR shapes (RFC 8949) a registration needs, in definite-length form as CTAP2 requires.
private indirect enum CBOR {
    case int(Int), bytes(Data), text(String), map([(CBOR, CBOR)])

    var encoded: Data {
        switch self {
        case .int(let v): v >= 0 ? Self.head(0, UInt64(v)) : Self.head(1, UInt64(-1 - v))
        case .bytes(let v): Self.head(2, UInt64(v.count)) + v
        case .text(let v): Self.head(3, UInt64(v.utf8.count)) + Data(v.utf8)
        case .map(let pairs): pairs.reduce(Self.head(5, UInt64(pairs.count))) { $0 + $1.0.encoded + $1.1.encoded }
        }
    }

    private static func head(_ major: UInt8, _ value: UInt64) -> Data {
        let type = major << 5
        switch value {
        case 0..<24: return Data([type | UInt8(value)])
        case 24...0xff: return Data([type | 24, UInt8(value)])
        case 0x100...0xffff: return Data([type | 25, UInt8(value >> 8), UInt8(value & 0xff)])
        default: return Data([type | 26] + (0..<4).reversed().map { UInt8((value >> ($0 * 8)) & 0xff) })
        }
    }
}
