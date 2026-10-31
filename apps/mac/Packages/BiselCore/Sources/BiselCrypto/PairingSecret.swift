import Foundation
import CryptoKit

/// The secret a new device shows while it waits to be approved over a lane that is only storage (docs/SYNC-LANES.md §4, D6).
///
/// Everyone who can write to that storage can rewrite an enrollment request with keys of their own; the secret is what they
/// cannot see. The new device shows it (a QR code, or 8 words from the BIP-39 list for a Mac without a camera), the person
/// types or scans it into the approving device, and both sides bind what they write to it: the request's keys (`proof`) and
/// the envelope the approver sealed (`approval`). 88 random bits resist an offline guess without a password hash, which is
/// why the typed form is 8 words and not a short code (SPEC §4: every KDF input is high entropy, no PBKDF).
public struct PairingSecret: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public static let byteCount = 11
    public static let wordCount = 8
    static let qrPrefix = "bisel-pair:1:"

    /// The 88 bits. Kept by the new device until its enrollment completes (`LocalIdentity.pairingSecret`).
    public let rawValue: Data

    // Like the recovery phrase: `print`, interpolation and `dump` never show the secret.
    public var description: String { "PairingSecret(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }

    public static func generate() -> PairingSecret { PairingSecret(checked: BiselRandom.bytes(byteCount)) }

    public init(rawValue: Data) throws {
        guard rawValue.count == Self.byteCount else { throw BiselCryptoError.invalidPairingSecret }
        self.rawValue = rawValue
    }

    private init(checked: Data) { rawValue = checked }

    /// The 8 words as typed on the approving device: any case and surrounding whitespace, every word on the BIP-39 list.
    /// Eight words carry exactly 88 bits, so there is no checksum: a typo gives another secret, which the proof then refuses.
    public init(words: [String]) throws {
        let typed = words.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }.filter { !$0.isEmpty }
        guard typed.count == Self.wordCount else { throw BiselCryptoError.invalidPairingSecret }
        var bytes = Data(count: Self.byteCount)
        var bit = 0
        for word in typed {
            guard let index = Self.index[word] else { throw BiselCryptoError.invalidPairingSecret }
            for shift in (0..<11).reversed() {
                if index >> shift & 1 == 1 { bytes[bit / 8] |= UInt8(0x80) >> UInt8(bit % 8) }
                bit += 1
            }
        }
        rawValue = bytes
    }

    /// The secret as 8 BIP-39 words, 11 bits each, most significant bit first.
    public var words: [String] {
        (0..<Self.wordCount).map { w in
            var index = 0
            for i in (w * 11)..<(w * 11 + 11) { index = index << 1 | Int(rawValue[i / 8] >> UInt8(7 - i % 8) & 1) }
            return PassphraseWords.list[index]
        }
    }

    private static let index: [String: Int] = Dictionary(uniqueKeysWithValues: PassphraseWords.list.enumerated().map { ($1, $0) })

    // MARK: QR code

    /// What the new device puts in its QR code: `bisel-pair:1:<deviceID>:<base64url secret>`. The device id lets the approver
    /// pick the request the code belongs to; it is public anyway.
    public func qrPayload(deviceID: String) -> String { Self.qrPrefix + deviceID + ":" + rawValue.base64URLEncoded() }

    /// Reads a scanned QR code. Throws on anything that is not a version-1 pairing code.
    public static func parse(qrPayload: String) throws -> (deviceID: String, secret: PairingSecret) {
        guard qrPayload.hasPrefix(qrPrefix) else { throw BiselCryptoError.invalidPairingSecret }
        let parts = qrPayload.dropFirst(qrPrefix.count).split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, let raw = Data(base64URLEncoded: String(parts[1])) else { throw BiselCryptoError.invalidPairingSecret }
        return (String(parts[0]), try PairingSecret(rawValue: raw))
    }

    // MARK: what the secret binds

    private var key: SymmetricKey { Aead.hkdf(rawValue, info: "bisel/v1/enroll") }

    private static func requestMessage(deviceID: String, sigPubkey: Data, encPubkey: Data, createdAt: Int) -> Data {
        Data("bisel/v1/enroll-request|\(deviceID)|\(sigPubkey.base64URLEncoded())|\(encPubkey.base64URLEncoded())|\(createdAt)".utf8)
    }

    private static func approvalMessage(deviceID: String, envelopeHash: String, rootAdminKey: Data, epoch: Int) -> Data {
        Data("bisel/v1/enroll-approved|\(deviceID)|\(envelopeHash)|\(rootAdminKey.base64URLEncoded())|\(epoch)".utf8)
    }

    /// The new device's claim that these are its keys: only someone who saw the secret can make it for other keys.
    public func proof(deviceID: String, sigPubkey: Data, encPubkey: Data, createdAt: Int) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Self.requestMessage(deviceID: deviceID, sigPubkey: sigPubkey, encPubkey: encPubkey,
                                                                      createdAt: createdAt), using: key))
    }

    public func isValidProof(_ proof: Data, deviceID: String, sigPubkey: Data, encPubkey: Data, createdAt: Int) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: Self.requestMessage(deviceID: deviceID, sigPubkey: sigPubkey,
                                                                                           encPubkey: encPubkey, createdAt: createdAt), using: key)
    }

    /// The approver's word that it sealed this envelope (its SHA-256, hex) for the box whose admin-key chain starts at
    /// `rootAdminKey`, at `epoch`. A box someone else built around the new device's public keys cannot carry it.
    public func approval(deviceID: String, envelopeHash: String, rootAdminKey: Data, epoch: Int) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Self.approvalMessage(deviceID: deviceID, envelopeHash: envelopeHash,
                                                                       rootAdminKey: rootAdminKey, epoch: epoch), using: key))
    }

    public func isValidApproval(_ mac: Data, deviceID: String, envelopeHash: String, rootAdminKey: Data, epoch: Int) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: Self.approvalMessage(deviceID: deviceID, envelopeHash: envelopeHash,
                                                                                          rootAdminKey: rootAdminKey, epoch: epoch), using: key)
    }
}
