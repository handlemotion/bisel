import Foundation
import CryptoKit
import BiselCrypto
import BiselVault

/// Why a `.bisel-backup` was refused. Each case is a different thing for the person to do, so they stay distinct.
public enum BackupError: Error, Sendable, Equatable, LocalizedError {
    /// Not a backup file at all (or a binary file of an unknown older layout).
    case notABackup
    /// Written by a newer Bisel (format `version`); update the app.
    case newerVersion(Int)
    /// The file ends early: `expected` bytes, `actual` present (an interrupted copy or download).
    case truncated(expected: Int, actual: Int)
    /// The file was changed after it was written (corruption, or someone edited it). Nothing in it is used.
    case tampered
    /// The 24 words are valid but are not the phrase this backup was made for.
    case wrongPhrase
    /// The box has no backup key yet (it predates backups v3): enter the 24 words once to export.
    case needsPhrase
    /// The recovery keys this device holds disagree with the box's manifest; sync first.
    case recoveryKeysUnknown
    /// Items do not open with the box key on this device; sync and try again.
    case unreadableItems(Int)

    public var errorDescription: String? {
        switch self {
        case .notABackup: return "This file is not a Bisel backup."
        case .newerVersion(let v): return "This backup was made by a newer version of Bisel (format \(v)). Update Bisel to restore it."
        case .truncated(let expected, let actual): return "This backup is incomplete (\(actual) of \(expected) bytes). Copy the whole file again."
        case .tampered: return "This backup was changed after it was written and cannot be trusted. Nothing was restored."
        case .wrongPhrase: return "These 24 words do not open this backup. Use the recovery phrase of the box it came from."
        case .needsPhrase: return "Enter your 24 words once to turn on encrypted backups for this box."
        case .recoveryKeysUnknown: return "This device does not know the box's recovery keys yet. Sync first."
        case .unreadableItems(let n): return "\(n) item(s) do not open with this box's key yet. Sync again and retry."
        }
    }
}

/// What the plaintext header says, readable without the phrase (SPEC §12).
public struct BackupHeader: Sendable, Equatable {
    public let version: Int
    public let createdAt: Date
    public let boxID: String
    /// Identifies the recovery key the file is sealed to, without revealing it.
    public let keyID: Data
    /// Size of the whole file in bytes.
    public let fileSize: Int
}

/// One item revision in a backup: the exact plaintext payload (SPEC §5), so nothing is lost even for a payload version this
/// build does not understand.
public struct BackupEntry: Codable, Sendable, Equatable {
    public var id: String
    public var rev: Int
    public var updatedAt: Int
    public var payload: Data
    public init(id: String, rev: Int, updatedAt: Int, payload: Data) {
        self.id = id; self.rev = rev; self.updatedAt = updatedAt; self.payload = payload
    }
}

/// A version the box kept in its 30-day history (the local trash).
public struct BackupHistoryEntry: Codable, Sendable, Equatable {
    public var id: String
    public var rev: Int
    public var updatedAt: Int
    public var replacedAt: Int
    public var reason: String
    public var payload: Data
    public init(id: String, rev: Int, updatedAt: Int, replacedAt: Int, reason: String, payload: Data) {
        self.id = id; self.rev = rev; self.updatedAt = updatedAt; self.replacedAt = replacedAt; self.reason = reason; self.payload = payload
    }
}

/// The encrypted body: everything needed to rebuild the box with no device, server or Apple ID.
public struct BackupContents: Codable, Sendable, Equatable, CustomStringConvertible, CustomReflectable {
    public var v = BackupArchive.version
    public var boxID: String
    public var createdAt: Int
    public var epoch: Int
    /// VK: a restore keeps the box's own key, so it is the same box (same verification code, same admin key).
    public var vaultKey: Data
    /// Roster and recovery pins, without the backup key (the restorer derives it from the phrase).
    public var manifest: VaultManifest
    public var items: [BackupEntry]
    public var history: [BackupHistoryEntry]

    public init(boxID: String, createdAt: Int, epoch: Int, vaultKey: Data, manifest: VaultManifest,
                items: [BackupEntry], history: [BackupHistoryEntry]) {
        self.boxID = boxID; self.createdAt = createdAt; self.epoch = epoch; self.vaultKey = vaultKey
        var manifest = manifest
        manifest.backupKey = nil; manifest.backupKeyFor = nil
        self.manifest = manifest; self.items = items; self.history = history
    }

    public var description: String { "BackupContents(box: \(boxID), items: \(items.count), history: \(history.count), contents redacted)" }
    public var customMirror: Mirror { Mirror(self, children: []) }

    /// Best-effort wipe of the key and payload copies this value holds.
    public mutating func zeroize() {
        vaultKey.zeroize()
        for i in items.indices { items[i].payload.zeroize() }
        for i in history.indices { history[i].payload.zeroize() }
    }
}

/// `.bisel-backup` format 3 (SPEC §12): a plaintext header and one HPKE message (X25519, HKDF-SHA256, AES-256-GCM) sealed to
/// the box's recovery encryption key in PSK mode. Opening needs the X25519 private key, so the 24 words; the PSK is the
/// backup key from the box's manifest, so making a file that opens needs the phrase or the box key, not just public keys.
public enum BackupArchive {
    public static let version = 3
    public static let fileExtension = "bisel-backup"
    static let magic = Data("BISELBAK".utf8)
    static let fixedHeader = 45            // magic .. box id length
    static let tagLength = 32
    static let encapsulatedKeyLength = 32
    static let maxBoxID = 64
    private static let suite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
    private static let info = Data("bisel/v1|backup|v3".utf8)
    private static let pskID = Data("bisel/v1|backup-psk".utf8)

    /// `HKDF(RK, "bisel/v1/backup-auth")`: the PSK. One-way, so it reveals nothing about the phrase or the recovery keys.
    public static func backupKey(phrase: RecoveryPhrase) throws -> Data {
        var rk = try phrase.entropy()
        defer { rk.zeroize() }
        return Aead.hkdf(rk, info: "bisel/v1/backup-auth").withUnsafeBytes { Data($0) }
    }

    /// First 16 bytes of `SHA-256("bisel/v1|backup-key-id|" || RK-enc public key)`.
    public static func keyID(recoveryEncryptionPublicKey: Data) -> Data {
        Data(SHA256.hash(data: Data("bisel/v1|backup-key-id|".utf8) + recoveryEncryptionPublicKey).prefix(16))
    }

    // MARK: write

    public static func seal(_ contents: BackupContents, recoveryEncryptionPublicKey: Data, backupKey: Data) throws -> Data {
        let boxID = Data(contents.boxID.utf8)
        guard boxID.count <= maxBoxID else { throw BackupError.notABackup }
        var body = try encoder().encode(contents)
        defer { body.zeroize() }
        var padded = Padding.pad(body)
        defer { padded.zeroize() }
        // HPKE adds the encapsulated key and the AES-GCM tag.
        let length = encapsulatedKeyLength + padded.count + 16
        var prefix = magic
        prefix.append(uint(UInt64(version), 2))
        prefix.append(uint(0, 2))                                        // flags, reserved
        prefix.append(uint(UInt64(contents.createdAt), 8))
        prefix.append(keyID(recoveryEncryptionPublicKey: recoveryEncryptionPublicKey))
        prefix.append(uint(UInt64(length), 8))
        prefix.append(UInt8(boxID.count))
        prefix.append(boxID)
        let sealed: Data
        do {
            let recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recoveryEncryptionPublicKey)
            var sender = try HPKE.Sender(recipientKey: recipient, ciphersuite: suite, info: info,
                                         presharedKey: SymmetricKey(data: backupKey), presharedKeyIdentifier: pskID)
            sealed = sender.encapsulatedKey + (try sender.seal(padded, authenticating: prefix))
        } catch {
            throw BiselCryptoError.envelopeFailed("backup: \(type(of: error))")
        }
        precondition(sealed.count == length)
        return prefix + integrityTag(prefix: prefix, sealed: sealed) + sealed
    }

    // MARK: read

    /// Checks structure, version, length and the integrity tag; needs no phrase. Every refusal happens here or in `open`,
    /// before anything is written anywhere.
    public static func inspect(_ file: Data) throws -> BackupHeader {
        try parse(file).header
    }

    /// Opens the file with the phrase. Throws `wrongPhrase` when the phrase is not the one the file was sealed to, `tampered`
    /// when it is and the file still does not authenticate.
    public static func open(_ file: Data, phrase: RecoveryPhrase) throws -> BackupContents {
        let parsed = try parse(file)
        let keys = try RecoveryKeys(phrase: phrase)
        guard keyID(recoveryEncryptionPublicKey: keys.encryptionPublicKey) == parsed.header.keyID else { throw BackupError.wrongPhrase }
        var psk = try backupKey(phrase: phrase)
        defer { psk.zeroize() }
        var padded: Data
        do {
            var recipient = try HPKE.Recipient(privateKey: keys.encryptionKey, ciphersuite: suite, info: info,
                                               encapsulatedKey: parsed.sealed.prefix(encapsulatedKeyLength),
                                               presharedKey: SymmetricKey(data: psk), presharedKeyIdentifier: pskID)
            padded = try recipient.open(parsed.sealed.dropFirst(encapsulatedKeyLength), authenticating: parsed.prefix)
        } catch {
            throw BackupError.tampered
        }
        defer { padded.zeroize() }
        guard let body = try? Padding.unpad(padded),
              let contents = try? decoder().decode(BackupContents.self, from: body),
              contents.v == version, contents.boxID == parsed.header.boxID,
              contents.createdAt == Int(parsed.header.createdAt.timeIntervalSince1970),
              contents.vaultKey.count == 32 else { throw BackupError.tampered }
        return contents
    }

    private struct Parsed { var header: BackupHeader; var prefix: Data; var sealed: Data }

    private static func parse(_ file: Data) throws -> Parsed {
        let file = Data(file)   // zero-based indices
        // Format 2 was JSON; it still opens through `BackupFile` (BiselRecovery).
        guard file.count >= magic.count, file.prefix(magic.count) == magic else { throw BackupError.notABackup }
        guard file.count >= fixedHeader else { throw BackupError.truncated(expected: fixedHeader, actual: file.count) }
        let version = Int(readUInt(file, 8, 2))
        if version > Self.version { throw BackupError.newerVersion(version) }
        guard version == Self.version else { throw BackupError.notABackup }
        guard readUInt(file, 10, 2) == 0 else { throw BackupError.newerVersion(version) }   // a flag this build does not know
        let created = readUInt(file, 12, 8)
        let keyID = file.subdata(in: 20..<36)
        let length = readUInt(file, 36, 8)
        let boxLength = Int(file[44])
        guard boxLength <= maxBoxID, length >= UInt64(encapsulatedKeyLength + 16 + Padding.block),
              length <= UInt64(Int.max / 2), created <= UInt64(Int64.max) else { throw BackupError.tampered }
        let headerLength = fixedHeader + boxLength + tagLength
        let total = headerLength + Int(length)
        guard file.count >= total else { throw BackupError.truncated(expected: total, actual: file.count) }
        guard file.count == total else { throw BackupError.tampered }
        let prefix = file.prefix(fixedHeader + boxLength)
        let tag = file.subdata(in: (fixedHeader + boxLength)..<headerLength)
        let sealed = file.subdata(in: headerLength..<total)
        guard integrityTag(prefix: prefix, sealed: sealed) == tag,
              let boxID = String(data: file.subdata(in: fixedHeader..<(fixedHeader + boxLength)), encoding: .utf8) else {
            throw BackupError.tampered
        }
        let header = BackupHeader(version: version, createdAt: Date(timeIntervalSince1970: TimeInterval(created)), boxID: boxID,
                                  keyID: keyID, fileSize: file.count)
        return Parsed(header: header, prefix: Data(prefix), sealed: sealed)
    }

    // MARK: helpers

    private static func integrityTag(prefix: Data, sealed: Data) -> Data {
        var h = SHA256()
        h.update(data: prefix)
        h.update(data: sealed)
        return Data(h.finalize())
    }

    private static func uint(_ value: UInt64, _ bytes: Int) -> Data {
        Data((0..<bytes).reversed().map { UInt8(truncatingIfNeeded: value >> (8 * UInt64($0))) })
    }

    private static func readUInt(_ data: Data, _ offset: Int, _ bytes: Int) -> UInt64 {
        data[offset..<(offset + bytes)].reduce(0) { ($0 << 8) | UInt64($1) }
    }

    private static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }

    private static func decoder() -> JSONDecoder { JSONDecoder() }
}
