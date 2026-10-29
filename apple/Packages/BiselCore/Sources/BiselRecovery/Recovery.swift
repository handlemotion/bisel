import Foundation
import BiselCrypto
import BiselVault
import BiselSync

/// A freshly generated recovery phrase together with what the server stores for it.
public struct RecoveryBundle: Sendable, CustomStringConvertible, CustomReflectable {
    public let phrase: RecoveryPhrase
    public let publicKey: Data     // RK-sig public key (Ed25519, 32 bytes)
    public let encryptionPublicKey: Data   // RK-enc public key (X25519, 32 bytes): the envelope is sealed to it
    public let envelope: Data      // VK sealed to RK-enc (HPKE)
    public init(phrase: RecoveryPhrase, publicKey: Data, encryptionPublicKey: Data, envelope: Data) {
        self.phrase = phrase; self.publicKey = publicKey; self.encryptionPublicKey = encryptionPublicKey; self.envelope = envelope
    }
    public var description: String { "RecoveryBundle(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: []) }
}

public enum RecoveryService {
    /// New phrase + recovery envelope for `vaultKey`.
    public static func makeBundle(vaultKey: Data) throws -> RecoveryBundle {
        let phrase = try RecoveryPhrase.generate()
        let keys = try RecoveryKeys(phrase: phrase)
        return RecoveryBundle(phrase: phrase, publicKey: keys.publicKey, encryptionPublicKey: keys.encryptionPublicKey,
                              envelope: try keys.seal(vaultKey: vaultKey))
    }

    /// Rebuild-from-phrase, steps 1-2: authenticate to the server with RK-sig, fetch the recovery envelope
    /// and open it. Throws `SyncError.notAuthorized` for a wrong phrase (server cannot tell you more).
    public static func fetchVaultKey(server: URL, phrase: RecoveryPhrase) async throws -> (vaultKey: Data, keys: RecoveryKeys, epoch: Int) {
        let keys = try RecoveryKeys(phrase: phrase)
        let client = SyncClient(baseURL: server, signer: RecoverySigner(keys: keys))
        let (envelope, epoch) = try await client.recoveryEnvelope()
        return (try keys.open(envelope: envelope), keys, epoch)
    }
}

/// `.bisel-backup`: the server's records plus the recovery public key and recovery envelope in one
/// JSON file. Item blobs are the same ciphertext the server holds and the envelope is sealed under
/// the recovery key, so only the recovery phrase opens it.
public struct BackupFile: Codable, Sendable {
    public static let format = "bisel-backup"
    public static let fileExtension = "bisel-backup"
    /// 2: the recovery envelope is HPKE-sealed to `recovery_enc_pubkey` (1 used a symmetric RK-wrap key).
    public static let currentVersion = 2

    public struct Record: Codable, Sendable, Equatable {
        public var id: String
        public var rev: Int
        public var seq: Int
        public var deleted: Bool
        public var blob: String
        public var updatedAt: Int
    }

    public var format: String
    public var version: Int
    public var createdAt: Int
    public var recoveryAlg: String
    public var recoveryPubkey: String
    public var recoveryEncPubkey: String
    public var recoveryEnvelope: String
    public var items: [Record]

    public init(recoveryPublicKey: Data, recoveryEncryptionPublicKey: Data, recoveryEnvelope: Data, records: [StoredRecord],
                createdAt: Date = Date()) {
        format = Self.format; version = Self.currentVersion; self.createdAt = Int(createdAt.timeIntervalSince1970)
        recoveryAlg = "ed25519"
        recoveryPubkey = recoveryPublicKey.base64URLEncoded()
        recoveryEncPubkey = recoveryEncryptionPublicKey.base64URLEncoded()
        self.recoveryEnvelope = recoveryEnvelope.base64URLEncoded()
        items = records.filter { $0.pending == .none || $0.baseRev > 0 }.map {
            Record(id: $0.id, rev: $0.rev, seq: $0.seq, deleted: $0.deleted, blob: $0.blob.base64URLEncoded(), updatedAt: $0.updatedAt)
        }
    }

    public func encoded() throws -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        e.keyEncodingStrategy = .convertToSnakeCase
        return try e.encode(self)
    }

    public static func decode(_ data: Data) throws -> BackupFile {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        guard let file = try? d.decode(BackupFile.self, from: data), file.format == Self.format else {
            throw VaultError.badBackup("not a bisel backup file")
        }
        guard file.version == Self.currentVersion, file.recoveryAlg == "ed25519" else { throw VaultError.badBackup("unsupported backup version") }
        return file
    }

    /// Opens the recovery envelope with the phrase; fails if the phrase does not belong to this backup.
    public func vaultKey(phrase: RecoveryPhrase) throws -> (vaultKey: Data, keys: RecoveryKeys) {
        let keys = try RecoveryKeys(phrase: phrase)
        guard Data(base64URLEncoded: recoveryPubkey) == keys.publicKey,
              Data(base64URLEncoded: recoveryEncPubkey) == keys.encryptionPublicKey,
              let env = Data(base64URLEncoded: recoveryEnvelope) else { throw VaultError.badBackup("wrong recovery phrase for this backup") }
        do { return (try keys.open(envelope: env), keys) } catch { throw VaultError.badBackup("wrong recovery phrase for this backup") }
    }

    public var records: [StoredRecord] {
        items.compactMap { r in
            Data(base64URLEncoded: r.blob).map {
                StoredRecord(id: r.id, rev: r.rev, seq: r.seq, deleted: r.deleted, blob: $0, updatedAt: r.updatedAt)
            }
        }
    }
}
