import Foundation
import CryptoKit
import BiselCrypto
import BiselKeyStore

/// Reserved record ids. These are ordinary encrypted records on the server (so they sync, rotate and back up like items)
/// but are never shown as items.
public enum ReservedRecord {
    /// The vault manifest: approved devices and recovery pins, sealed under VK.
    public static let manifestID = "bisel-manifest-v1-reserved"
    public static func isReserved(_ id: String) -> Bool { id == manifestID }
}

/// A device the owner approved (or this device itself). Only a VK holder can add one: the manifest is AEAD-sealed under VK.
public struct RosterEntry: Codable, Sendable, Equatable, Identifiable {
    public var deviceID: String
    public var name: String
    public var kind: String
    public var sigPubkey: Data
    public var encPubkey: Data
    public var addedAt: Int
    /// How it got here: `bootstrap`, `approved`, `recovery`, `trusted` (the owner confirmed its fingerprint by hand).
    public var via: String
    public var id: String { deviceID }
    /// 96-bit fingerprint shown when approving.
    public var fingerprint: String { DevicePublicKeys(sig: sigPubkey, enc: encPubkey).fingerprint }

    public init(deviceID: String, name: String, kind: String, sigPubkey: Data, encPubkey: Data, addedAt: Int = Int(Date().timeIntervalSince1970), via: String) {
        self.deviceID = deviceID; self.name = Data.sanitizedName(name); self.kind = kind; self.sigPubkey = sigPubkey
        self.encPubkey = encPubkey; self.addedAt = addedAt; self.via = via
    }
}

/// What every device of the vault agrees on, itself end-to-end encrypted: who is allowed to receive the vault key, and which
/// recovery keys belong to this vault. It is what lets a freshly enrolled device learn the roster without trusting the server.
public struct VaultManifest: Codable, Sendable, Equatable {
    public var v = 1
    public var roster: [RosterEntry] = []
    public var recoveryPublicKey: Data?
    public var recoveryEncryptionPublicKey: Data?
    /// Bumped by every new recovery phrase; the highest generation wins.
    public var recoveryGeneration = 1

    public init(roster: [RosterEntry] = [], recoveryPublicKey: Data? = nil, recoveryEncryptionPublicKey: Data? = nil, recoveryGeneration: Int = 1) {
        self.roster = roster; self.recoveryPublicKey = recoveryPublicKey
        self.recoveryEncryptionPublicKey = recoveryEncryptionPublicKey; self.recoveryGeneration = recoveryGeneration
    }

    /// Union of rosters (by device id; on a clash of keys the entry already here wins), highest recovery generation wins.
    public func merged(with other: VaultManifest) -> VaultManifest {
        var out = self
        for e in other.roster where !out.roster.contains(where: { $0.deviceID == e.deviceID }) { out.roster.append(e) }
        if other.recoveryGeneration > out.recoveryGeneration {
            out.recoveryGeneration = other.recoveryGeneration
            out.recoveryPublicKey = other.recoveryPublicKey
            out.recoveryEncryptionPublicKey = other.recoveryEncryptionPublicKey
        }
        return out
    }
}

public enum ManifestCodec {
    public static func seal(_ m: VaultManifest, rev: Int, vaultKey: SymmetricKey) throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return try ItemSealer.seal(payload: try enc.encode(m), id: ReservedRecord.manifestID, rev: rev, vaultKey: vaultKey)
    }

    public static func open(_ record: StoredRecord, vaultKey: SymmetricKey) throws -> VaultManifest {
        let payload = try ItemSealer.open(blob: record.blob, id: record.id, rev: record.rev, vaultKey: vaultKey)
        do { return try JSONDecoder().decode(VaultManifest.self, from: payload) } catch { throw BiselCryptoError.malformedCiphertext }
    }
}

/// Failures that mean "do not trust what the server told you". Separate from `VaultError`/`SyncError` so existing
/// exhaustive switches keep compiling; all are `LocalizedError`s with text fit for a dialog.
public enum IntegrityError: Error, Sendable, Equatable, LocalizedError {
    /// The vault key this device received does not open the vault's own records: the envelope did not come from a device that holds the vault key.
    case keyConfirmationFailed
    /// Records exist but none decrypts under the current key.
    case noRecordDecrypts
    /// The code typed does not match the one the approving device shows.
    case verificationCodeMismatch
    /// Active devices that this device never approved (or whose keys differ from the approved ones). Rotation refuses to seal the new key to them.
    case unknownDevices([UnknownDevice])
    /// The server reports a lower head than this device already saw, or a cursor beyond its own head.
    case serverRolledBack(known: Int, reported: Int)
    case invalidCursor
    /// The recovery keys the server reports differ from the ones this device pinned.
    case recoveryMaterialChanged
    /// Recovery material is not pinned yet (sync first).
    case recoveryNotPinned
    /// This device was registered through the recovery phrase and is held back until `until`.
    case pendingActivation(until: Date)

    public var errorDescription: String? {
        switch self {
        case .keyConfirmationFailed: return "This device received a box key that does not open your box. Do not use it: remove this device and add it again from a device you trust, or recover with your 24 words."
        case .noRecordDecrypts: return "None of the stored items can be decrypted with this device's key. Something is wrong with the box key on this device or on the server."
        case .verificationCodeMismatch: return "The verification code does not match. Do not continue: someone may be interfering with the enrollment."
        case .unknownDevices(let d): return "\(d.count) device(s) on the server were never approved on this device: \(d.map(\.name).joined(separator: ", ")). Check each one's fingerprint, then trust or revoke it."
        case .serverRolledBack: return "The server reports an older state than this device already saw. It may have been restored from a backup or tampered with."
        case .invalidCursor: return "The server sent an inconsistent sync position and was ignored."
        case .recoveryMaterialChanged: return "The recovery keys on the server are not the ones this device recorded. Your recovery phrase may no longer work: create a new one from a device you trust."
        case .recoveryNotPinned: return "Sync first: this device has not yet confirmed the recovery keys."
        case .pendingActivation(let until): return "This device was added with the recovery phrase and is held back until \(until.formatted(date: .abbreviated, time: .shortened)). Your other devices can cancel it."
        }
    }
}

public struct UnknownDevice: Sendable, Equatable {
    public var id: String
    public var name: String
    public var kind: String
    public var fingerprint: String
    /// The device id is known but its keys differ from the approved ones.
    public var keysChanged: Bool
    public var pendingActivation: Bool
    public init(id: String, name: String, kind: String, fingerprint: String, keysChanged: Bool, pendingActivation: Bool) {
        self.id = id; self.name = name; self.kind = kind; self.fingerprint = fingerprint
        self.keysChanged = keysChanged; self.pendingActivation = pendingActivation
    }
}
