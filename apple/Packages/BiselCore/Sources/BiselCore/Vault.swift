@_exported import BiselCrypto
@_exported import BiselKeyStore
@_exported import BiselVault
@_exported import BiselSync
@_exported import BiselRecovery
@_exported import BiselTOTP
import Foundation
import CryptoKit

/// A device asking to join the vault. Carries public keys only, so it is safe to move over a QR code or a file.
public struct EnrollmentRequest: Codable, Sendable, Equatable {
    public var server: URL
    public var deviceID: String
    public var name: String
    public var kind: String
    public var sigPubkey: Data
    public var encPubkey: Data
    /// Show this on both devices and compare before approving.
    public var fingerprint: String { DevicePublicKeys(sig: sigPubkey, enc: encPubkey).fingerprint }
}

public struct ItemListing: Sendable {
    public var items: [Item]
    /// Records whose ciphertext failed authentication (wrong key, tampering, or moved to another id/revision). Never shown as items.
    public var undecryptable: [String]
}


/// One item a revoked device could read.
public struct ExposedItem: Sendable, Equatable, Identifiable {
    public var id: String
    public var title: String
    public var username: String?
    public var urls: [String]
    public var hasPassword: Bool
    public var hasTOTP: Bool
    public var updatedAt: Date
    /// False only when the server's (hour-rounded) "last seen" for that device is older than the item's last change:
    /// then it had no chance to sync that revision. Everything else should be treated as seen.
    public var mayHaveBeenRead: Bool
}

/// What a key rotation did, and, when it revoked a device, what that device could still have copied. Revoking cuts it off from
/// the server and re-keys everything the server holds, but cannot take back what the device already read: say so, and
/// offer to change those passwords.
public struct RotationReport: Sendable {
    public var epoch: Int
    public var revokedDeviceID: String?
    public var revokedDeviceName: String?
    public var revokedDeviceLastSeen: Date?
    public var exposed: [ExposedItem]
    /// The subset to change first: logins whose password or one-time secret the device may have read.
    public var secretsToChange: [ExposedItem] { exposed.filter { $0.mayHaveBeenRead && ($0.hasPassword || $0.hasTOTP) } }
}

/// A previous version of an item kept on this device's trash or by the server's history, decrypted.
public struct PastVersion: Sendable, Identifiable {
    public enum Source: Sendable, Equatable { case localTrash(reason: String), serverHistory }
    public var id: String
    public var itemID: String
    public var rev: Int
    public var item: Item
    public var replacedAt: Date
    public var source: Source
    fileprivate var localKey: Int?
}

public enum RecoveryError: Error, Sendable, Equatable, LocalizedError {
    case nothingToRestore
    public var errorDescription: String? { "That version can no longer be read with the current box key." }
}

/// Facade over the core (SPEC §7). One instance per device/store.
public actor Vault {
    public struct Configuration: Sendable {
        public var location: StoreLocation
        public var keyStore: any DeviceKeyStore
        public var gate: any BiometricGate
        /// How long VK stays in memory after `unlock` (§4: default 5 min).
        public var fillWindow: TimeInterval
        /// Free tag sent to the server: `mac`, `iphone`, `cli`...
        public var deviceKind: String
        /// Where small secrets (the server's address) live instead of the plaintext database. With the Secure Enclave key
        /// store this defaults to the Keychain in the same access group.
        public var secrets: (any SecretStore)?

        public init(location: StoreLocation, keyStore: any DeviceKeyStore, gate: any BiometricGate = LocalAuthenticationGate(),
                    fillWindow: TimeInterval = 300, deviceKind: String = "mac", secrets: (any SecretStore)? = nil) {
            self.location = location; self.keyStore = keyStore; self.gate = gate
            self.fillWindow = fillWindow; self.deviceKind = deviceKind
            if let secrets { self.secrets = secrets }
            else if let se = keyStore as? SecureEnclaveDeviceKeyStore { self.secrets = KeychainSecretStore(accessGroup: se.accessGroup) }
            else { self.secrets = nil }
        }

        /// Production configuration: Secure Enclave keys in the shared keychain access group, store in the App Group
        /// container (so the AutoFill extensions can open the same files). Both identifiers are injected, never
        /// hard-coded in the package; the app passes the ones from its signed entitlements.
        ///
        /// - Parameters:
        ///   - appGroupIdentifier: `<TEAMID>.app.bisel` on macOS, `group.app.bisel` on iOS.
        ///   - keychainAccessGroup: `<TEAMID>.app.bisel` (a `keychain-access-groups` entry), or nil for the app's default group.
        public static func secureEnclave(appGroupIdentifier: String, keychainAccessGroup: String?,
                                         keyTagPrefix: String = "app.bisel.device",
                                         gate: any BiometricGate = LocalAuthenticationGate(),
                                         fillWindow: TimeInterval = 300, deviceKind: String = "mac") throws -> Configuration {
            Configuration(location: try StoreLocation.appGroup(identifier: appGroupIdentifier),
                          keyStore: SecureEnclaveDeviceKeyStore(accessGroup: keychainAccessGroup, tagPrefix: keyTagPrefix),
                          gate: gate, fillWindow: fillWindow, deviceKind: deviceKind)
        }

        #if BISEL_SOFTWARE_KEYS
        /// Headless configuration: software keys in `location.directory`, biometric gate auto-approved. TEST ONLY.
        public static func software(location: StoreLocation, deviceKind: String = "cli", fillWindow: TimeInterval = 300) -> Configuration {
            Configuration(location: location, keyStore: SoftwareDeviceKeyStore(directory: location.directory),
                          gate: SoftwareGate(), fillWindow: fillWindow, deviceKind: deviceKind,
                          secrets: FileSecretStore(directory: location.directory))
        }
        #endif
    }

    private let config: Configuration
    private let store: LocalStore
    private var key: LockedKey?
    private var unlockedUntil: Date?
    private var rotationInProgress = false

    public init(_ configuration: Configuration) throws {
        config = configuration
        store = try LocalStore(location: configuration.location, secrets: configuration.secrets)
    }

    // MARK: state

    public func identity() throws -> LocalIdentity? { try store.identity() }
    public var isConfigured: Bool { ((try? store.identity()) ?? nil)?.envelope != nil }
    public var isUnlocked: Bool { liveKey() != nil }
    public func pendingChanges() throws -> Int { try store.pendingRecords().count }

    private func liveKey() -> LockedKey? {
        guard let key, let until = unlockedUntil, until > Date(), key.isLive else {
            lock()
            return nil
        }
        return key
    }

    private func requireKey() throws -> LockedKey {
        guard let k = liveKey() else { throw VaultError.locked }
        return k
    }

    private func requireIdentity() throws -> LocalIdentity {
        guard let id = try store.identity() else { throw VaultError.notConfigured }
        return id
    }

    private func client() throws -> SyncClient {
        let id = try requireIdentity()
        guard let server = id.serverURL else { throw VaultError.noServer }
        return SyncClient(baseURL: server, signer: DeviceSigner(deviceID: id.deviceID, keyStore: config.keyStore))
    }

    /// The vault-admin signer for the unlocked vault (needs VK, so a stolen device-signing key cannot make it).
    private func adminSigner(_ key: LockedKey) throws -> AdminSigner {
        var raw = try key.rawBytes()
        defer { raw.zeroize() }
        return try AdminSigner(vaultKey: raw)
    }

    private func setKey(_ vaultKey: Data) {
        key?.zero()
        key = LockedKey(vaultKey)
        unlockedUntil = Date().addingTimeInterval(config.fillWindow)
    }

    // MARK: lifecycle

    /// Biometric unlock: opens the device envelope with DK-enc and keeps VK in memory for the fill window.
    /// If another device rotated the vault key while local edits were still unsynced, those edits are re-wrapped
    /// under the new key here (one Touch ID sheet covers both envelopes).
    public func unlock(reason: String = "Unlock bisel") async throws {
        let id = try requireIdentity()
        guard let envelope = id.envelope else { throw VaultError.notConfigured }
        switch config.keyStore.status() {
        case .biometryChanged: throw DeviceKeyError.biometryChanged
        case .ok, .missing: break
        }
        let opened = try await config.keyStore.openEnvelopes([envelope] + (id.previousEnvelope.map { [$0] } ?? []), reason: reason)
        guard var vk = opened.first else { throw VaultError.notConfigured }
        defer { vk.zeroize() }
        if opened.count > 1 {
            var old = opened[1]
            defer { old.zeroize() }
            try rewrapPendingEdits(from: old, to: vk)
        }
        setKey(vk)
    }

    /// Local edits sealed under a rotated-away key get their wrapped item key re-wrapped under the current one.
    private func rewrapPendingEdits(from old: Data, to new: Data) throws {
        let oldKey = SymmetricKey(data: old), newKey = SymmetricKey(data: new)
        var unresolved = false
        for rec in try store.pendingRecords() where rec.pending == .delete {
            // A pending delete carries a marker sealed under the old key: seal a fresh one under the new key.
            try store.replacePendingBlob(id: rec.id, expectedRev: rec.rev, with: try ItemSealer.sealTombstone(id: rec.id, rev: rec.rev, vaultKey: newKey))
        }
        for rec in try store.pendingRecords() where rec.pending == .put {
            do {
                let wrapped = try ItemSealer.rewrapKey(blob: rec.blob, id: rec.id, rev: rec.rev, from: oldKey, to: newKey)
                try store.replacePendingBlob(id: rec.id, expectedRev: rec.rev, with: wrapped + rec.blob.dropFirst(ItemSealer.wrappedKeyLength))
            } catch {
                // Already under the new key (nothing to do) or unreadable (keep the envelope so a later unlock can retry).
                if (try? ItemSealer.open(blob: rec.blob, id: rec.id, rev: rec.rev, vaultKey: newKey)) == nil { unresolved = true }
            }
        }
        guard !unresolved, var id = try store.identity() else { return }
        id.previousEnvelope = nil
        try store.setIdentity(id)
    }

    /// Zeroes VK. Call on sleep, screen lock, idle timeout.
    public func lock() {
        key?.zero()
        key = nil
        unlockedUntil = nil
    }

    // MARK: bootstrap / recovery / enrollment

    /// First device: generates VK, device keys and the recovery phrase, registers with the server.
    /// The returned phrase is the only copy; show it once.
    public func bootstrap(server: URL, bootstrapToken: String, deviceName: String) async throws -> RecoveryPhrase {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        var vk = BiselRandom.bytes(32)
        defer { vk.zeroize() }
        let bundle = try RecoveryService.makeBundle(vaultKey: vk, epoch: 1)
        try await register(server: server, bootstrapToken: bootstrapToken, deviceName: deviceName, vaultKey: vk, recovery: bundle)
        // The phrase exists only in the caller's hands now: until it is proven written down, the flag stays.
        var identity = try requireIdentity()
        identity.recoveryUnconfirmed = true
        try store.setIdentity(identity)
        return bundle.phrase
    }

    /// First device, no server: the same keys, vault key and recovery phrase as `bootstrap`, kept on this Mac only.
    /// A server can be connected later with `connectServer`; until then nothing leaves the device.
    public func bootstrapLocal(deviceName: String) throws -> RecoveryPhrase {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        var vk = BiselRandom.bytes(32)
        defer { vk.zeroize() }
        let bundle = try RecoveryService.makeBundle(vaultKey: vk, epoch: 1)
        let pub = try config.keyStore.createKeys()
        let deviceID = BiselRandom.identifier()
        let envelope = try DeviceEnvelope.seal(vaultKey: vk, toEncryptionKey: pub.enc)
        var identity = LocalIdentity(deviceID: deviceID, deviceName: deviceName, serverURL: nil,
                                     keyStore: config.keyStore.implementation, envelope: envelope,
                                     recoveryPublicKey: bundle.publicKey, recoveryEnvelope: bundle.envelope,
                                     recoveryEncryptionPublicKey: bundle.encryptionPublicKey, epoch: 1)
        identity.roster = [RosterEntry(deviceID: deviceID, name: deviceName, kind: config.deviceKind, sigPubkey: pub.sig,
                                       encPubkey: pub.enc, via: "bootstrap")]
        identity.recoveryPinned = true
        identity.recoveryUnconfirmed = true
        try store.setIdentity(identity)
        setKey(vk)
        try writeManifest()
        return bundle.phrase
    }

    /// Registers this device and the recovery keys of an existing local-only vault with a fresh server. The next
    /// `sync()` uploads everything that was created while the vault was local.
    public func connectServer(_ server: URL, bootstrapToken: String) async throws {
        let key = try requireKey()
        var identity = try requireIdentity()
        guard identity.serverURL == nil else { throw VaultError.alreadyConfigured }
        guard let me = identity.roster.first(where: { $0.deviceID == identity.deviceID }), let envelope = identity.envelope,
              let recoveryPub = identity.recoveryPublicKey, let recoveryEnv = identity.recoveryEnvelope,
              let recoveryEncPub = identity.recoveryEncryptionPublicKey else { throw VaultError.notConfigured }
        try await config.gate.authenticate(reason: "Connect \(identity.deviceName) to a server")
        let device = WireDevice(id: identity.deviceID, name: identity.deviceName, kind: config.deviceKind, sigPubkey: me.sigPubkey,
                                encPubkey: me.encPubkey, envelope: envelope)
        try await SyncClient.bootstrap(baseURL: server, token: bootstrapToken, device: device, recoveryPublicKey: recoveryPub,
                                       recoveryEncryptionPublicKey: recoveryEncPub, recoveryEnvelope: recoveryEnv,
                                       adminPublicKey: try adminSigner(key).publicKey)
        identity.serverURL = server
        try store.setIdentity(identity)
    }

    private func register(server: URL, bootstrapToken: String, deviceName: String, vaultKey vk: Data, recovery: RecoveryBundle) async throws {
        let pub = try config.keyStore.createKeys()
        let deviceID = BiselRandom.identifier()
        let envelope = try DeviceEnvelope.seal(vaultKey: vk, toEncryptionKey: pub.enc)
        let device = WireDevice(id: deviceID, name: deviceName, kind: config.deviceKind, sigPubkey: pub.sig, encPubkey: pub.enc, envelope: envelope)
        try await SyncClient.bootstrap(baseURL: server, token: bootstrapToken, device: device,
                                       recoveryPublicKey: recovery.publicKey, recoveryEncryptionPublicKey: recovery.encryptionPublicKey,
                                       recoveryEnvelope: recovery.envelope, adminPublicKey: try AdminSigner(vaultKey: vk).publicKey)
        try store.setIdentity(LocalIdentity(deviceID: deviceID, deviceName: deviceName, serverURL: server,
                                            keyStore: config.keyStore.implementation, envelope: envelope,
                                            recoveryPublicKey: recovery.publicKey, recoveryEnvelope: recovery.envelope,
                                            recoveryEncryptionPublicKey: recovery.encryptionPublicKey, epoch: 1))
        var identity = try requireIdentity()
        identity.roster = [RosterEntry(deviceID: deviceID, name: deviceName, kind: config.deviceKind, sigPubkey: pub.sig,
                                       encPubkey: pub.enc, via: "bootstrap")]
        identity.recoveryPinned = true
        try store.setIdentity(identity)
        setKey(vk)
        try writeManifest()
    }

    /// New device, step 1: create keys and describe yourself. Give the result to an already-enrolled device.
    public func prepareEnrollment(server: URL, deviceName: String) throws -> EnrollmentRequest {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        let pub = try config.keyStore.createKeys()
        let deviceID = BiselRandom.identifier()
        try store.setIdentity(LocalIdentity(deviceID: deviceID, deviceName: deviceName, serverURL: server,
                                            keyStore: config.keyStore.implementation, envelope: nil))
        return EnrollmentRequest(server: server, deviceID: deviceID, name: deviceName, kind: config.deviceKind,
                                 sigPubkey: pub.sig, encPubkey: pub.enc)
    }

    /// Enrolled device, step 2: seal VK to the new device's DK-enc and register it. Needs a fresh biometric check.
    public func approveEnrollment(_ request: EnrollmentRequest) async throws {
        let vk = try requireKey()
        try await config.gate.authenticate(reason: "Add \(request.name) to your box")
        let epoch = try requireIdentity().epoch
        var raw = try vk.rawBytes()
        defer { raw.zeroize() }
        let envelope = try DeviceEnvelope.seal(vaultKey: raw, toEncryptionKey: request.encPubkey)
        do {
            try await client().addDevice(WireDevice(id: request.deviceID, name: request.name, kind: request.kind,
                                                    sigPubkey: request.sigPubkey, encPubkey: request.encPubkey, envelope: envelope,
                                                    epoch: epoch), admin: try adminSigner(vk))
        } catch RotationError.staleEpoch {
            // The vault key changed under us: adopt the new one (this locks the vault) and let the caller retry.
            _ = try? await sync()
            throw RotationError.vaultKeyRotated
        }
        // The owner approved this device with its public keys in hand: record it, and publish it in the sealed manifest
        // (best effort: the next sync pushes it if the network fails now).
        var identity = try requireIdentity()
        if !identity.roster.contains(where: { $0.deviceID == request.deviceID }) {
            identity.roster.append(RosterEntry(deviceID: request.deviceID, name: request.name, kind: request.kind,
                                               sigPubkey: request.sigPubkey, encPubkey: request.encPubkey, via: "approved"))
            try store.setIdentity(identity)
        }
        try writeManifest()
        _ = try? await sync()
    }

    /// New device, step 3 (after approval): fetch own envelope. Then `unlock()` and `sync()` work.
    public func completeEnrollment() async throws {
        var id = try requireIdentity()
        let (envelope, epoch) = try await client().envelope()
        id.envelope = envelope
        id.epoch = epoch
        id.enrollmentUnconfirmed = true   // until the code shown by the approving device has been checked
        try store.setIdentity(id)
    }

    /// Fresh install: rebuild from the recovery phrase (new device keys, VK from the recovery envelope).
    /// Call `sync()` afterwards, and consider `rotateRecovery()`.
    public func recover(server: URL, phrase: RecoveryPhrase, deviceName: String) async throws {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        var (vk, keys, epoch) = try await RecoveryService.fetchVaultKey(server: server, phrase: phrase)
        defer { vk.zeroize() }
        let pub = try config.keyStore.createKeys()
        let deviceID = BiselRandom.identifier()
        let envelope = try DeviceEnvelope.seal(vaultKey: vk, toEncryptionKey: pub.enc)
        let device = WireDevice(id: deviceID, name: deviceName, kind: config.deviceKind, sigPubkey: pub.sig, encPubkey: pub.enc, envelope: envelope)
        let activatesAt = try await SyncClient(baseURL: server, signer: RecoverySigner(keys: keys)).recoveryRegister(device: device, epoch: epoch)
        var identity = LocalIdentity(deviceID: deviceID, deviceName: deviceName, serverURL: server,
                                     keyStore: config.keyStore.implementation, envelope: envelope,
                                     recoveryPublicKey: keys.publicKey, recoveryEncryptionPublicKey: keys.encryptionPublicKey, epoch: epoch)
        // The phrase holder is the owner: this device is trusted, and the recovery keys are pinned from the phrase itself.
        identity.roster = [RosterEntry(deviceID: deviceID, name: deviceName, kind: config.deviceKind, sigPubkey: pub.sig,
                                       encPubkey: pub.enc, via: "recovery")]
        identity.recoveryPinned = true
        identity.activatesAt = activatesAt.map { Int($0.timeIntervalSince1970) }
        try store.setIdentity(identity)
        setKey(vk)
    }

    /// Replaces the recovery key and envelope (new phrase; the old one stops working immediately).
    public func rotateRecovery() async throws -> RecoveryPhrase {
        let vk = try requireKey()
        try await config.gate.authenticate(reason: "Create a new recovery phrase")
        var raw = try vk.rawBytes()
        defer { raw.zeroize() }
        var id = try requireIdentity()
        let bundle = try RecoveryService.makeBundle(vaultKey: raw, epoch: id.epoch)
        do {
            try await client().rotateRecovery(publicKey: bundle.publicKey, encryptionPublicKey: bundle.encryptionPublicKey,
                                              envelope: bundle.envelope, epoch: id.epoch, admin: try adminSigner(vk))
        } catch RotationError.staleEpoch {
            _ = try? await sync()
            throw RotationError.vaultKeyRotated
        }
        id.recoveryPublicKey = bundle.publicKey
        id.recoveryEncryptionPublicKey = bundle.encryptionPublicKey
        id.recoveryEnvelope = bundle.envelope
        id.recoveryGeneration += 1
        id.recoveryPinned = true
        id.recoveryMismatch = false
        id.recoveryUnconfirmed = true
        try store.setIdentity(id)
        try writeManifest()
        return bundle.phrase
    }

    // MARK: manifest, roster, confirmation

    private func manifestFromIdentity(_ id: LocalIdentity) -> VaultManifest {
        VaultManifest(roster: id.roster, recoveryPublicKey: id.recoveryPublicKey,
                      recoveryEncryptionPublicKey: id.recoveryEncryptionPublicKey, recoveryGeneration: id.recoveryGeneration)
    }

    /// Seals this device's view of the manifest (roster + recovery pins) as the reserved record; `sync()` pushes it.
    /// Merges with what is already stored so concurrent writers never drop each other's entries.
    private func writeManifest() throws {
        let k = try requireKey()
        let id = try requireIdentity()
        var manifest = manifestFromIdentity(id)
        if let existing = try store.record(ReservedRecord.manifestID), !existing.deleted,
           let stored = try? k.withKey({ try ManifestCodec.open(existing, vaultKey: $0) }) {
            manifest = manifest.merged(with: stored)
            if manifest == stored { return }
        }
        try store.commitLocal(id: ReservedRecord.manifestID, deleted: false) { rev in
            try k.withKey { try ManifestCodec.seal(manifest, rev: rev, vaultKey: $0) }
        }
    }

    /// Reads the manifest the vault's devices share and folds it into this device's roster and recovery pins.
    /// The manifest is sealed under VK, so only a VK holder could have written it. A manifest that does not open under the
    /// key this device holds is the proof that the key is wrong (a server that swapped the envelope cannot forge one).
    private func ingestManifest(_ k: LockedKey) throws {
        guard let record = try store.record(ReservedRecord.manifestID), !record.deleted, record.pending == .none else { return }
        let manifest: VaultManifest
        do { manifest = try k.withKey { try ManifestCodec.open(record, vaultKey: $0) } } catch {
            lock()
            throw IntegrityError.keyConfirmationFailed
        }
        var id = try requireIdentity()
        var changed = false
        for entry in manifest.roster where !id.roster.contains(where: { $0.deviceID == entry.deviceID }) {
            id.roster.append(entry); changed = true
        }
        if manifest.recoveryGeneration > id.recoveryGeneration || (!id.recoveryPinned && manifest.recoveryPublicKey != nil) {
            id.recoveryGeneration = manifest.recoveryGeneration
            id.recoveryPublicKey = manifest.recoveryPublicKey
            id.recoveryEncryptionPublicKey = manifest.recoveryEncryptionPublicKey
            id.recoveryPinned = true
            changed = true
        }
        if changed { try store.setIdentity(id) }
        // Entries this device knows that the shared manifest lacks (a freshly recovered device itself): publish them.
        if id.roster.contains(where: { r in !manifest.roster.contains { $0.deviceID == r.deviceID } }) { try writeManifest() }
    }

    /// Devices this vault's owner approved, as known to this device.
    public func roster() throws -> [RosterEntry] { try requireIdentity().roster }

    /// Short code derived from the vault key. The approving device shows it, the new device shows it, the human compares them.
    public func verificationCode() throws -> String {
        let k = try requireKey()
        return try k.withKey { VaultAdmin.verificationCode(vaultKey: $0) }
    }

    /// Checks the code typed from the approving device. On a mismatch the vault locks and nothing is trusted further.
    public func confirmEnrollment(code: String) throws {
        let expected = try verificationCode()
        let typed = code.uppercased().filter { !$0.isWhitespace && $0 != "-" }
        guard Data(expected.filter { $0 != "-" }.utf8).constantTimeEquals(Data(typed.utf8)) else {
            lock()
            throw IntegrityError.verificationCodeMismatch
        }
        var id = try requireIdentity()
        id.enrollmentUnconfirmed = false
        try store.setIdentity(id)
    }

    /// True on a device enrolled through another device until `confirmEnrollment(code:)` succeeds.
    public var enrollmentNeedsConfirmation: Bool { ((try? store.identity()) ?? nil)?.enrollmentUnconfirmed ?? false }

    /// The owner compared this device's fingerprint with the one shown on the device itself: record it as approved.
    /// Needs a fresh biometric check. Use after `IntegrityError.unknownDevices`, for devices that really are yours.
    public func trustDevice(id deviceID: String, fingerprint: String) async throws {
        _ = try requireKey()
        try await config.gate.authenticate(reason: "Trust a device")
        guard let d = try await client().devices().first(where: { $0.id == deviceID && !$0.isRevoked }) else { throw RotationError.deviceNotFound(deviceID) }
        guard let sig = Data(base64URLEncoded: d.sigPubkey), let enc = Data(base64URLEncoded: d.encPubkey) else { throw SyncError.malformedResponse }
        let actual = DevicePublicKeys(sig: sig, enc: enc).fingerprint
        let typed = fingerprint.lowercased().filter { !$0.isWhitespace && $0 != "-" }
        guard Data(actual.filter { $0 != "-" }.utf8).constantTimeEquals(Data(typed.utf8)) else { throw IntegrityError.verificationCodeMismatch }
        var identity = try requireIdentity()
        identity.roster.removeAll { $0.deviceID == deviceID }
        identity.roster.append(RosterEntry(deviceID: deviceID, name: d.name, kind: d.kind, sigPubkey: sig, encPubkey: enc, via: "trusted"))
        try store.setIdentity(identity)
        try writeManifest()
    }

    // MARK: recovery phrase confirmation

    /// The phrase was shown at bootstrap (or after a new one was made) and not yet proved written down.
    public var recoveryNeedsConfirmation: Bool { ((try? store.identity()) ?? nil)?.recoveryUnconfirmed ?? false }

    /// The recovery keys the server reported differ from the ones this device pinned (`IntegrityError.recoveryMaterialChanged`).
    public var recoveryMaterialChanged: Bool { ((try? store.identity()) ?? nil)?.recoveryMismatch ?? false }

    /// Types-back check done by the app (it holds the phrase in memory between bootstrap and the quiz): clears the flag.
    public func markRecoveryConfirmed() throws {
        var id = try requireIdentity()
        id.recoveryUnconfirmed = false
        try store.setIdentity(id)
    }

    /// The user typed all 24 words: they must derive the recovery keys pinned for this vault. Clears the flag.
    public func confirmRecovery(phrase: RecoveryPhrase) throws {
        let keys = try RecoveryKeys(phrase: phrase)
        var id = try requireIdentity()
        guard let pinned = id.recoveryPublicKey, id.recoveryPinned else { throw IntegrityError.recoveryNotPinned }
        guard pinned.constantTimeEquals(keys.publicKey) else { throw BiselCryptoError.invalidRecoveryPhrase }
        id.recoveryUnconfirmed = false
        try store.setIdentity(id)
    }

    // MARK: items

    private func decrypt(_ rec: StoredRecord, _ k: LockedKey) throws -> Item {
        let payload = try k.withKey { try ItemSealer.open(blob: rec.blob, id: rec.id, rev: rec.rev, vaultKey: $0) }
        return try ItemCodec.decode(payload, id: rec.id)
    }

    /// All live items, decrypted in memory. Requires the vault to be unlocked.
    public func items() throws -> ItemListing {
        let k = try requireKey()
        var out = ItemListing(items: [], undecryptable: [])
        for rec in try store.liveRecords() where !ReservedRecord.isReserved(rec.id) {
            if let item = try? decrypt(rec, k) { out.items.append(item) } else { out.undecryptable.append(rec.id) }
        }
        // On a device that was just enrolled and not yet confirmed: records exist and not one opens means the key is wrong,
        // not the data. Say so loudly instead of showing an empty vault.
        if out.items.isEmpty, !out.undecryptable.isEmpty, (try? store.identity())??.enrollmentUnconfirmed == true {
            throw IntegrityError.noRecordDecrypts
        }
        return out
    }

    /// Search source for the command panel: no passwords, notes or TOTP secrets.
    public func summaries() throws -> [ItemSummary] { try items().items.map(ItemSummary.init) }

    public func item(id: String) throws -> Item {
        let k = try requireKey()
        guard let rec = try store.record(id), !rec.deleted else { throw VaultError.notFound(id) }
        return try decrypt(rec, k)
    }

    /// Creates (empty `id`) or edits an item locally; `sync()` pushes it. Editing needs a fresh biometric check.
    @discardableResult
    public func save(_ item: Item) async throws -> Item {
        let k = try requireKey()
        var item = item
        let now = Date()
        if item.id.isEmpty {
            item.id = BiselRandom.identifier()
            item.createdAt = now
        } else if let existing = try store.record(item.id), !existing.deleted {
            try await config.gate.authenticate(reason: "Edit \(item.title)")
        }
        item.updatedAt = now
        let payload = try ItemCodec.encode(item)
        let id = item.id
        try store.commitLocal(id: id, deleted: false, now: now) { rev in
            try k.withKey { try ItemSealer.seal(payload: payload, id: id, rev: rev, vaultKey: $0) }
        }
        return item
    }

    public func delete(id: String) async throws {
        let k = try requireKey()
        guard let rec = try store.record(id), !rec.deleted else { throw VaultError.notFound(id) }
        try await config.gate.authenticate(reason: "Delete item")
        if rec.pending == .put && rec.baseRev == 0 { try store.forget(id); return }   // never reached the server
        try store.commitLocal(id: id, deleted: true) { rev in
            try k.withKey { try ItemSealer.sealTombstone(id: id, rev: rev, vaultKey: $0) }
        }
    }

    /// Fresh biometric check, then the password.
    public func revealPassword(id: String) async throws -> String {
        let k = try requireKey()
        guard let rec = try store.record(id), !rec.deleted else { throw VaultError.notFound(id) }
        try await config.gate.authenticate(reason: "Reveal password")
        return try decrypt(rec, k).password ?? ""
    }

    /// Fresh biometric check every time, then the current TOTP code. (Putting it on the pasteboard is the app's job.)
    public func copyTOTP(id: String, at date: Date = Date()) async throws -> TOTPCode {
        let k = try requireKey()
        guard let rec = try store.record(id), !rec.deleted else { throw VaultError.notFound(id) }
        try await config.gate.authenticate(reason: "Copy one-time code")
        guard let params = try decrypt(rec, k).totp else { throw VaultError.noTOTP }
        return try TOTPGenerator.code(params, at: date)
    }

    // MARK: sync / devices

    @discardableResult
    public func sync() async throws -> SyncReport {
        guard !rotationInProgress else { throw RotationError.inProgress }
        if let at = try store.identity()?.activatesAt, Date(timeIntervalSince1970: TimeInterval(at)) > Date() {
            throw IntegrityError.pendingActivation(until: Date(timeIntervalSince1970: TimeInterval(at)))
        }
        guard try store.identity()?.serverURL != nil else { return SyncReport() }   // local-only: nothing to sync with
        let held = liveKey()
        let report = try await SyncEngine(store: store, client: try client(), vaultKey: { held }).run()
        if report.rotationAdopted { lock() }   // the key in memory is the rotated-away one; unlock to get the new one
        else if let held { try ingestManifest(held) }
        return report
    }

    /// Fetches the device list from the server.
    public func devices() async throws -> [DeviceInfo] { try await client().devices() }

    /// Revokes a device **and rotates the vault key** in one atomic server transaction (see `rotateVaultKey`):
    /// the revoked device is cut off and everything it could still read from the server is re-keyed. Needs a fresh
    /// biometric check and an unlocked vault (it unlocks first if necessary).
    @discardableResult
    public func revoke(deviceID: String) async throws -> RotationReport {
        try await rotateVaultKey(revoking: deviceID)
    }

    /// Emergency only: cuts a device off at the server without rotating the vault key. The device keeps VK, so it
    /// can still read every copy of the ciphertext it (or anyone) holds. Follow with `rotateVaultKey()`.
    public func revokeWithoutRotation(deviceID: String) async throws {
        let vk = try requireKey()
        try await config.gate.authenticate(reason: "Revoke a device")
        try await client().revokeDevice(id: deviceID, admin: try adminSigner(vk))
    }

    // MARK: vault-key rotation

    /// Generates a new vault key and re-keys everything under it, atomically on the server:
    /// - every live item's wrapped item key is re-wrapped (payloads, revisions and AADs do not change),
    /// - every remaining device gets a new envelope, and `deviceID` (if given) is revoked,
    /// - the recovery envelope is re-sealed to the same recovery key (the existing 24 words keep working).
    /// If anything changed on the server since the snapshot (an edit, a new device, another rotation) the server
    /// applies nothing and this retries from a fresh sync, up to a few times, then throws `.tooManyConflicts`.
    /// Other devices notice on their next sync, lock themselves, and unlock into the new key.
    @discardableResult
    public func rotateVaultKey(revoking deviceID: String? = nil) async throws -> RotationReport {
        guard !rotationInProgress else { throw RotationError.inProgress }
        let reason = deviceID == nil ? "Rotate the box key" : "Revoke a device"
        if !isUnlocked { try await unlock(reason: reason) }
        _ = try requireKey()
        try await config.gate.authenticate(reason: reason)
        rotationInProgress = true
        defer { rotationInProgress = false }
        for attempt in 0..<6 {
            if let report = try await rotateOnce(revoking: deviceID) { return report }
            try await Task.sleep(for: .milliseconds(100 * (attempt + 1)))
        }
        throw RotationError.tooManyConflicts
    }

    /// One attempt. Returns nil when the server reported a change since the snapshot (the caller retries).
    private func rotateOnce(revoking deviceID: String?) async throws -> RotationReport? {
        let oldKey = try requireKey()
        let client = try client()

        // 1. A current, fully pushed local view.
        let report = try await SyncEngine(store: store, client: client, vaultKey: { oldKey }).run()
        if report.rotationAdopted { lock(); throw RotationError.vaultKeyRotated }
        let pending = try store.pendingRecords()
        guard pending.isEmpty else { throw RotationError.pendingChanges(pending.count) }
        guard try store.cursor() == report.headSeq else { return nil }
        let identity = try requireIdentity()
        guard let recoveryEncryptionKey = identity.recoveryEncryptionPublicKey, !recoveryEncryptionKey.isEmpty else {
            throw RotationError.recoveryNeedsUpgrade
        }

        // 2. Who stays.
        let devices = try await client.devices()
        let active = devices.filter { !$0.isRevoked }
        if let deviceID {
            guard deviceID != identity.deviceID else { throw RotationError.cannotRevokeThisDevice }
            guard devices.contains(where: { $0.id == deviceID }) else { throw RotationError.deviceNotFound(deviceID) }
        }
        let revokeID = deviceID.flatMap { id in active.contains { $0.id == id } ? id : nil }   // already revoked: just rotate
        let remaining = active.filter { $0.id != revokeID }
        guard remaining.contains(where: { $0.id == identity.deviceID }) else { throw SyncError.notAuthorized }
        // The new vault key goes only to devices this vault's owner approved. A device the server lists that is not in the
        // roster (planted through a stolen signing key, a hostile server, or a leaked phrase) stops the rotation.
        let approved = Dictionary(uniqueKeysWithValues: identity.roster.map { ($0.deviceID, $0) })
        var unknown: [UnknownDevice] = []
        for d in remaining {
            let sig = Data(base64URLEncoded: d.sigPubkey), enc = Data(base64URLEncoded: d.encPubkey)
            if let entry = approved[d.id], entry.sigPubkey == sig, entry.encPubkey == enc { continue }
            let fp = DevicePublicKeys(sig: sig ?? Data(), enc: enc ?? Data()).fingerprint
            unknown.append(UnknownDevice(id: d.id, name: d.name, kind: d.kind, fingerprint: fp,
                                         keysChanged: approved[d.id] != nil, pendingActivation: d.isPending()))
        }
        guard unknown.isEmpty else { throw IntegrityError.unknownDevices(unknown) }

        // 3. New key; re-wrap every item key. Nothing leaves the device until all of it succeeded.
        var newRaw = BiselRandom.bytes(32)
        defer { newRaw.zeroize() }
        let newKey = SymmetricKey(data: newRaw)
        let live = try store.liveRecords()
        var wrapped: [Data] = []
        var undecryptable: [String] = []
        for rec in live {
            do {
                wrapped.append(try oldKey.withKey { old in
                    try ItemSealer.rewrapKey(blob: rec.blob, id: rec.id, rev: rec.rev, from: old, to: newKey)
                })
            } catch { undecryptable.append(rec.id) }
        }
        guard undecryptable.isEmpty else { throw RotationError.undecryptableItems(undecryptable) }

        var envelopes: [(id: String, envelope: Data)] = []
        for d in remaining {
            guard let entry = approved[d.id] else { throw SyncError.malformedResponse }
            envelopes.append((d.id, try DeviceEnvelope.seal(vaultKey: newRaw, toEncryptionKey: entry.encPubkey)))
        }
        guard let ownEnvelope = envelopes.first(where: { $0.id == identity.deviceID })?.envelope else { throw SyncError.notAuthorized }
        guard let recoverySigningKey = identity.recoveryPublicKey else { throw RotationError.recoveryNeedsUpgrade }
        let newEpoch = identity.epoch + 1
        let recoveryEnvelope = try RecoveryKeys.seal(vaultKey: newRaw, toEncryptionKey: recoveryEncryptionKey,
                                                     signingKey: recoverySigningKey, epoch: newEpoch)
        // Tombstone markers are sealed under VK too: re-seal every one under the new key.
        let tombstoneRecords = try store.allRecords().filter { $0.deleted && $0.pending == .none }
        let markers = try tombstoneRecords.map { try ItemSealer.sealTombstone(id: $0.id, rev: $0.rev, vaultKey: newKey) }
        // The admin key moves with VK: the old key authorises this request and the new public key.
        let oldAdmin = try adminSigner(oldKey)
        let newAdmin = try AdminSigner(vaultKey: newRaw)

        // What the revoked device could have read: everything that was in the vault while it still held the key.
        var exposure: (name: String?, lastSeen: Date?, items: [ExposedItem]) = (nil, nil, [])
        if let revokeID, let target = devices.first(where: { $0.id == revokeID }) {
            let lastSeen = target.lastSeenAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
            let items: [ExposedItem] = live.compactMap { rec in
                guard !ReservedRecord.isReserved(rec.id), let item = try? decrypt(rec, oldKey) else { return nil }
                // "Last seen" is kept to the hour on the server, so an item changed within an hour after it might have been seen too.
                let seen = target.lastSeenAt.map { rec.updatedAt <= $0 + 3600 } ?? true
                return ExposedItem(id: item.id, title: item.title, username: item.username, urls: item.urls,
                                   hasPassword: !(item.password ?? "").isEmpty, hasTOTP: item.totp != nil,
                                   updatedAt: item.updatedAt, mayHaveBeenRead: seen)
            }
            exposure = (target.name, lastSeen, items.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending })
        }

        // 4. One atomic request.
        let outcome = try await client.rotate(
            baseEpoch: identity.epoch, baseSeq: report.headSeq, revoke: revokeID, newAdminPublicKey: newAdmin.publicKey,
            items: zip(live, wrapped).map { (id: $0.id, rev: $0.rev, wrappedKey: $1) },
            tombstones: zip(tombstoneRecords, markers).map { (id: $0.id, rev: $0.rev, marker: $1) },
            devices: envelopes, recoveryEnvelope: recoveryEnvelope, admin: oldAdmin)
        guard case .rotated(let epoch, let headSeq) = outcome else { return nil }

        // 5. Mirror it locally. Edits made while the request was in flight are still sealed under the old key: re-wrap them too.
        let rotated = zip(live, wrapped).enumerated().map { index, pair -> StoredRecord in
            var r = pair.0
            r.blob = pair.1 + r.blob.dropFirst(ItemSealer.wrappedKeyLength)
            r.seq = report.headSeq + 1 + index
            return r
        }
        let retombed = zip(tombstoneRecords, markers).enumerated().map { index, pair -> StoredRecord in
            var r = pair.0
            r.blob = pair.1
            r.seq = report.headSeq + live.count + 1 + index
            return r
        }
        try store.applyRotation(rotated + retombed, cursor: headSeq)
        for rec in try store.pendingRecords() where rec.pending == .delete {
            try store.replacePendingBlob(id: rec.id, expectedRev: rec.rev, with: try ItemSealer.sealTombstone(id: rec.id, rev: rec.rev, vaultKey: newKey))
        }
        for rec in try store.pendingRecords() where rec.pending == .put {
            let w = try oldKey.withKey { old in try ItemSealer.rewrapKey(blob: rec.blob, id: rec.id, rev: rec.rev, from: old, to: newKey) }
            try store.replacePendingBlob(id: rec.id, expectedRev: rec.rev, with: w + rec.blob.dropFirst(ItemSealer.wrappedKeyLength))
        }
        var updated = try requireIdentity()
        updated.envelope = ownEnvelope
        updated.epoch = epoch
        updated.recoveryEnvelope = recoveryEnvelope
        updated.previousEnvelope = nil
        try store.setIdentity(updated)
        setKey(newRaw)
        return RotationReport(epoch: epoch, revokedDeviceID: revokeID, revokedDeviceName: exposure.name,
                              revokedDeviceLastSeen: exposure.lastSeen, exposed: exposure.items)
    }

    // MARK: trash, history, events, device state

    /// Versions the server replaced or deleted that this device still holds (30 days). Needs the vault unlocked.
    public func trash() throws -> [PastVersion] {
        let k = try requireKey()
        return try store.trashedRecords().compactMap { t in
            guard !t.record.deleted, !ReservedRecord.isReserved(t.record.id),
                  let item = try? decrypt(t.record, k) else { return nil }
            return PastVersion(id: "trash-\(t.key)", itemID: t.record.id, rev: t.record.rev, item: item, replacedAt: t.replacedAt,
                               source: .localTrash(reason: t.reason), localKey: t.key)
        }
    }

    /// Earlier versions of items from the server's retention (30 days), readable with the current vault key. Versions
    /// from before a key rotation were sealed under the old key and are skipped.
    public func serverHistory(itemID: String? = nil) async throws -> [PastVersion] {
        let k = try requireKey()
        let entries = try await client().history(itemID: itemID)
        return entries.compactMap { e in
            guard e.kind == .overwrite, !ReservedRecord.isReserved(e.itemID),
                  let item = try? decrypt(StoredRecord(id: e.itemID, rev: e.rev, seq: 0, deleted: false, blob: e.blob, updatedAt: 0), k) else { return nil }
            return PastVersion(id: "history-\(e.serverID)", itemID: e.itemID, rev: e.rev, item: item, replacedAt: e.replacedAt,
                               source: .serverHistory, localKey: nil)
        }
    }

    /// Saves a past version as the item's newest revision (fresh biometric check, like any edit).
    @discardableResult
    public func restore(_ version: PastVersion) async throws -> Item {
        let k = try requireKey()
        try await config.gate.authenticate(reason: "Restore \(version.item.title)")
        var item = version.item
        item.updatedAt = Date()
        let payload = try ItemCodec.encode(item)
        let id = version.itemID
        try store.commitLocal(id: id, deleted: false) { rev in
            try k.withKey { try ItemSealer.seal(payload: payload, id: id, rev: rev, vaultKey: $0) }
        }
        if let key = version.localKey { try store.removeFromTrash(key: key) }
        return item
    }

    /// Recent server events (device added or revoked, key rotated, recovery used), oldest first.
    public func recentEvents() throws -> [ServerEvent] {
        guard let json = try store.recentEventsJSON() else { return [] }
        return (try? JSONDecoder().decode([ServerEvent].self, from: json)) ?? []
    }

    /// The server reported an older state than this device saw (restored from a backup?). After the owner has checked that
    /// this is expected, forget the old position and pull everything again.
    public func acknowledgeServerReset() throws {
        try store.setKnownHeadSeq(0)
        try store.setCursor(0)
        try store.setEventCursor(0)
    }

    /// When a device registered through the recovery phrase may start syncing (nil: now). `sync()` throws
    /// `IntegrityError.pendingActivation` before that.
    public func activationDate() -> Date? {
        ((try? store.identity()) ?? nil)?.activatesAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }.flatMap { $0 > Date() ? $0 : nil }
    }

    /// Whether this device's Secure Enclave keys are usable; never prompts. `.biometryChanged` means a fingerprint was
    /// added or removed and the vault key on this device is locked for safety: use `removeLocalDevice()` and enrol again
    /// (from another device, or with the recovery phrase).
    public nonisolated func deviceKeyStatus() -> DeviceKeyStatus { config.keyStore.status() }

    /// Erases everything this device holds (database, keys, saved server address). The vault on the server and on other
    /// devices is untouched; the owner should also revoke this device from another one. Use before enrolling again.
    public func removeLocalDevice() throws {
        lock()
        try store.removeAll()
        try config.keyStore.deleteKeys()
    }

    // MARK: backup

    /// Writes a `.bisel-backup` with everything the server holds. Syncs first when reachable.
    public func exportBackup(to url: URL) async throws {
        _ = try? await sync()
        guard let id = try store.identity(), let pub = id.recoveryPublicKey, let env = id.recoveryEnvelope else {
            throw VaultError.badBackup("no recovery material known yet; sync first")
        }
        guard !id.recoveryMismatch else { throw IntegrityError.recoveryMaterialChanged }
        guard id.recoveryPinned else { throw IntegrityError.recoveryNotPinned }
        guard let encPub = id.recoveryEncryptionPublicKey, !encPub.isEmpty else {
            throw VaultError.badBackup("this box's recovery phrase predates key rotation; create a new one first")
        }
        let file = BackupFile(recoveryPublicKey: pub, recoveryEncryptionPublicKey: encPub, recoveryEnvelope: env,
                              epoch: id.epoch, records: try store.allRecords())
        try file.encoded().write(to: url, options: .atomic)
    }

    /// Disaster recovery onto a fresh (un-bootstrapped) server: opens the backup with the phrase, bootstraps
    /// this device with the same recovery key, and re-uploads every item (re-sealed for its new revision).
    public func importBackup(from url: URL, phrase: RecoveryPhrase, server: URL, bootstrapToken: String,
                             deviceName: String) async throws {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        let file = try BackupFile.decode(try Data(contentsOf: url))
        var (vkData, _) = try file.vaultKey(phrase: phrase)
        defer { vkData.zeroize() }
        let vk = SymmetricKey(data: vkData)
        // A fresh server starts at epoch 1, and the recovery envelope is bound to the epoch: seal it again for this server.
        let keys = try RecoveryKeys(phrase: phrase)
        let bundle = RecoveryBundle(phrase: phrase, publicKey: keys.publicKey, encryptionPublicKey: keys.encryptionPublicKey,
                                    envelope: try keys.seal(vaultKey: vkData, epoch: 1))
        try await register(server: server, bootstrapToken: bootstrapToken, deviceName: deviceName, vaultKey: vkData, recovery: bundle)
        var skipped = 0
        for rec in file.records where !rec.deleted {
            guard let payload = try? ItemSealer.open(blob: rec.blob, id: rec.id, rev: rec.rev, vaultKey: vk) else { skipped += 1; continue }
            try store.commitLocal(id: rec.id, deleted: false) { rev in
                try ItemSealer.seal(payload: payload, id: rec.id, rev: rev, vaultKey: vk)
            }
        }
        if skipped > 0 { throw VaultError.badBackup("\(skipped) item(s) in the backup failed authentication and were skipped") }
        _ = try await sync()
    }
}
