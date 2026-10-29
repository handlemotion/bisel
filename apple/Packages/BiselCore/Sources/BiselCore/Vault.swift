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

        public init(location: StoreLocation, keyStore: any DeviceKeyStore, gate: any BiometricGate = LocalAuthenticationGate(),
                    fillWindow: TimeInterval = 300, deviceKind: String = "mac") {
            self.location = location; self.keyStore = keyStore; self.gate = gate
            self.fillWindow = fillWindow; self.deviceKind = deviceKind
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
                          gate: SoftwareGate(), fillWindow: fillWindow, deviceKind: deviceKind)
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
        store = try LocalStore(location: configuration.location)
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
        return SyncClient(baseURL: id.serverURL, signer: DeviceSigner(deviceID: id.deviceID, keyStore: config.keyStore))
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
        let bundle = try RecoveryService.makeBundle(vaultKey: vk)
        try await register(server: server, bootstrapToken: bootstrapToken, deviceName: deviceName, vaultKey: vk, recovery: bundle)
        return bundle.phrase
    }

    private func register(server: URL, bootstrapToken: String, deviceName: String, vaultKey vk: Data, recovery: RecoveryBundle) async throws {
        let pub = try config.keyStore.createKeys()
        let deviceID = BiselRandom.identifier()
        let envelope = try DeviceEnvelope.seal(vaultKey: vk, toEncryptionKey: pub.enc)
        let device = WireDevice(id: deviceID, name: deviceName, kind: config.deviceKind, sigPubkey: pub.sig, encPubkey: pub.enc, envelope: envelope)
        try await SyncClient.bootstrap(baseURL: server, token: bootstrapToken, device: device,
                                       recoveryPublicKey: recovery.publicKey, recoveryEncryptionPublicKey: recovery.encryptionPublicKey,
                                       recoveryEnvelope: recovery.envelope)
        try store.setIdentity(LocalIdentity(deviceID: deviceID, deviceName: deviceName, serverURL: server,
                                            keyStore: config.keyStore.implementation, envelope: envelope,
                                            recoveryPublicKey: recovery.publicKey, recoveryEnvelope: recovery.envelope,
                                            recoveryEncryptionPublicKey: recovery.encryptionPublicKey, epoch: 1))
        setKey(vk)
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
        try await config.gate.authenticate(reason: "Add \(request.name) to your vault")
        let epoch = try requireIdentity().epoch
        var raw = try vk.rawBytes()
        defer { raw.zeroize() }
        let envelope = try DeviceEnvelope.seal(vaultKey: raw, toEncryptionKey: request.encPubkey)
        do {
            try await client().addDevice(WireDevice(id: request.deviceID, name: request.name, kind: request.kind,
                                                    sigPubkey: request.sigPubkey, encPubkey: request.encPubkey, envelope: envelope,
                                                    epoch: epoch))
        } catch RotationError.staleEpoch {
            // The vault key changed under us: adopt the new one (this locks the vault) and let the caller retry.
            _ = try? await sync()
            throw RotationError.vaultKeyRotated
        }
    }

    /// New device, step 3 (after approval): fetch own envelope. Then `unlock()` and `sync()` work.
    public func completeEnrollment() async throws {
        var id = try requireIdentity()
        let (envelope, epoch) = try await client().envelope()
        id.envelope = envelope
        id.epoch = epoch
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
        try await SyncClient(baseURL: server, signer: RecoverySigner(keys: keys)).recoveryRegister(device: device, epoch: epoch)
        try store.setIdentity(LocalIdentity(deviceID: deviceID, deviceName: deviceName, serverURL: server,
                                            keyStore: config.keyStore.implementation, envelope: envelope,
                                            recoveryEncryptionPublicKey: keys.encryptionPublicKey, epoch: epoch))
        setKey(vk)
    }

    /// Replaces the recovery key and envelope (new phrase; the old one stops working immediately).
    public func rotateRecovery() async throws -> RecoveryPhrase {
        let vk = try requireKey()
        try await config.gate.authenticate(reason: "Create a new recovery phrase")
        var raw = try vk.rawBytes()
        defer { raw.zeroize() }
        let bundle = try RecoveryService.makeBundle(vaultKey: raw)
        var id = try requireIdentity()
        do {
            try await client().rotateRecovery(publicKey: bundle.publicKey, encryptionPublicKey: bundle.encryptionPublicKey,
                                              envelope: bundle.envelope, epoch: id.epoch)
        } catch RotationError.staleEpoch {
            _ = try? await sync()
            throw RotationError.vaultKeyRotated
        }
        id.recoveryPublicKey = bundle.publicKey
        id.recoveryEncryptionPublicKey = bundle.encryptionPublicKey
        id.recoveryEnvelope = bundle.envelope
        try store.setIdentity(id)
        return bundle.phrase
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
        for rec in try store.liveRecords() {
            if let item = try? decrypt(rec, k) { out.items.append(item) } else { out.undecryptable.append(rec.id) }
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
        _ = try requireKey()
        guard let rec = try store.record(id), !rec.deleted else { throw VaultError.notFound(id) }
        try await config.gate.authenticate(reason: "Delete item")
        if rec.pending == .put && rec.baseRev == 0 { try store.forget(id); return }   // never reached the server
        try store.commitLocal(id: id, deleted: true) { _ in Data() }
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
        let held = liveKey()
        let report = try await SyncEngine(store: store, client: try client(), vaultKey: { held }).run()
        if report.rotationAdopted { lock() }   // the key in memory is the rotated-away one; unlock to get the new one
        return report
    }

    /// Fetches the device list from the server.
    public func devices() async throws -> [DeviceInfo] { try await client().devices() }

    /// Revokes a device **and rotates the vault key** in one atomic server transaction (see `rotateVaultKey`):
    /// the revoked device is cut off and everything it could still read from the server is re-keyed. Needs a fresh
    /// biometric check and an unlocked vault (it unlocks first if necessary).
    public func revoke(deviceID: String) async throws {
        try await rotateVaultKey(revoking: deviceID)
    }

    /// Emergency only: cuts a device off at the server without rotating the vault key. The device keeps VK, so it
    /// can still read every copy of the ciphertext it (or anyone) holds. Follow with `rotateVaultKey()`.
    public func revokeWithoutRotation(deviceID: String) async throws {
        try await config.gate.authenticate(reason: "Revoke a device")
        try await client().revokeDevice(id: deviceID)
    }

    // MARK: vault-key rotation

    /// Generates a new vault key and re-keys everything under it, atomically on the server:
    /// - every live item's wrapped item key is re-wrapped (payloads, revisions and AADs do not change),
    /// - every remaining device gets a new envelope, and `deviceID` (if given) is revoked,
    /// - the recovery envelope is re-sealed to the same recovery key (the existing 24 words keep working).
    /// If anything changed on the server since the snapshot (an edit, a new device, another rotation) the server
    /// applies nothing and this retries from a fresh sync, up to a few times, then throws `.tooManyConflicts`.
    /// Other devices notice on their next sync, lock themselves, and unlock into the new key.
    public func rotateVaultKey(revoking deviceID: String? = nil) async throws {
        guard !rotationInProgress else { throw RotationError.inProgress }
        let reason = deviceID == nil ? "Rotate the vault key" : "Revoke a device"
        if !isUnlocked { try await unlock(reason: reason) }
        _ = try requireKey()
        try await config.gate.authenticate(reason: reason)
        rotationInProgress = true
        defer { rotationInProgress = false }
        for attempt in 0..<6 {
            if try await rotateOnce(revoking: deviceID) { return }
            try await Task.sleep(for: .milliseconds(100 * (attempt + 1)))
        }
        throw RotationError.tooManyConflicts
    }

    /// One attempt. Returns false when the server reported a change since the snapshot (the caller retries).
    private func rotateOnce(revoking deviceID: String?) async throws -> Bool {
        let oldKey = try requireKey()
        let client = try client()

        // 1. A current, fully pushed local view.
        let report = try await SyncEngine(store: store, client: client, vaultKey: { oldKey }).run()
        if report.rotationAdopted { lock(); throw RotationError.vaultKeyRotated }
        let pending = try store.pendingRecords()
        guard pending.isEmpty else { throw RotationError.pendingChanges(pending.count) }
        guard try store.cursor() == report.headSeq else { return false }
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
            guard let pub = Data(base64URLEncoded: d.encPubkey) else { throw SyncError.malformedResponse }
            envelopes.append((d.id, try DeviceEnvelope.seal(vaultKey: newRaw, toEncryptionKey: pub)))
        }
        guard let ownEnvelope = envelopes.first(where: { $0.id == identity.deviceID })?.envelope else { throw SyncError.notAuthorized }
        let recoveryEnvelope = try RecoveryKeys.seal(vaultKey: newRaw, toEncryptionKey: recoveryEncryptionKey)

        // 4. One atomic request.
        let outcome = try await client.rotate(
            baseEpoch: identity.epoch, baseSeq: report.headSeq, revoke: revokeID,
            items: zip(live, wrapped).map { (id: $0.id, rev: $0.rev, wrappedKey: $1) },
            devices: envelopes, recoveryEnvelope: recoveryEnvelope)
        guard case .rotated(let epoch, let headSeq) = outcome else { return false }

        // 5. Mirror it locally. Edits made while the request was in flight are still sealed under the old key: re-wrap them too.
        let rotated = zip(live, wrapped).enumerated().map { index, pair -> StoredRecord in
            var r = pair.0
            r.blob = pair.1 + r.blob.dropFirst(ItemSealer.wrappedKeyLength)
            r.seq = report.headSeq + 1 + index
            return r
        }
        try store.applyRotation(rotated, cursor: headSeq)
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
        return true
    }

    // MARK: backup

    /// Writes a `.bisel-backup` with everything the server holds. Syncs first when reachable.
    public func exportBackup(to url: URL) async throws {
        _ = try? await sync()
        guard let id = try store.identity(), let pub = id.recoveryPublicKey, let env = id.recoveryEnvelope else {
            throw VaultError.badBackup("no recovery material known yet; sync first")
        }
        guard let encPub = id.recoveryEncryptionPublicKey, !encPub.isEmpty else {
            throw VaultError.badBackup("this vault's recovery phrase predates key rotation; create a new one first")
        }
        let file = BackupFile(recoveryPublicKey: pub, recoveryEncryptionPublicKey: encPub, recoveryEnvelope: env,
                              records: try store.allRecords())
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
        guard let pub = Data(base64URLEncoded: file.recoveryPubkey), let encPub = Data(base64URLEncoded: file.recoveryEncPubkey),
              let env = Data(base64URLEncoded: file.recoveryEnvelope) else {
            throw VaultError.badBackup("corrupt recovery material")
        }
        let bundle = RecoveryBundle(phrase: phrase, publicKey: pub, encryptionPublicKey: encPub, envelope: env)
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
