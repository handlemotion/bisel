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
    public func unlock(reason: String = "Unlock bisel") async throws {
        let id = try requireIdentity()
        guard let envelope = id.envelope else { throw VaultError.notConfigured }
        let vk = try await config.keyStore.openEnvelope(envelope, reason: reason)
        setKey(vk)
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
        let vk = BiselRandom.bytes(32)
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
                                       recoveryPublicKey: recovery.publicKey, recoveryEnvelope: recovery.envelope)
        try store.setIdentity(LocalIdentity(deviceID: deviceID, deviceName: deviceName, serverURL: server,
                                            keyStore: config.keyStore.implementation, envelope: envelope,
                                            recoveryPublicKey: recovery.publicKey, recoveryEnvelope: recovery.envelope))
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
        let envelope = try vk.withKey { try DeviceEnvelope.seal(vaultKey: $0.withUnsafeBytes { Data($0) }, toEncryptionKey: request.encPubkey) }
        try await client().addDevice(WireDevice(id: request.deviceID, name: request.name, kind: request.kind,
                                                sigPubkey: request.sigPubkey, encPubkey: request.encPubkey, envelope: envelope))
    }

    /// New device, step 3 (after approval): fetch own envelope. Then `unlock()` and `sync()` work.
    public func completeEnrollment() async throws {
        var id = try requireIdentity()
        id.envelope = try await client().envelope()
        try store.setIdentity(id)
    }

    /// Fresh install: rebuild from the recovery phrase (new device keys, VK from the recovery envelope).
    /// Call `sync()` afterwards, and consider `rotateRecovery()`.
    public func recover(server: URL, phrase: RecoveryPhrase, deviceName: String) async throws {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        let (vk, keys) = try await RecoveryService.fetchVaultKey(server: server, phrase: phrase)
        let pub = try config.keyStore.createKeys()
        let deviceID = BiselRandom.identifier()
        let envelope = try DeviceEnvelope.seal(vaultKey: vk, toEncryptionKey: pub.enc)
        let device = WireDevice(id: deviceID, name: deviceName, kind: config.deviceKind, sigPubkey: pub.sig, encPubkey: pub.enc, envelope: envelope)
        try await SyncClient(baseURL: server, signer: RecoverySigner(keys: keys)).recoveryRegister(device: device)
        try store.setIdentity(LocalIdentity(deviceID: deviceID, deviceName: deviceName, serverURL: server,
                                            keyStore: config.keyStore.implementation, envelope: envelope))
        setKey(vk)
    }

    /// Replaces the recovery key and envelope (new phrase; the old one stops working immediately).
    public func rotateRecovery() async throws -> RecoveryPhrase {
        let vk = try requireKey()
        try await config.gate.authenticate(reason: "Create a new recovery phrase")
        let bundle = try RecoveryService.makeBundle(vaultKey: try vk.rawBytes())
        try await client().rotateRecovery(publicKey: bundle.publicKey, envelope: bundle.envelope)
        var id = try requireIdentity()
        id.recoveryPublicKey = bundle.publicKey
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
        let held = liveKey()
        return try await SyncEngine(store: store, client: try client(), vaultKey: { held }).run()
    }

    /// Fetches the device list from the server.
    public func devices() async throws -> [DeviceInfo] { try await client().devices() }

    public func revoke(deviceID: String) async throws {
        try await config.gate.authenticate(reason: "Revoke a device")
        try await client().revokeDevice(id: deviceID)
    }

    // MARK: backup

    /// Writes a `.bisel-backup` with everything the server holds. Syncs first when reachable.
    public func exportBackup(to url: URL) async throws {
        _ = try? await sync()
        guard let id = try store.identity(), let pub = id.recoveryPublicKey, let env = id.recoveryEnvelope else {
            throw VaultError.badBackup("no recovery material known yet; sync first")
        }
        let file = BackupFile(recoveryPublicKey: pub, recoveryEnvelope: env, records: try store.allRecords())
        try file.encoded().write(to: url, options: .atomic)
    }

    /// Disaster recovery onto a fresh (un-bootstrapped) server: opens the backup with the phrase, bootstraps
    /// this device with the same recovery key, and re-uploads every item (re-sealed for its new revision).
    public func importBackup(from url: URL, phrase: RecoveryPhrase, server: URL, bootstrapToken: String,
                             deviceName: String) async throws {
        guard try store.identity() == nil else { throw VaultError.alreadyConfigured }
        let file = try BackupFile.decode(try Data(contentsOf: url))
        let (vkData, _) = try file.vaultKey(phrase: phrase)
        let vk = SymmetricKey(data: vkData)
        guard let pub = Data(base64URLEncoded: file.recoveryPubkey), let env = Data(base64URLEncoded: file.recoveryEnvelope) else {
            throw VaultError.badBackup("corrupt recovery material")
        }
        let bundle = RecoveryBundle(phrase: phrase, publicKey: pub, envelope: env)
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
