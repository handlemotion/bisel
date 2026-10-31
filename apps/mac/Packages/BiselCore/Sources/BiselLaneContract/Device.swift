#if BISEL_SOFTWARE_KEYS
import Foundation
import BiselCore
import BiselTestSupport

/// A simulated device: its own directory (store + software keys) and a vault bound to it. Dev/test only.
public struct Device: Sendable {
    public let name: String
    public let location: StoreLocation
    public let keyStore: SoftwareDeviceKeyStore
    public let gate: RecordingGate
    public let vault: Vault
    public let laneProvider: (@Sendable (LocalIdentity, @escaping @Sendable () -> LockedKey?) throws -> any SyncLane)?
    public let freshnessWitness: (any FreshnessWitness)?

    /// `laneProvider` nil: the device syncs with the Bisel server at its identity's address.
    public init(_ name: String, gate: RecordingGate = RecordingGate(), fillWindow: TimeInterval = 300,
                laneProvider: (@Sendable (LocalIdentity, @escaping @Sendable () -> LockedKey?) throws -> any SyncLane)? = nil,
                freshnessWitness: (any FreshnessWitness)? = nil) throws {
        self.name = name
        self.laneProvider = laneProvider
        self.freshnessWitness = freshnessWitness
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("bisel-flow-\(name)-\(UUID().uuidString)")
        location = StoreLocation(directory: dir)
        keyStore = SoftwareDeviceKeyStore(directory: dir)
        self.gate = gate
        vault = try Vault(.init(location: location, keyStore: keyStore, gate: gate, fillWindow: fillWindow, deviceKind: "test",
                                secrets: FileSecretStore(directory: dir), laneProvider: laneProvider, freshnessWitness: freshnessWitness))
    }

    /// Re-opens the same store and keys as a new process would.
    public func relaunched(fillWindow: TimeInterval = 300) throws -> Vault {
        try Vault(.init(location: location, keyStore: keyStore, gate: gate, fillWindow: fillWindow, deviceKind: "test",
                        secrets: FileSecretStore(directory: location.directory), laneProvider: laneProvider, freshnessWitness: freshnessWitness))
    }

    public var signedClientFactory: (URL, String) -> SyncClient {
        { url, id in SyncClient(baseURL: url, signer: DeviceSigner(deviceID: id, keyStore: keyStore)) }
    }
}

/// Stands in for the Touch ID check: records every request and can refuse.
public final class RecordingGate: BiometricGate, @unchecked Sendable {
    private let lock = NSLock()
    private var reasons: [String] = []
    private var denying = false
    public init() {}
    public var calls: [String] { lock.withLock { reasons } }
    public func deny(_ on: Bool) { lock.withLock { denying = on } }
    public func authenticate(reason: String) async throws {
        let refuse = lock.withLock { reasons.append(reason); return denying }
        if refuse { throw KeyStoreError.userCancelled }
    }
}

public extension Device {
    /// Bootstraps this device as the first device of a new vault on `server`.
    @discardableResult
    func bootstrap(_ server: TestServer) async throws -> RecoveryPhrase {
        try await vault.bootstrap(server: server.url, bootstrapToken: TestServer.bootstrapToken, deviceName: name)
    }

    /// Enrolls `self` through `approver` the way a second Mac or iPhone would be added.
    func enroll(through approver: Device, server: TestServer) async throws { try await enroll(through: approver, address: server.url) }

    func enroll(through approver: Device, address: URL) async throws {
        let request = try await vault.prepareEnrollment(server: address, deviceName: name)
        try await approver.vault.approveEnrollment(request)
        try await vault.completeEnrollment()
        try await vault.unlock()
        // What the two humans do: compare the code the approving device shows with the new one's.
        try await vault.confirmEnrollment(code: try await approver.vault.verificationCode())
        try await vault.sync()
    }
}

public func login(_ title: String, user: String = "user", password: String) -> Item {
    Item(title: title, urls: ["https://\(title.lowercased().replacingOccurrences(of: " ", with: "")).example"],
         username: user, password: password)
}
#endif
