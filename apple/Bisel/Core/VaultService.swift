import AppKit
import Observation
import BiselCore

/// Non-secret view of an item: what the list, the search index and the panel need. Passwords, notes and TOTP
/// secrets are never held here; they are decrypted on demand through the `Vault` actor.
struct ItemRow: Identifiable, Hashable, Sendable {
    let id: String
    let type: ItemType
    let title: String
    let urls: [String]
    let username: String
    let tags: [String]
    let updatedAt: Date
    let hasTOTP: Bool
    let totpPeriod: Int

    init(_ item: Item) {
        id = item.id; type = item.type; title = item.title; urls = item.urls; username = item.username ?? ""
        tags = item.tags; updatedAt = item.updatedAt; hasTOTP = item.totp != nil; totpPeriod = item.totp?.period ?? 30
    }

    var domain: String { SearchRecord.domain(of: urls.first) }
}

enum SyncState: Equatable {
    case idle
    case syncing
    case synced(Date)
    case offline(String)
    case failed(String)
}

/// Everything between the UI and BiselCore's `Vault` actor: lifecycle (set up / locked / unlocked), the in-memory
/// search index, sync, auto-lock. The command panel talks to it through `VaultSearchSource` / `VaultSecretProvider`.
@MainActor
@Observable
final class VaultService: VaultSearchSource, VaultSecretProvider {
    enum Phase: Equatable { case needsSetup, locked, unlocked }

    // MARK: observable state
    private(set) var phase: Phase = .needsSetup
    private(set) var rows: [ItemRow] = []
    private(set) var syncState: SyncState = .idle
    private(set) var pendingChanges = 0
    private(set) var lastConflicts = 0
    private(set) var undecryptable = 0
    private(set) var startupError: String?
    private(set) var deviceName = ""
    private(set) var serverURL: URL?
    private(set) var deviceID = ""
    /// Recovery phrase shown right after set-up, until the user confirms "I have stored it".
    private(set) var pendingPhrase: RecoveryPhrase?
    private(set) var unlockedAt: Date?
    var isBusy = false

    // MARK: VaultSearchSource
    var isUnlocked: Bool { phase == .unlocked }
    var provenanceLabel: String? { BiselEnvironment.usesSoftwareKeys ? "SOFTWARE KEYS" : nil }

    // MARK: wiring
    @ObservationIgnored private(set) var vault: Vault?
    @ObservationIgnored private let directory = BiselEnvironment.dataDirectory
    @ObservationIgnored private let usage: UsageStore
    @ObservationIgnored private let index = FuzzySearchIndex()
    @ObservationIgnored private var rowsByID: [String: ItemRow] = [:]
    @ObservationIgnored private var pollTimer: Timer?
    @ObservationIgnored private var syncing = false
    @ObservationIgnored private var lockMonitor: LockMonitor?
    /// Called on lock/unlock so the panel can redraw.
    @ObservationIgnored var onLockStateChange: (() -> Void)?

    static let fillWindowKey = "security.fillWindowMinutes"
    static let idleLockKey = "security.idleLockMinutes"
    static var fillWindowMinutes: Int { UserDefaults.standard.object(forKey: fillWindowKey) as? Int ?? 5 }
    static var idleLockMinutes: Int { UserDefaults.standard.object(forKey: idleLockKey) as? Int ?? 5 }

    init() {
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        usage = UsageStore(directory: directory)
        do {
            let keyStore = BiselEnvironment.makeKeyStore(directory: directory)
            // The core's own window is a backstop (30 min); the app enforces the user's fill window and idle timeout.
            vault = try Vault(.init(location: StoreLocation(directory: directory), keyStore: keyStore, gate: AppGate(),
                                    fillWindow: 30 * 60, deviceKind: "mac"))
        } catch {
            startupError = "Could not open the local vault store: \(error.localizedDescription)"
            Log.app.error("vault init failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    func start() async {
        lockMonitor = LockMonitor(service: self)
        lockMonitor?.start()
        await refreshPhase()
    }

    // MARK: phase

    func refreshPhase() async {
        guard let vault else { return }
        if let id = try? await vault.identity() {
            deviceName = id.deviceName; serverURL = id.serverURL; deviceID = id.deviceID
        }
        let configured = await vault.isConfigured
        let unlocked = await vault.isUnlocked
        pendingChanges = (try? await vault.pendingChanges()) ?? 0
        let new: Phase = !configured ? .needsSetup : (unlocked ? .unlocked : .locked)
        setPhase(new)
        if new == .unlocked { await reload() }
    }

    private func setPhase(_ new: Phase) {
        guard new != phase else { return }
        let was = phase
        phase = new
        if new == .unlocked {
            unlockedAt = Date()
            startPolling()
        } else {
            unlockedAt = nil
            stopPolling()
            if was == .unlocked { dropDecryptedState() }
        }
        Log.app.notice("vault phase \(String(describing: was), privacy: .public) -> \(String(describing: new), privacy: .public)")
        onLockStateChange?()
    }

    // MARK: unlock / lock

    /// Touch ID, then VK is held for the fill window. With software keys (Debug) the Secure Enclave prompt that would
    /// normally come from opening the device envelope doesn't exist, so the same biometric gate runs first.
    func unlock(reason: String = "Unlock bisel") async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        if BiselEnvironment.usesSoftwareKeys { try await AppGate().authenticate(reason: reason) }
        do { try await vault.unlock(reason: reason) }
        catch let e as KeyStoreError where e == .userCancelled { throw e }
        setPhase(.unlocked)
        await reload()
        Task { await sync(reason: "unlock") }
    }

    /// Zeroes VK (inside the core) and drops every decrypted/derived thing the app holds.
    func lock(reason: String) {
        guard phase == .unlocked else { return }
        Log.app.notice("locking: \(reason, privacy: .public)")
        setPhase(.locked)
        Task { await vault?.lock() }
        // Lock the core synchronously enough: a second call below is idempotent.
    }

    private func dropDecryptedState() {
        rows = []; rowsByID = [:]
        index.replace([])
        pendingPhrase = nil
    }

    // MARK: set-up flows (all leave the vault unlocked on this Mac)

    func bootstrap(server: URL, token: String, deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let phrase = try await vault.bootstrap(server: server, bootstrapToken: token, deviceName: deviceName)
        pendingPhrase = phrase
        await refreshPhase()
        setPhase(.unlocked)
    }

    func confirmPhraseStored() {
        pendingPhrase = nil
        Task { await sync(reason: "setup") }
    }

    func recover(server: URL, phrase: String, deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        try await vault.recover(server: server, phrase: try RecoveryPhrase(phrase), deviceName: deviceName)
        await refreshPhase()
        setPhase(.unlocked)
        await sync(reason: "recover")
        await reload()
    }

    func importBackup(from url: URL, phrase: String, server: URL, token: String, deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        try await vault.importBackup(from: url, phrase: try RecoveryPhrase(phrase), server: server, bootstrapToken: token,
                                     deviceName: deviceName)
        await refreshPhase()
        setPhase(.unlocked)
        await reload()
    }

    func exportBackup(to url: URL) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.exportBackup(to: url)
    }

    func rotateRecovery() async throws -> RecoveryPhrase {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        let phrase = try await vault.rotateRecovery()
        return phrase
    }

    // MARK: items

    /// Rebuilds rows and the search index from the encrypted store. Requires the vault to be unlocked.
    func reload() async {
        guard let vault, phase == .unlocked else { return }
        do {
            let listing = try await vault.items()
            guard phase == .unlocked else { return }   // locked while decrypting: discard
            let all = listing.items.map(ItemRow.init)
            apply(rows: all)
            undecryptable = listing.undecryptable.count
        } catch {
            Log.app.error("reload failed: \(describe(error), privacy: .public)")
            if case BiselVault.VaultError.locked = error { setPhase(.locked) }
        }
    }

    private func apply(rows all: [ItemRow]) {
        rows = all.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        rowsByID = Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })
        index.replace(all.filter { $0.type == .login || $0.type == .secret }.map { r in
            let u = usage.entries[r.id]
            return SearchRecord(id: r.id, title: r.title, username: r.username, urls: r.urls, tags: r.tags,
                                lastUsed: u?.last ?? r.updatedAt, useCount: u?.count ?? 0)
        })
    }

    func item(id: String) async throws -> Item {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        return try await vault.item(id: id)
    }

    @discardableResult
    func save(_ item: Item) async throws -> Item {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        let saved = try await vault.save(item)
        await reload()
        pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges
        Task { await sync(reason: "save") }
        return saved
    }

    func delete(id: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.delete(id: id)
        usage.forget(id)
        await reload()
        pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges
        Task { await sync(reason: "delete") }
    }

    /// Imports many items without per-item syncing; one sync at the end.
    func saveMany(_ items: [Item], progress: (Int) -> Void = { _ in }) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        for (i, it) in items.enumerated() {
            var fresh = it
            fresh.id = ""
            try await vault.save(fresh)
            if i % 20 == 0 { progress(i + 1) }
        }
        progress(items.count)
        await reload()
        await sync(reason: "import")
    }

    // MARK: devices

    func devices() async throws -> [DeviceInfo] {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        return try await vault.devices()
    }

    func revoke(deviceID: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.revoke(deviceID: deviceID)
    }

    // MARK: sync

    private func startPolling() {
        pollTimer?.invalidate()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { Task { await self?.sync(reason: "poll") } }
        }
    }

    private func stopPolling() { pollTimer?.invalidate(); pollTimer = nil }

    /// Push local edits, resolve conflicts (remote wins; local edit kept as "<title> (conflict)"), pull. Offline-tolerant.
    func sync(reason: String) async {
        guard let vault, phase != .needsSetup, !syncing else { return }
        syncing = true
        syncState = .syncing
        defer { syncing = false }
        do {
            let report = try await vault.sync()
            pendingChanges = (try? await vault.pendingChanges()) ?? 0
            syncState = .synced(Date())
            lastConflicts = report.conflicts.count
            Log.app.notice("sync(\(reason, privacy: .public)): pushed=\(report.pushed) pulled=\(report.pulled) conflicts=\(report.conflicts.count) deferred=\(report.deferredConflicts.count)")
            if report.pulled > 0 || report.pushed > 0 || !report.conflicts.isEmpty { await reload() }
            if !report.conflicts.isEmpty {
                Toast.shared.show("\(report.conflicts.count) sync conflict(s): your edit was kept as “… (conflict)”", isError: true, duration: .seconds(4))
            }
        } catch let e as SyncError {
            pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges
            switch e {
            case .network(let m): syncState = .offline(m)
            default: syncState = .failed(describe(e))
            }
            Log.app.notice("sync(\(reason, privacy: .public)) failed: \(describe(e), privacy: .public)")
        } catch {
            syncState = .failed(describe(error))
            Log.app.error("sync(\(reason, privacy: .public)) failed: \(describe(error), privacy: .public)")
        }
    }

    // MARK: VaultSearchSource / VaultSecretProvider (the command panel)

    func search(_ query: String, limit: Int) -> [VaultSearchResult] {
        guard isUnlocked else { return [] }
        return index.search(query, limit: limit).map {
            VaultSearchResult(id: $0.id, title: $0.title, username: $0.username, domain: $0.domain, tags: $0.tags)
        }
    }

    func recordUse(id: String) {
        index.recordUse(id: id)
        usage.record(id)
    }

    func secret(_ kind: SecretKind, for id: String) async throws -> String {
        guard isUnlocked else { throw VaultError.locked }
        let item: Item
        do { item = try await self.item(id: id) }
        catch BiselVault.VaultError.locked { setPhase(.locked); throw VaultError.locked }
        catch BiselVault.VaultError.notFound { throw VaultError.notFound }
        switch kind {
        case .username:
            guard let v = item.username, !v.isEmpty else { throw VaultError.unavailable(kind) }
            return v
        case .password:
            guard let v = item.password, !v.isEmpty else { throw VaultError.unavailable(kind) }
            return v
        case .totp:
            guard let p = item.totp else { throw VaultError.unavailable(kind) }
            do { return try TOTPGenerator.code(p).code } catch { throw VaultError.unavailable(kind) }
        }
    }

    func url(for id: String) -> URL? {
        guard let first = rowsByID[id]?.urls.first else { return nil }
        return URL(string: first.contains("://") ? first : "https://\(first)")
    }

    func totpPeriod(for id: String) -> Int { rowsByID[id]?.totpPeriod ?? 30 }
}
