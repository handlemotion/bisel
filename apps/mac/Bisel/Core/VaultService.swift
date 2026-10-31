import AppKit
import Observation
import BiselCore
#if BISEL_CLOUDKIT
import BiselCloudKit
#endif

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
    let hasPassword: Bool
    let hasTOTP: Bool
    let totpPeriod: Int

    init(_ item: Item) {
        id = item.id; type = item.type; title = item.title; urls = item.urls; username = item.username ?? ""
        tags = item.tags; updatedAt = item.updatedAt; hasPassword = !(item.password ?? "").isEmpty; hasTOTP = item.totp != nil; totpPeriod = item.totp?.period ?? 30
    }

    var domain: String { SearchRecord.domain(of: urls.first) }
}

/// Something the owner must look at: a sync reported an event or an integrity result that could mean a stolen key, a stolen
/// phrase or a hostile server. Kept until dismissed (the Devices window lists them; the sync indicator turns red).
struct SecurityAlert: Identifiable, Equatable {
    let id: String
    let text: String
    let date: Date
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
    private(set) var securityAlerts: [SecurityAlert] = []
    /// The server offered recovery keys different from the ones this device pinned: never adopted, backups are blocked.
    private(set) var recoveryKeyChanged = false
    private(set) var undecryptable = 0
    private(set) var startupError: String?
    private(set) var deviceName = ""
    private(set) var serverURL: URL?
    /// Where the box syncs and whether that works right now (iCloud signed out, another Apple Account, data deleted in
    /// iCloud, moved elsewhere). Refreshed at launch and after every sync. See BiselCore/LANES.md for what each state asks of the UI.
    private(set) var laneStatus: LaneStatus = .thisDeviceOnly
    private(set) var deviceID = ""
    /// Recovery phrase shown right after set-up, until the user confirms "I have stored it".
    private(set) var pendingPhrase: RecoveryPhrase?
    /// True from creating a brand-new box until its phrase is confirmed: the only time "Back" may throw the box away.
    private(set) var freshBox = false
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
    @ObservationIgnored private var reloadGeneration = 0
    @ObservationIgnored private var installedGeneration = 0
    @ObservationIgnored private var pollTimer: Timer?
    @ObservationIgnored private var syncing = false
    @ObservationIgnored private var syncChain: Task<Void, Never>?
    @ObservationIgnored private var otpGatedAt: [String: ContinuousClock.Instant] = [:]
    @ObservationIgnored private var lockMonitor: LockMonitor?
    /// Called on lock/unlock so the panel can redraw.
    @ObservationIgnored var onLockStateChange: (() -> Void)?

    /// A panel open within this many seconds of the last finished sync does not sync again.
    private static let panelSyncMinInterval: TimeInterval = 10
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
                                    fillWindow: 30 * 60, deviceKind: "mac", laneProvider: Self.laneProvider))
        } catch {
            startupError = "Could not open the local box store: \(error.localizedDescription)"
            Log.app.error("vault init failed: \(error.localizedDescription)")
        }
    }

    func start() async {
        lockMonitor = LockMonitor(service: self)
        lockMonitor?.start()
        await refreshPhase()
        listenForLaneSignals()
    }

    /// The signed build syncs boxes through iCloud (`cloudkit://` addresses); the server stays for boxes that use it.
    private static var laneProvider: Vault.LaneProvider? {
        #if BISEL_CLOUDKIT
        CloudBox.provider
        #else
        nil
        #endif
    }

    /// A push from CloudKit, or the iCloud account changing, means "sync now"; the 60 s poll stays the floor.
    private func listenForLaneSignals() {
        #if BISEL_CLOUDKIT
        Task { [weak self] in
            for await _ in CloudKitLane.signals() { await self?.sync(reason: "push") }
        }
        #endif
    }

    private func refreshLaneStatus() async {
        laneStatus = ((try? await vault?.laneStatus()) ?? nil) ?? .thisDeviceOnly
    }

    // MARK: phase

    func refreshPhase() async {
        guard let vault else { return }
        if let id = try? await vault.identity() {
            deviceName = id.deviceName; serverURL = id.serverURL; deviceID = id.deviceID
        }
        await refreshLaneStatus()
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
    func unlock(reason: String = "Unlock your box") async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        if BiselEnvironment.usesSoftwareKeys { try await AppGate().authenticate(reason: reason) }
        do { try await vault.unlock(reason: reason) }
        catch let e as KeyStoreError where e == .userCancelled { throw e }
        setPhase(.unlocked)
        await reload()
        Task { await sync(reason: "unlock") }
        await resumeUnconfirmedRecovery()
    }

    /// Zeroes VK (inside the core) and drops every decrypted/derived thing the app holds.
    func lock(reason: String) {
        guard phase == .unlocked else { return }
        Log.app.notice("locking: \(reason)")
        setPhase(.locked)
        Task { await vault?.lock() }
        // Lock the core synchronously enough: a second call below is idempotent.
    }

    private func dropDecryptedState() {
        rows = []; rowsByID = [:]; otpGatedAt = [:]
        index.replace([])
        undecryptable = 0
        // pendingPhrase is deliberately kept: losing the only copy of a just-created phrase to an idle lock would be worse.
    }

    // MARK: set-up flows (all leave the vault unlocked on this Mac)

    func bootstrap(server: URL, token: String, deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let phrase = try await vault.bootstrap(server: server, bootstrapToken: token, deviceName: deviceName)
        setRecoveryUnconfirmed(true)   // the server now holds an envelope for a phrase nobody has confirmed storing yet
        pendingPhrase = phrase
        await refreshPhase()
        setPhase(.unlocked)
    }

    /// New vault that lives on this Mac only. A server can be connected later (Settings → Vault).
    func bootstrapLocal(deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let phrase = try await vault.bootstrapLocal(deviceName: deviceName)
        setRecoveryUnconfirmed(true)
        pendingPhrase = phrase
        freshBox = true
        await refreshPhase()
        setPhase(.unlocked)
    }

    /// "Create a box": in iCloud when this build has it and an account is signed in (no server involved), otherwise on this Mac
    /// only (it can be moved to iCloud later with `moveToICloud`). The server is opt-in (`connectServer`).
    func createBox(deviceName: String) async throws {
        #if BISEL_CLOUDKIT
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        if await CloudBox.isAvailable() {
            isBusy = true; defer { isBusy = false }
            let address = CloudBox.newAddress()
            let phrase = try await vault.bootstrap(lane: address, deviceName: deviceName)
            setRecoveryUnconfirmed(true)
            pendingPhrase = phrase
            freshBox = true
            await refreshPhase()
            setPhase(.unlocked)
            await CloudBox.subscribe(address)
            return
        }
        Log.app.notice("iCloud not available: creating the box on this Mac only")
        #endif
        try await bootstrapLocal(deviceName: deviceName)
    }

    /// Puts this box in iCloud and syncs through it from now on (from the server or from "this Mac only"). The server's copy
    /// is left alone. `phrase` is needed when the box never lived in iCloud (`MigrationError.phraseRequired`).
    func moveToICloud(phrase: String?) async throws {
        #if BISEL_CLOUDKIT
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let address = CloudBox.newAddress()
        try await vault.enableLane(address, phrase: try phrase.map(RecoveryPhrase.init))
        await CloudBox.subscribe(address)
        await refreshPhase()
        await sync(reason: "moved to iCloud")
        #else
        throw LaneError.unsupported
        #endif
    }

    /// After `.storeMissing` (the box's iCloud data was deleted) or `.accountChanged` (another Apple Account): upload this
    /// Mac's copy to the iCloud account signed in now. Never done without the person asking.
    func putBoxInICloudAgain(phrase: String? = nil) async throws {
        guard let vault, let address = serverURL else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        try await vault.enableLane(address, phrase: try phrase.map(RecoveryPhrase.init))
        #if BISEL_CLOUDKIT
        await CloudBox.subscribe(address)
        #endif
        await refreshPhase()
        await sync(reason: "put back in iCloud")
    }

    /// Stops syncing; the box stays on this Mac and nothing is deleted where it synced.
    func stopSyncing() async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.detachLane()
        await refreshPhase()
    }

    /// Back from the recovery phrase of a box that was created a moment ago and holds nothing: erase it and start over.
    func discardNewBox() async {
        guard freshBox, pendingPhrase != nil, let vault else { return }
        isBusy = true; defer { isBusy = false }
        do { try await vault.removeLocalDevice() } catch { Log.app.error("discarding the new box failed") }
        setRecoveryUnconfirmed(false)
        await refreshPhase()   // first: the phase goes back to set-up while the phrase is still held, so no other screen shows
        pendingPhrase = nil
        freshBox = false
    }

    /// Registers this Mac's vault with a fresh server, then uploads everything made while it was local.
    func connectServer(server: URL, token: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        try await vault.connectServer(server, bootstrapToken: token)
        await refreshPhase()
        await sync(reason: "connect")
    }

    /// No server yet: nothing to sync, nothing to show as "synced".
    var isLocalOnly: Bool { phase != .needsSetup && serverURL == nil }

    func confirmPhraseStored() {
        freshBox = false
        pendingPhrase = nil
        setRecoveryUnconfirmed(false)
        Task { await sync(reason: "setup") }
    }

    func recover(server: URL, phrase: String, deviceName: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let words = try RecoveryPhrase(phrase)
        if try await !recoverFromICloud(words, deviceName: deviceName) {
            try await vault.recover(server: server, phrase: words, deviceName: deviceName)
        }
        await refreshPhase()
        setPhase(.unlocked)
        await sync(reason: "recover")
        await reload()
    }

    /// "I already have one": a box in this Mac's iCloud that the 24 words open comes first; false when there is none (the
    /// server is tried next).
    private func recoverFromICloud(_ phrase: RecoveryPhrase, deviceName: String) async throws -> Bool {
        #if BISEL_CLOUDKIT
        guard let vault, await CloudBox.isAvailable() else { return false }
        for address in (try? await CloudBox.existingBoxes()) ?? [] {
            guard let lane = CloudBox.lane(for: address) else { continue }
            do {
                try await vault.recover(lane: RecordBox(storage: lane, deviceID: nil), address: address, phrase: phrase, deviceName: deviceName)
                await CloudBox.subscribe(address)
                return true
            } catch {
                Log.app.notice("an iCloud box did not open with these words: \(describe(error))")   // another box of the account
            }
        }
        #endif
        return false
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
        setRecoveryUnconfirmed(true)   // cleared by `confirmPhraseStored()` once the user re-enters words from it
        return phrase
    }

    // MARK: unconfirmed recovery phrase (security review M5)

    /// A marker file (no secret inside) that survives a quit or crash between "phrase generated" and "I have stored it".
    private var unconfirmedMarker: URL { directory.appendingPathComponent("recovery-unconfirmed") }
    var recoveryUnconfirmed: Bool { FileManager.default.fileExists(atPath: unconfirmedMarker.path) }

    private func setRecoveryUnconfirmed(_ on: Bool) {
        if on { FileManager.default.createFile(atPath: unconfirmedMarker.path, contents: Data()) }
        else { try? FileManager.default.removeItem(at: unconfirmedMarker) }
    }

    /// The phrase from last time was never confirmed and can't be shown again: make a new one (Touch ID) and show it.
    private func resumeUnconfirmedRecovery() async {
        guard phase == .unlocked, pendingPhrase == nil, recoveryUnconfirmed else { return }
        do {
            pendingPhrase = try await rotateRecovery()
            Log.app.notice("recovery phrase was never confirmed: issued a new one")
            AppModel.shared.showMainWindow()
        } catch { Log.app.error("could not re-issue the recovery phrase: \(describe(error))") }
    }

    // MARK: items

    /// Rebuilds rows and the search index from the encrypted store. Requires the vault to be unlocked.
    /// Decrypting happens in the `Vault` actor and sorting + tokenising on a background task; the main actor only
    /// swaps the results in (it used to do the sort and the tokenising itself: ~90 ms at 5,000 items).
    func reload() async {
        guard let vault, phase == .unlocked else { return }
        reloadGeneration += 1
        let generation = reloadGeneration
        do {
            let listing = try await vault.items()
            guard phase == .unlocked else { return }   // locked while decrypting: discard
            let usage = usage.entries
            let built = await Task.detached(priority: .userInitiated) { Self.build(listing.items, usage: usage) }.value
            // Locked meanwhile, or a reload that started later already installed a newer snapshot.
            guard phase == .unlocked, generation >= installedGeneration else { return }
            installedGeneration = generation
            apply(built)
            undecryptable = listing.undecryptable.count
        } catch {
            Log.app.error("reload failed: \(describe(error))")
            if case BiselVault.VaultError.locked = error { setPhase(.locked) }
        }
    }

    private struct Built: Sendable {
        let rows: [ItemRow]
        let byID: [String: ItemRow]
        let index: FuzzySearchIndex.Built
    }

    private nonisolated static func build(_ items: [Item], usage: [String: UsageStore.Entry]) -> Built {
        let all = items.map(ItemRow.init)
        let sorted = all.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        let records = all.filter { $0.type == .login || $0.type == .secret }.map { r in
            let u = usage[r.id]
            return SearchRecord(id: r.id, title: r.title, username: r.username, urls: r.urls, tags: r.tags,
                                lastUsed: u?.last ?? r.updatedAt, useCount: u?.count ?? 0)
        }
        return Built(rows: sorted, byID: Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) }), index: FuzzySearchIndex.build(records))
    }

    private func apply(_ built: Built) {
        rows = built.rows
        rowsByID = built.byID
        index.install(built.index)
    }

    func item(id: String) async throws -> Item {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        return try await vault.item(id: id)
    }

    @discardableResult
    func save(_ item: Item) async throws -> Item {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        let saved = try await vault.save(item)
        await didChangeLocally(reason: "save")
        return saved
    }

    /// After the vault actor stored a local change: refresh rows, index and the pending count, then sync in the background.
    func didChangeLocally(reason: String) async {
        await reload()
        if let vault { pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges }
        Task { await sync(reason: reason) }
    }

    /// An operation found the core locked (its own timer ran out): bring the app's phase in line.
    func coreReportedLocked() { setPhase(.locked) }

    func delete(id: String) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.delete(id: id)
        usage.forget(id)
        await didChangeLocally(reason: "delete")
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

    /// Revokes and re-keys. The report lists what the device could still have read, for the caller to show.
    @discardableResult
    func revoke(deviceID: String) async throws -> RotationReport {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        return try await vault.revoke(deviceID: deviceID)
    }

    func recentEvents() async -> [ServerEvent] {
        guard let vault else { return [] }
        return (try? await vault.recentEvents()) ?? []
    }

    func dismissAlert(_ id: String) { securityAlerts.removeAll { $0.id == id } }

    /// Turns what a sync reported into alerts. Events caused by this Mac itself are not alarms.
    private func raiseAlerts(_ report: SyncReport, vault: Vault) async {
        var fresh: [SecurityAlert] = []
        for e in report.events where e.deviceId != deviceID {
            let text: String
            switch e.type {
            case "recovery":
                text = e.subjectId == nil
                    ? "The recovery phrase was used to read your box. If that was not you, replace the recovery phrase and change your important passwords."
                    : "A device was added with your recovery phrase and is held back for now. If that was not you, revoke it in Devices and replace the recovery phrase."
            case "recovery_rotate": text = "The recovery phrase was replaced from another device."
            case "approve": text = "Another device was approved to join your box."
            case "revoke", "rotate": text = "Another device revoked a device or replaced the box key."
            default: continue
            }
            fresh.append(SecurityAlert(id: "event-\(e.id)", text: text, date: e.date))
        }
        for id in report.rejectedTombstones {
            fresh.append(SecurityAlert(id: "tombstone-\(id)-\(report.headSeq)", text:
                "A delete arrived that was not made with your box key. The item was restored from this Mac’s trash.", date: Date()))
        }
        let changed = await vault.recoveryMaterialChanged
        if changed && !recoveryKeyChanged {
            fresh.append(SecurityAlert(id: "recovery-material", text:
                "The server is offering different recovery keys than this Mac remembers. They were not adopted and backups are blocked. If you did not change the recovery phrase, treat the server as compromised.", date: Date()))
        }
        recoveryKeyChanged = changed
        let known = Set(securityAlerts.map(\.id))
        let added = fresh.filter { !known.contains($0.id) }
        guard !added.isEmpty else { return }
        securityAlerts.append(contentsOf: added)
        Toast.shared.show(added.count == 1 ? added[0].text : "\(added.count) security notices. Open Devices to read them", isError: true, duration: .seconds(8))
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
        // Requests run one after another (a caller that awaits always sees a pass that started after its own edits);
        // the background poll just skips a tick while one is running.
        if reason == "poll" && syncing { return }
        // Opening the panel syncs, so opening and closing it quickly would queue one pass (a signature, Keychain reads, a GET
        // and SQLite writes) per open. One that just finished, or is running, already covers it.
        if reason == "panel" {
            if syncing { return }
            if case .synced(let at) = syncState, Date().timeIntervalSince(at) < Self.panelSyncMinInterval { return }
        }
        let previous = syncChain
        let run = Task { await previous?.value; await performSync(reason: reason) }
        syncChain = run
        await run.value
    }

    private func performSync(reason: String) async {
        guard let vault, phase != .needsSetup, serverURL != nil else { return }
        syncing = true
        syncState = .syncing
        defer { syncing = false }
        do {
            let report = try await vault.sync()
            pendingChanges = (try? await vault.pendingChanges()) ?? 0
            syncState = .synced(Date())
            if !report.conflicts.isEmpty { lastConflicts = report.conflicts.count }
            await raiseAlerts(report, vault: vault)
            Log.app.notice("sync(\(reason)): pushed=\(report.pushed) pulled=\(report.pulled) conflicts=\(report.conflicts.count) deferred=\(report.deferredConflicts.count)")
            if report.rotationAdopted, await !vault.isUnlocked {
                // Another device rotated the vault key (a revoke): the core locked itself. Drop everything and ask for Touch ID.
                setPhase(.locked)
                Toast.shared.show("Box key changed on another device. Unlock to continue", duration: .seconds(4))
                return
            }
            if report.pulled > 0 || report.pushed > 0 || !report.conflicts.isEmpty { await reload() }
            await refreshLaneStatus()
            // D4 (docs/SYNC-LANES.md §6, §13): a box only in iCloud has no second copy if the Apple Account is lost. INTEGRATION
            // POINT for the backup reminder of the .bisel-backup work (PR #4): once it is on main, ask
            // `vault.backupStatus(policy:)` here (it classifies a `cloudkit://` address as iCloud-only) and raise its reminder.
            // The UI for it is Rodrigo's (BiselCore/LANES.md).
            if !report.conflicts.isEmpty {
                Toast.shared.show("\(report.conflicts.count) sync conflict(s): your edit was kept as “… (conflict)”", isError: true, duration: .seconds(4))
            }
        } catch let e as SyncError {
            pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges
            switch e {
            case .network(let m): syncState = .offline(m)
            default: syncState = .failed(describe(e))
            }
            Log.app.notice("sync(\(reason)) failed: \(describe(e))")
        } catch let e as LaneError {
            // iCloud signed out, another account, data deleted: not a failure of this Mac. `laneStatus` says which.
            pendingChanges = (try? await vault.pendingChanges()) ?? pendingChanges
            syncState = .offline(describe(e))
            await refreshLaneStatus()
            Log.app.notice("sync(\(reason)) paused: \(describe(e))")
        } catch {
            syncState = .failed(describe(error))
            Log.app.error("sync(\(reason)) failed: \(describe(error))")
        }
    }

    // MARK: VaultSearchSource / VaultSecretProvider (the command panel)

    func search(_ query: String, limit: Int) -> [VaultSearchResult] {
        guard isUnlocked else { return [] }
        return index.search(query, limit: limit).map {
            VaultSearchResult(id: $0.id, title: $0.title, username: $0.username, domain: $0.domain, tags: $0.tags,
                              hasPassword: rowsByID[$0.id]?.hasPassword ?? true, hasTOTP: rowsByID[$0.id]?.hasTOTP ?? true)
        }
    }

    func recordUse(id: String) {
        index.recordUse(id: id)
        usage.record(id)
    }

    func secret(_ kind: SecretKind, for id: String) async throws -> String {
        guard isUnlocked else { throw VaultError.locked }
        try await gateStrict(kind, id)
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

    /// SPEC §4 strict mode ("Require Touch ID to reveal or copy password and OTP"): every read of a password or OTP, from any caller
    /// (copy, fill, panel), needs a fresh `LAContext` check unless the caller just ran it (single-use credit). The panel refreshes a
    /// revealed OTP at each period boundary, so an OTP read for an item already revealed in the last 35 s does not prompt again.
    private func gateStrict(_ kind: SecretKind, _ id: String) async throws {
        guard SecuritySettings.requireTouchID, kind != .username else { return }
        if kind == .totp, let t = otpGatedAt[id], ContinuousClock.now - t < .seconds(35) { otpGatedAt[id] = .now; return }
        if !BiometricGate.consumeCredit() {
            try await BiometricGate.authenticate(reason: kind == .totp ? "Use one-time code" : "Use password", grantsCredit: false)
        }
        if kind == .totp { otpGatedAt[id] = .now }
    }

    func url(for id: String) -> URL? {
        guard let first = rowsByID[id]?.urls.first else { return nil }
        return URLPolicy.allowed(first)
    }

    func hosts(for id: String) -> [String] { FillOrigin.hosts(of: rowsByID[id]?.urls ?? []) }

    func totpPeriod(for id: String) -> Int { rowsByID[id]?.totpPeriod ?? 30 }
}
