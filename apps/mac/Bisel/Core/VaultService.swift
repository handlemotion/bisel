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
    /// What the freshness witness said at the last sync. `.forked` is an alarm (a removed device is writing a box of its own);
    /// `.laneBehind` resolves itself. See BiselCore/LANES.md.
    private(set) var freshness: FreshnessState = .unavailable
    /// D4: whether to remind the owner to export a `.bisel-backup` (`status.reminder.isDue`); a box only in iCloud or only on
    /// this Mac has no second copy. nil until first read. Refreshed after each sync, reload and export. See BiselCore/BACKUP.md.
    private(set) var backupStatus: BackupStatus?
    private(set) var deviceID = ""
    /// Recovery phrase shown right after set-up, until the user confirms "I have stored it".
    private(set) var pendingPhrase: RecoveryPhrase?
    /// True from creating a brand-new box until its phrase is confirmed: the only time "Back" may throw the box away.
    private(set) var freshBox = false
    private(set) var unlockedAt: Date?
    /// First run, iCloud first (BiselCore/SETUP.md): which set-up screen the core says is next. `.welcome` before set-up, `.done`
    /// or `.attention` once a box is here. The views drive it through the set-up calls below.
    private(set) var setupState: BoxSetup.State = .checking
    var isBusy = false

    // MARK: VaultSearchSource
    var isUnlocked: Bool { phase == .unlocked }
    var provenanceLabel: String? { BiselEnvironment.usesSoftwareKeys ? "SOFTWARE KEYS" : nil }

    // MARK: wiring
    @ObservationIgnored private(set) var vault: Vault?
    @ObservationIgnored private(set) var setup: BoxSetup?
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
                                    fillWindow: 30 * 60, deviceKind: "mac", laneProvider: Self.laneProvider,
                                    freshnessWitness: Self.freshnessWitness))
            if let vault { setup = BoxSetup(vault: vault, home: Self.home) }
        } catch {
            startupError = "Could not open the local box store: \(error.localizedDescription)"
            Log.app.error("vault init failed: \(error.localizedDescription)")
        }
    }

    func start() async {
        lockMonitor = LockMonitor(service: self)
        lockMonitor?.start()
        BiometricGate.enrollmentChanged = { [weak self] in
            // Only an open box is at stake; a locked one already refuses at the Secure Enclave, and re-adding this Mac must not stall.
            guard let self, self.isUnlocked, self.vault?.deviceKeyStatus() == .biometryChanged else { return false }
            self.lock(reason: "Touch ID enrolment changed")
            return true
        }
        await followSetup()
        await refreshPhase()
        listenForLaneSignals()
    }

    /// Mirrors the set-up machine's state, and reads this Mac and iCloud once.
    private func followSetup() async {
        guard let setup else { return }
        Task { [weak self] in
            for await state in await setup.updates() { self?.setupState = state }
        }
        let state = await setup.start()
        Log.app.notice("set-up: \(String(describing: state), privacy: .public)")
    }

    /// Where new boxes go: the person's iCloud in the signed build, none in BiselDev (no iCloud entitlement; its boxes stay on this Mac).
    private static var home: (any BoxHome)? {
        #if BISEL_CLOUDKIT
        CloudBox.home
        #else
        nil
        #endif
    }

    /// The signed build syncs boxes through iCloud (`cloudkit://` addresses); the server stays for boxes that use it.
    private static var laneProvider: Vault.LaneProvider? {
        #if BISEL_CLOUDKIT
        CloudBox.provider
        #else
        nil
        #endif
    }

    /// The second freshness witness for iCloud boxes (docs/SYNC-LANES.md §8, D5): iCloud key-value storage, a separate service
    /// from the box's zone. The engine consults it only on storage lanes, so server boxes are unaffected.
    private static var freshnessWitness: (any FreshnessWitness)? {
        #if BISEL_CLOUDKIT
        ICloudFreshnessWitness()
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

    private func refreshBackupStatus() async {
        backupStatus = try? await vault?.backupStatus()
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

    /// "Create a box": in this Apple Account's iCloud (`BoxSetup.create`). Throws `SetupError.iCloud(reason)` when iCloud cannot
    /// take it and `.iCloudHasBox` when iCloud already holds one (offer adding this Mac or restoring, never a second box); nothing
    /// is made then. BiselDev (no iCloud) makes it on this Mac
    /// only. The server is not part of first run: it is opt-in from Settings (`connectServer`).
    func createBox(deviceName: String) async throws {
        guard let setup else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let phrase = try await setup.create(deviceName: deviceName)
        await didCreate(phrase)
    }

    /// The person chose to keep a new box on this Mac only (iCloud unavailable). Never chosen for them.
    func createBoxOnThisMacOnly(deviceName: String) async throws {
        guard let setup else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let phrase = try await setup.createOnThisMacOnly(deviceName: deviceName)
        await didCreate(phrase)
    }

    private func didCreate(_ phrase: RecoveryPhrase) async {
        setRecoveryUnconfirmed(true)
        pendingPhrase = phrase
        freshBox = true
        await refreshPhase()
        setPhase(.unlocked)
        if let address = serverURL { await subscribeIfICloud(address) }
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
    /// Mac's copy to the iCloud account signed in now (`BoxSetup.moveBoxToThisAccount`). Never done without the person asking;
    /// refused with `SetupError.iCloudHasBox` when that account already holds another box, unless `evenIfItHoldsAnotherBox`.
    func putBoxInICloudAgain(phrase: String? = nil, evenIfItHoldsAnotherBox: Bool = false) async throws {
        guard let setup, let address = serverURL else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        await setup.refresh()
        try await setup.moveBoxToThisAccount(words: try phrase.map(RecoveryPhrase.init), evenIfItHoldsAnotherBox: evenIfItHoldsAnotherBox)
        await subscribeIfICloud(address)
        await refreshPhase()
        await sync(reason: "put back in iCloud")
    }

    /// Stops syncing; the box stays on this Mac and nothing is deleted where it synced.
    func stopSyncing() async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.detachLane()
        await refreshPhase()
    }

    /// Back from the recovery phrase of a box that was created a moment ago and holds nothing: erase it (here and in iCloud, so
    /// the next "Create a box" is not taken for a second box) and start over.
    func discardNewBox() async {
        guard freshBox, pendingPhrase != nil, let setup else { return }
        isBusy = true; defer { isBusy = false }
        do { try await setup.discardNewBox() }
        catch SetupError.wrongStep {
            // Made outside the set-up machine (a debug tour): nothing in iCloud to erase.
            do { try await vault?.removeLocalDevice() } catch { Log.app.error("discarding the new box failed: \(describe(error))") }
        } catch { Log.app.error("discarding the new box failed: \(describe(error))") }
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
        Task {
            // A new box: the set-up machine moves on to `.done`, whose backup status carries the D4 reminder.
            if case .showPhrase = setupState { _ = try? await setup?.phraseStored() }
            await sync(reason: "setup")
            await refreshBackupStatus()
        }
    }

    /// "I already have one" with the 24 words: the box in this Apple Account's iCloud that they open (`BoxSetup.restore`).
    /// Throws `SetupError` (`.noBoxInICloud`, `.wrongPhrase`, `.iCloud(reason)`, `.boxForked`…). The server is not tried: a box on
    /// the server is reached from Settings.
    func restore(phrase: String, deviceName: String) async throws {
        guard let setup else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        try await setup.restore(words: try RecoveryPhrase(phrase), deviceName: deviceName)
        await didRestore()
    }

    /// A `.bisel-backup` file and its 24 words (`BoxSetup.restore(backup:)`): back into iCloud, or merged into the box iCloud holds.
    func restore(backup url: URL, phrase: String, deviceName: String) async throws {
        guard let setup else { throw BiselVault.VaultError.notConfigured }
        isBusy = true; defer { isBusy = false }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        try await setup.restore(backup: url, words: try RecoveryPhrase(phrase), deviceName: deviceName)
        await didRestore()
    }

    private func didRestore() async {
        if let address = (try? await vault?.identity())??.serverURL { await subscribeIfICloud(address) }
        await refreshPhase()
        setPhase(.unlocked)
        await reload()
    }

    /// The 24 words against a box on the Bisel server (after looking in iCloud). Off the first-run path, which is iCloud only
    /// (`restore(phrase:deviceName:)`); kept for the opt-in server and the debug flows that run against a local server.
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
        await refreshBackupStatus()
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
        await refreshBackupStatus()   // a box only on this Mac never syncs
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

    // MARK: enrollment over iCloud (a second Mac or an iPhone on the same Apple Account)

    /// New device, step 1: finds the box in this Mac's iCloud and asks to join it. Show `offer.secret.words` (8 words) and
    /// `offer.qrPayload` (QR), and `offer.fingerprint`; then call `finishICloudEnrollment()` until it stops throwing
    /// `EnrollmentError.notApprovedYet`. Throws `LaneError.storeMissing` when this iCloud account holds no box.
    func startICloudEnrollment(deviceName: String, box: URL? = nil) async throws -> PairingOffer {
        guard let setup else { throw BiselVault.VaultError.notConfigured }
        return try await setup.startPairing(deviceName: deviceName, box: box)
    }

    /// New device, step 2 (poll every few seconds while the offer is on screen): false until another device approved with the
    /// words; true once the box key is here and unlocked (Touch ID). Then `setupState` is `.compareCode(code)`: show it, and
    /// `confirmICloudEnrollment(code:)` with the code the other device shows.
    func finishICloudEnrollment() async throws -> Bool {
        guard let setup else { throw BiselVault.VaultError.notConfigured }
        return try await setup.checkPairing()
    }

    func confirmICloudEnrollment(code: String) async throws {
        guard let setup else { throw BiselVault.VaultError.notConfigured }
        try await setup.confirmPairing(code: code)
        if let address = (try? await vault?.identity())??.serverURL { await subscribeIfICloud(address) }
        await refreshPhase()
    }

    /// Gives up on pairing; this Mac forgets its half-made keys.
    func cancelICloudEnrollment() async throws {
        guard let setup else { throw BiselVault.VaultError.notConfigured }
        try await setup.cancelPairing()
        await refreshPhase()
    }

    /// Approving device: requests this box's iCloud lane has seen (sync first). Never approved without the person.
    func pendingEnrollments() async -> [PendingEnrollment] {
        ((try? await vault?.pendingEnrollments()) ?? nil) ?? []
    }

    /// Approving device: the person typed (or scanned) the new device's 8 words. Touch ID inside.
    func approve(_ pending: PendingEnrollment, words: [String]) async throws {
        guard let vault else { throw BiselVault.VaultError.notConfigured }
        try await vault.approveEnrollment(pending, pairing: try PairingSecret(words: words))
    }

    private func subscribeIfICloud(_ address: URL) async {
        #if BISEL_CLOUDKIT
        await CloudBox.subscribe(address)
        #endif
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
            freshness = report.freshness
            if report.freshness == .forked { Log.app.fault("freshness witness: the lane and the witness hold two chains of this box") }
            // D4 (docs/SYNC-LANES.md §6, §13): a box only in iCloud has no second copy if the Apple Account is lost.
            // `backupStatus.reminder` says when to ask for a `.bisel-backup`; the UI for it is Rodrigo's (BiselCore/BACKUP.md).
            await refreshBackupStatus()
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
