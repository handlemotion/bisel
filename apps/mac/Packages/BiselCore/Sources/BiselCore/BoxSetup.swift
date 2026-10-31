import Foundation

/// First run on this Mac, iCloud first (docs/SYNC-LANES.md, milestones L3 and L4), as one state machine: the single API the
/// onboarding screens drive (SETUP.md). The Bisel server is not part of first run; it is opt-in, from Settings (`connectServer`,
/// `AccountLinker`).
///
/// Paths, each from `.welcome`:
/// - **Create** a box in iCloud (`create`): iCloud is checked first and every reason it cannot be used is a typed error; then the
///   24 words are shown once (`.showPhrase`) and confirmed (`phraseStored`). A box iCloud already holds is offered instead of
///   making a second one (`SetupError.iCloudHasBox`).
/// - **Add this Mac** to the box in iCloud (`startPairing`, `checkPairing`, `confirmPairing`): the 8 words or the QR code over
///   iCloud (D6), same Apple Account only (D2).
/// - **Restore** with the 24 words from the box in iCloud (`restore(words:)`), or from a `.bisel-backup` file and its 24 words
///   (`restore(backup:words:)`).
///
/// And once a box is here, `refresh` notices the iCloud account signing out or changing (`.attention`): nothing local is ever
/// lost, nothing is uploaded to another account, and the person chooses what happens (`moveBoxToThisAccount`, `stopSyncing`).
///
/// Every action throws a `SetupError` and leaves `state` on the screen to show next (on a failure, the one it came from). The
/// recovery phrase in `.showPhrase` is the only secret a state holds.
public actor BoxSetup {
    /// Where a box lives once set up.
    public enum Place: Sendable, Equatable {
        case iCloud(URL)
        /// This Mac only: a build without iCloud, or the person chose it. `putInICloud` moves it there later.
        case thisMacOnly
    }

    public struct Welcome: Sendable, Equatable {
        /// Whether a new box can go to iCloud now. `.unavailable(.notInThisBuild)` on BiselDev, whose boxes stay on this Mac.
        public var iCloud: HomeAvailability
        /// The boxes this Apple Account already holds in iCloud. Not empty: offer "add this Mac" and "restore" first, not "create".
        public var boxesInICloud: [URL]
        public var iCloudHasBox: Bool { !boxesInICloud.isEmpty }
    }

    public enum Work: Sendable, Equatable { case creating, startingPairing, finishingPairing, restoring, moving }

    public struct NewBox: Sendable, Equatable {
        /// The only copy. Show it once, then `phraseStored()` (or `discardNewBox()` to go back).
        public var phrase: RecoveryPhrase
        public var place: Place
    }

    public struct Done: Sendable, Equatable {
        public var place: Place
        /// Items brought back from a backup file.
        public var restoredItems: Int?
        /// The box could not be put in iCloud (it is on this Mac, nothing is lost): `putInICloud` once this is resolved.
        public var iCloudProblem: HomeUnavailable?
        /// D4: `backup.reminder.isDue` means the forced `.bisel-backup` reminder (BACKUP.md). A new iCloud box is always due.
        public var backup: BackupStatus?
        /// D7: a Mac recovered with the 24 words is held back (advisory) until then.
        public var activatesAt: Date?
    }

    public enum State: Sendable, Equatable {
        /// Reading this Mac and iCloud.
        case checking
        /// Nothing on this Mac yet.
        case welcome(Welcome)
        case working(Work)
        /// A new box: show the 24 words once.
        case showPhrase(NewBox)
        /// This Mac asked to join the box in iCloud: show `offer.secret.words` (8 words), `offer.qrPayload` as a QR code and
        /// `offer.fingerprint`, and call `checkPairing()` every few seconds.
        case pairing(PairingOffer)
        /// Approved on the other device: show this code, the person types the one the other device shows (`confirmPairing`).
        case compareCode(String)
        /// Set up. The app takes over (lock screen, command panel).
        case done(Done)
        /// A box is here, but its iCloud lane needs the person (`.accountUnavailable`, `.accountChanged`, `.storeMissing`,
        /// `.moved`). The box keeps working on this Mac in every one of them.
        case attention(LaneStatus)
    }

    private let vault: Vault
    private let home: (any BoxHome)?

    public private(set) var state: State = .checking
    private var continuations: [UUID: AsyncStream<State>.Continuation] = [:]

    /// `home`: the person's iCloud (`ICloudHome` in the signed app), nil in a build without iCloud. The vault's lane provider must
    /// reach the home's addresses (the app's `CloudBox.provider`).
    public init(vault: Vault, home: (any BoxHome)?) {
        self.vault = vault
        self.home = home
    }

    /// The current state first, then every change.
    public func updates() -> AsyncStream<State> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<State>.makeStream(bufferingPolicy: .bufferingNewest(1))
        continuation.yield(state)
        continuations[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.drop(id) } }
        return stream
    }

    private func drop(_ id: UUID) { continuations[id] = nil }

    @discardableResult
    private func set(_ new: State) -> State {
        state = new
        for c in continuations.values { c.yield(new) }
        return new
    }

    // MARK: start

    /// Reads this Mac and iCloud: `.welcome` with nothing here, `.pairing` when a pairing was interrupted (the app quit while
    /// the words were up), `.done` or `.attention` with a box here (`refresh`). Never throws.
    @discardableResult
    public func start() async -> State {
        set(.checking)
        // Approved, but the codes were never compared (the app quit in between): `checkPairing()` unlocks and shows the code.
        if await vault.isConfigured, await vault.enrollmentNeedsConfirmation { return set(.working(.finishingPairing)) }
        if await vault.isConfigured { return await refresh() }
        if let offer = await vault.pendingPairing() { return set(.pairing(offer)) }
        // Device keys without a box key (a pairing of an older build, cut short): nothing to lose, so start clean.
        if await vault.isHalfMade { try? await vault.removeLocalDevice() }
        return set(.welcome(await look()))
    }

    private func look() async -> Welcome {
        guard let home else { return Welcome(iCloud: .unavailable(.notInThisBuild), boxesInICloud: []) }
        let available = await home.availability()
        guard available == .available else { return Welcome(iCloud: available, boxesInICloud: []) }
        do { return Welcome(iCloud: .available, boxesInICloud: try await home.boxes()) }
        catch { return Welcome(iCloud: .unavailable(home.classify(error) ?? .temporarilyUnavailable), boxesInICloud: []) }
    }

    /// iCloud as a step needs it: usable now, or the typed reason it is not.
    private func usableHome() async throws(SetupError) -> any BoxHome {
        guard let home else { throw .iCloud(.notInThisBuild) }
        if case .unavailable(let why) = await home.availability() { throw .iCloud(why) }
        return home
    }

    // MARK: create

    /// A new box in this Apple Account's iCloud. Throws `.iCloud(reason)` when iCloud cannot take it (nothing is made) and
    /// `.iCloudHasBox` when iCloud already holds one (offer pairing and restore; `createAnyway` makes a second box regardless).
    /// In a build without iCloud the box is made on this Mac only, as that build always did. Then `.showPhrase`.
    @discardableResult
    public func create(deviceName: String) async throws(SetupError) -> RecoveryPhrase {
        try await create(deviceName: deviceName, evenIfICloudHasBox: false)
    }

    /// Same, when the person saw the box iCloud already holds and still wants a new, separate one.
    @discardableResult
    public func createAnyway(deviceName: String) async throws(SetupError) -> RecoveryPhrase {
        try await create(deviceName: deviceName, evenIfICloudHasBox: true)
    }

    /// The person chose to keep the box on this Mac only (iCloud is unavailable, or they do not want it there). Never chosen for them.
    @discardableResult
    public func createOnThisMacOnly(deviceName: String) async throws(SetupError) -> RecoveryPhrase {
        try await notSetUp()
        let back = state
        set(.working(.creating))
        let phrase = try await run(back) { try await self.vault.bootstrapLocal(deviceName: deviceName) }
        set(.showPhrase(NewBox(phrase: phrase, place: .thisMacOnly)))
        return phrase
    }

    private func create(deviceName: String, evenIfICloudHasBox: Bool) async throws(SetupError) -> RecoveryPhrase {
        try await notSetUp()
        let welcome = await look()
        switch welcome.iCloud {
        case .unavailable(.notInThisBuild):
            return try await createOnThisMacOnly(deviceName: deviceName)
        case .unavailable(let why):
            set(.welcome(welcome))
            throw .iCloud(why)
        case .available:
            if welcome.iCloudHasBox && !evenIfICloudHasBox {
                set(.welcome(welcome))
                throw .iCloudHasBox(welcome.boxesInICloud)
            }
        }
        guard let home else { throw .iCloud(.notInThisBuild) }
        set(.working(.creating))
        let address = home.newAddress()
        do {
            let phrase = try await vault.bootstrap(lane: address, deviceName: deviceName)
            set(.showPhrase(NewBox(phrase: phrase, place: .iCloud(address))))
            return phrase
        } catch {
            // The vault already removed what it made here; whatever reached iCloud must not pose as a box (it would block the
            // next try with `.iCloudHasBox`). Best effort: offline, nothing reached it anyway.
            try? await home.lane(address)?.erase(confirmed: LaneEraseToken())
            set(.welcome(welcome))
            throw failure(error)
        }
    }

    /// The 24 words of the new box are written down: on to `.done`, with the backup reminder (D4) due for a box with no second copy.
    @discardableResult
    public func phraseStored() async throws(SetupError) -> Done {
        guard case .showPhrase(let new) = state else { throw .wrongStep }
        try await run(nil) { try await self.vault.markRecoveryConfirmed() }
        let done = await finished(new.place)
        set(.done(done))
        return done
    }

    /// Back from the phrase of a box made a moment ago: it is erased here and in iCloud, so the next `create` starts clean.
    public func discardNewBox() async throws(SetupError) {
        guard case .showPhrase(let new) = state else { throw .wrongStep }
        if case .iCloud(let address) = new.place {
            try? await home?.lane(address)?.erase(confirmed: LaneEraseToken())
        }
        try await run(nil) { try await self.vault.removeLocalDevice() }
        set(.welcome(await look()))
    }

    // MARK: add this Mac to the box in iCloud (D6)

    /// Puts this Mac's request to join on the box in iCloud and returns what to show: the 8 words, the QR code, the fingerprint.
    /// `box` only when iCloud holds several (`.chooseBox`). Same Apple Account only: another account's boxes are not visible here.
    @discardableResult
    public func startPairing(deviceName: String, box: URL? = nil) async throws(SetupError) -> PairingOffer {
        try await notSetUp()
        let home = try await usableHome()
        let back = state
        let boxes = try await run(back) { try await home.boxes() }
        let address: URL
        if let box {
            guard boxes.contains(box) else { throw .noBoxInICloud }
            address = box
        } else if boxes.count == 1 {
            address = boxes[0]
        } else {
            throw boxes.isEmpty ? .noBoxInICloud : .chooseBox(boxes)
        }
        set(.working(.startingPairing))
        let offer = try await run(back) { try await self.vault.prepareEnrollment(lane: address, deviceName: deviceName) }
        set(.pairing(offer))
        return offer
    }

    /// Call every few seconds while `.pairing` is up. false: not approved yet. true: approved, the box key is here and the vault
    /// is unlocked (Touch ID): `.compareCode`. `.approvalUnproven` is an alarm: something that is not the person's other device
    /// answered. Stop polling, say so, and `cancelPairing()`.
    ///
    /// After a cancelled Touch ID (`.cancelled`) the state stays `.working(.finishingPairing)`: call it again to retry the unlock.
    public func checkPairing() async throws(SetupError) -> Bool {
        switch state {
        case .pairing:
            do { try await vault.completeEnrollment() }
            catch EnrollmentError.notApprovedYet { return false }
            catch { throw failure(error) }
            set(.working(.finishingPairing))
        case .working(.finishingPairing): break
        default: throw .wrongStep
        }
        let code: String = try await run(nil) {
            try await self.vault.unlock(reason: "Open your box on this Mac")
            return try await self.vault.verificationCode()
        }
        set(.compareCode(code))
        return true
    }

    /// The person typed the code the other device shows. A mismatch locks the box here (`.codeMismatch`): `cancelPairing()`.
    @discardableResult
    public func confirmPairing(code: String) async throws(SetupError) -> Done {
        guard case .compareCode = state else { throw .wrongStep }
        try await run(nil) { try await self.vault.confirmEnrollment(code: code) }
        _ = try? await vault.sync()
        let place: Place = (try? await vault.identity()?.serverURL).flatMap { $0 }.map { .iCloud($0) } ?? .thisMacOnly
        let done = await finished(place)
        set(.done(done))
        return done
    }

    /// Gives up on pairing: this Mac forgets its half-made keys (it holds no box key yet, so nothing is lost). The request left in
    /// iCloud expires on its own (`PendingEnrollment.lifetime`).
    public func cancelPairing() async throws(SetupError) {
        switch state {
        case .pairing, .compareCode, .working(.finishingPairing): break
        default: throw .wrongStep
        }
        try await run(nil) { try await self.vault.removeLocalDevice() }
        set(.welcome(await look()))
    }

    // MARK: restore

    /// The 24 words and the box already in this Apple Account's iCloud: the box the words open is restored on this Mac.
    /// `.noBoxInICloud`, `.wrongPhrase` (no box there opens with them), `.boxForked` / `.boxBehind` (the freshness witness, D5,
    /// says that copy is not the box's latest: refused, not retried).
    @discardableResult
    public func restore(words: RecoveryPhrase, deviceName: String) async throws(SetupError) -> Done {
        try await notSetUp()
        let back = state
        let address = try await recoverFromICloud(words, deviceName: deviceName, back: back)
        _ = try? await vault.sync()
        let done = await finished(.iCloud(address))
        set(.done(done))
        return done
    }

    private func recoverFromICloud(_ words: RecoveryPhrase, deviceName: String, back: State) async throws(SetupError) -> URL {
        let home = try await usableHome()
        let boxes = try await run(back) { try await home.boxes() }
        guard !boxes.isEmpty else { throw .noBoxInICloud }
        set(.working(.restoring))
        for address in boxes {
            guard let lane = home.lane(address) else { continue }
            do {
                try await vault.recover(lane: RecordBox(storage: lane, deviceID: nil), address: address, phrase: words, deviceName: deviceName)
                return address
            } catch {
                let failed = failure(error)
                switch failed {
                // The words opened this box, but it is not to be trusted as it is; another box is not the answer.
                case .boxForked, .boxBehind, .iCloud: set(back); throw failed
                // Another box of this account, or not these words.
                default: continue
                }
            }
        }
        set(back)
        throw .wrongPhrase
    }

    /// A `.bisel-backup` file and its 24 words. The file is checked before anything is written. Then:
    /// - iCloud already holds the box (the words open it): that copy is restored, as the live one, and the file merged into it
    ///   (nothing overwritten; `BACKUP.md`). iCloud holds a box the words do not open: `.iCloudHasOtherBox`, nothing written.
    /// - iCloud holds no box: the file is restored and the box put in iCloud. If that last step fails the box stays on this Mac
    ///   (`Done.iCloudProblem`; `putInICloud` later).
    /// - iCloud unavailable: `.iCloud(reason)`, nothing written (`restoreOnThisMacOnly` is the person's explicit alternative).
    ///   A build without iCloud restores on this Mac.
    @discardableResult
    public func restore(backup url: URL, words: RecoveryPhrase, deviceName: String) async throws(SetupError) -> Done {
        try await notSetUp()
        let back = state
        try await run(back) { try Vault.checkBackup(at: url, phrase: words) }
        let welcome = await look()
        switch welcome.iCloud {
        case .unavailable(.notInThisBuild):
            return try await restoreOnThisMacOnly(backup: url, words: words, deviceName: deviceName)
        case .unavailable(let why):
            throw .iCloud(why)
        case .available where welcome.iCloudHasBox:
            let address: URL
            do { address = try await recoverFromICloud(words, deviceName: deviceName, back: back) }
            catch .wrongPhrase { throw .iCloudHasOtherBox(welcome.boxesInICloud) }
            _ = try? await vault.sync()
            // Restored from iCloud: the file only adds what the box no longer has. Touch ID inside.
            let merged = try await run(nil) { try await self.vault.mergeBackup(from: url, phrase: words) }
            _ = try? await vault.sync()
            var done = await finished(.iCloud(address))
            done.restoredItems = merged.added
            set(.done(done))
            return done
        case .available:
            set(.working(.restoring))
            let report = try await run(back) { try await self.vault.restoreBackup(from: url, phrase: words, deviceName: deviceName) }
            var done: Done
            do {
                guard let home else { throw SetupError.iCloud(.notInThisBuild) }
                set(.working(.moving))
                let address = home.newAddress()
                try await vault.enableLane(address, phrase: words)
                done = await finished(.iCloud(address))
            } catch {
                done = await finished(.thisMacOnly)
                done.iCloudProblem = failure(error).iCloudReason ?? .temporarilyUnavailable
            }
            done.restoredItems = report.added
            set(.done(done))
            return done
        }
    }

    /// The person chose to restore the file on this Mac only (iCloud unavailable, or not wanted). Never chosen for them.
    @discardableResult
    public func restoreOnThisMacOnly(backup url: URL, words: RecoveryPhrase, deviceName: String) async throws(SetupError) -> Done {
        try await notSetUp()
        let back = state
        set(.working(.restoring))
        let report = try await run(back) { try await self.vault.restoreBackup(from: url, phrase: words, deviceName: deviceName) }
        var done = await finished(.thisMacOnly)
        done.restoredItems = report.added
        set(.done(done))
        return done
    }

    // MARK: a box here, and its iCloud account

    /// With a box on this Mac: one sync, then where it stands. `.done` when the lane is fine (or there is none), `.attention`
    /// when iCloud signed out, another Apple Account is signed in, the box's iCloud data was deleted, or it moved elsewhere.
    /// Call at launch and whenever the iCloud account changes. Nothing is ever uploaded to an account the box was not put on.
    @discardableResult
    public func refresh() async -> State {
        guard await vault.isConfigured else { return await start() }
        _ = try? await vault.sync()
        let status = (try? await vault.laneStatus()) ?? .thisDeviceOnly
        switch status {
        case .active, .thisDeviceOnly:
            let address = (try? await vault.identity()?.serverURL).flatMap { $0 }
            return set(.done(await finished(address.map { .iCloud($0) } ?? .thisMacOnly)))
        case .accountUnavailable, .accountChanged, .storeMissing, .moved:
            return set(.attention(status))
        }
    }

    /// `.attention(.accountChanged)`: the person moves the box to the Apple Account signed in now (or, after `.storeMissing`,
    /// puts this Mac's copy back). Needs the box unlocked. Refuses (`.iCloudHasBox`) when that account already holds another
    /// box, unless `evenIfItHoldsAnotherBox`. `words` when the vault asks for them (`.move(.phraseRequired)`).
    public func moveBoxToThisAccount(words: RecoveryPhrase? = nil, evenIfItHoldsAnotherBox: Bool = false) async throws(SetupError) {
        guard case .attention(let status) = state, status == .accountChanged || status == .storeMissing else { throw .wrongStep }
        let home = try await usableHome()
        let address: URL = try await run(nil) {
            guard let url = try await self.vault.identity()?.serverURL else { throw VaultError.notConfigured }
            return url
        }
        if status == .accountChanged && !evenIfItHoldsAnotherBox {
            let others = try await run(nil) { try await home.boxes().filter { $0 != address } }
            if !others.isEmpty { throw .iCloudHasBox(others) }
        }
        set(.working(.moving))
        try await run(.attention(status)) { try await self.vault.enableLane(address, phrase: words) }
        await refresh()
    }

    /// `.attention`: the person stops syncing. The box stays on this Mac, whole; nothing is deleted in iCloud.
    public func stopSyncing() async throws(SetupError) {
        guard case .attention = state else { throw .wrongStep }
        try await run(nil) { try await self.vault.detachLane() }
        set(.done(await finished(.thisMacOnly)))
    }

    /// A box on this Mac only (restored while iCloud was unavailable, or made there on purpose) goes to iCloud. Needs it unlocked
    /// and, for a box that never was in iCloud, the 24 words.
    public func putInICloud(words: RecoveryPhrase?) async throws(SetupError) {
        guard case .done(let done) = state, done.place == .thisMacOnly else { throw .wrongStep }
        let home = try await usableHome()
        let boxes = try await run(nil) { try await home.boxes() }
        if !boxes.isEmpty { throw .iCloudHasBox(boxes) }
        set(.working(.moving))
        let address = home.newAddress()
        try await run(.done(done)) { try await self.vault.enableLane(address, phrase: words) }
        set(.done(await finished(.iCloud(address))))
    }

    // MARK: plumbing

    private func notSetUp() async throws(SetupError) {
        if await vault.isConfigured { throw .alreadySetUp }
        switch state {
        case .working, .showPhrase, .pairing, .compareCode: throw .wrongStep
        default: break
        }
    }

    private func finished(_ place: Place) async -> Done {
        Done(place: place, backup: try? await vault.backupStatus(), activatesAt: await vault.activationDate())
    }

    /// Runs one step; on a failure goes back to `back` (when given) and throws the failure as the person should read it.
    @discardableResult
    private func run<T>(_ back: State?, _ body: () async throws -> T) async throws(SetupError) -> T {
        do { return try await body() }
        catch {
            if let back { set(back) }
            throw failure(error)
        }
    }

    private func failure(_ error: any Error) -> SetupError {
        if let e = error as? SetupError { return e }
        if let why = home?.classify(error) { return .iCloud(why) }
        switch error {
        case SyncError.server(_, let code) where code == "\(LaneRejection.quota)": return .iCloud(.quotaFull)
        case SyncError.network: return .iCloud(.offline)
        case is URLError: return .iCloud(.offline)
        case FreshnessError.forked: return .boxForked
        case FreshnessError.laneBehind: return .boxBehind
        case BackupError.wrongPhrase: return .wrongPhrase
        case let e as BackupError: return .backup(e)
        case BiselCryptoError.invalidRecoveryPhrase: return .invalidPhrase
        case KeyStoreError.userCancelled: return .cancelled
        case VaultError.alreadyConfigured: return .alreadySetUp
        case VaultError.locked: return .locked
        case EnrollmentError.approvalUnproven: return .approvalUnproven
        case EnrollmentError.expired: return .pairingExpired
        case IntegrityError.verificationCodeMismatch: return .codeMismatch
        case let e as MigrationError: return .move(e)
        case LaneError.occupied: return .iCloudHasOtherBox([])
        case LaneError.accountChanged: return .accountChanged
        default: return .failed(error.localizedDescription)
        }
    }
}

/// Why a setup step did not happen. In every case nothing on this Mac was lost, and nothing half-made was left behind.
public enum SetupError: Error, Sendable, Equatable {
    /// iCloud cannot be used for this right now (`HomeUnavailable` says why and what the person can do).
    case iCloud(HomeUnavailable)
    /// This Apple Account's iCloud already holds a box: offer "add this Mac" and "restore" rather than a second box.
    case iCloudHasBox([URL])
    /// iCloud holds a box, but not one these 24 words open: restoring a backup here would make a second box (nothing written).
    case iCloudHasOtherBox([URL])
    /// Adding this Mac or restoring needs a box in iCloud, and this Apple Account holds none.
    case noBoxInICloud
    /// iCloud holds several boxes: pass the one to join (`startPairing(box:)`).
    case chooseBox([URL])
    /// The 24 words open no box in iCloud, or are not the backup's.
    case wrongPhrase
    /// Not 24 valid words.
    case invalidPhrase
    /// The box in iCloud is a fork a removed device wrote (D5): refused. An alarm, not a retry.
    case boxForked
    /// The box in iCloud is older than the box was (a restored snapshot): refused. Try again later or from another device.
    case boxBehind
    /// The backup file was refused before anything was written (BACKUP.md: tampered, truncated, newer version…).
    case backup(BackupError)
    /// The approval that arrived was not made with this Mac's pairing words. Alarm: stop, say so, cancel.
    case approvalUnproven
    /// The other device saw this request too long ago: start pairing again.
    case pairingExpired
    /// The code typed is not the other device's: the box locked itself here. Cancel and pair again.
    case codeMismatch
    /// Moving the box to the signed-in account did not happen (`MigrationError`: phrase required, pending changes…).
    case move(MigrationError)
    /// The account signed in to iCloud is not the one the box was put on: nothing was uploaded.
    case accountChanged
    /// Touch ID was cancelled.
    case cancelled
    /// The box is locked: unlock, then try again.
    case locked
    /// This Mac already has a box.
    case alreadySetUp
    /// That action does not apply to the current state.
    case wrongStep
    case failed(String)

    /// The iCloud reason, when this is one.
    public var iCloudReason: HomeUnavailable? { if case .iCloud(let why) = self { return why } else { return nil } }
}

extension SetupError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .iCloud(let why): return why.errorDescription
        case .iCloudHasBox: return "Your iCloud already has a Bisel box. Add this Mac to it, or restore it with your 24 words."
        case .iCloudHasOtherBox: return "Your iCloud holds a different Bisel box than the one these 24 words open. Nothing was restored."
        case .noBoxInICloud: return "There's no Bisel box in this Mac's iCloud. Sign in to the Apple Account that has it, or create a box."
        case .chooseBox: return "Your iCloud holds more than one Bisel box. Choose the one to use."
        case .wrongPhrase: return "These 24 words don't open your box."
        case .invalidPhrase: return "That isn't a valid 24-word recovery phrase."
        case .boxForked: return "The box in iCloud was changed by a device that was removed. Nothing was restored. Remove that device from your Apple Account."
        case .boxBehind: return "The box in iCloud is older than your box. Nothing was restored. Try again later, or from another device."
        case .backup(let e): return e.errorDescription
        case .approvalUnproven: return "Something other than your device answered this request. Nothing was added. Start again."
        case .pairingExpired: return "The request expired. Start again on this Mac."
        case .codeMismatch: return "The codes don't match. Nothing was trusted. Start again."
        case .move(let e): return e.errorDescription
        case .accountChanged: return LaneError.accountChanged.errorDescription
        case .cancelled: return "Cancelled"
        case .locked: return "Unlock your box first."
        case .alreadySetUp: return "This Mac already has a box."
        case .wrongStep: return "That can't be done right now."
        case .failed(let message): return message
        }
    }
}

extension Vault {
    /// A pairing this Mac started and did not finish (the app quit while the words were up): the same offer again.
    func pendingPairing() -> PairingOffer? {
        guard let id = (try? store.identity()) ?? nil, id.envelope == nil, let raw = id.pairingSecret, let address = id.serverURL,
              let secret = try? PairingSecret(rawValue: raw), let keys = (try? config.keyStore.publicKeys()) ?? nil else { return nil }
        return PairingOffer(request: EnrollmentRequest(server: address, deviceID: id.deviceID, name: id.deviceName, kind: config.deviceKind,
                                                       sigPubkey: keys.sig, encPubkey: keys.enc), secret: secret)
    }

    /// Device keys and an identity, but no box key: an enrollment that never finished.
    var isHalfMade: Bool { ((try? store.identity()) ?? nil).map { $0.envelope == nil } ?? false }

    /// Refuses a file these words do not open (or a damaged one) before anything is written.
    static func checkBackup(at url: URL, phrase: RecoveryPhrase) throws {
        _ = try inspectBackup(at: url)
        var contents = try BackupArchive.open(try Data(contentsOf: url), phrase: phrase)
        contents.zeroize()
    }
}
