import AppKit
import Observation

enum PanelAction: String, CaseIterable, Identifiable {
    case copyPassword, copyUsername, copyTOTP, fill, fillUserTabPassword, fillUsername, fillPassword, fillTOTP, openURL

    var id: String { rawValue }

    /// User-facing name (also the VoiceOver label and the Voice Control name).
    var title: String {
        switch self {
        case .copyPassword: String(localized: "Copy password")
        case .copyUsername: String(localized: "Copy username")
        case .copyTOTP: String(localized: "Copy one-time code")
        case .fill: String(localized: "Fill focused field")
        case .fillUserTabPassword: String(localized: "Fill username, Tab, password")
        case .fillUsername: String(localized: "Fill username")
        case .fillPassword: String(localized: "Fill password")
        case .fillTOTP: String(localized: "Fill one-time code")
        case .openURL: String(localized: "Open site")
        }
    }

    /// The shortcut as VoiceOver should say it ("↩" is read as nothing useful).
    var spokenShortcut: String? {
        switch self {
        case .copyPassword: String(localized: "Return")
        case .copyUsername: String(localized: "Shift Return")
        case .copyTOTP: String(localized: "Command Return")
        case .fill: String(localized: "Option Return")
        case .fillUserTabPassword: String(localized: "Command Option Return")
        default: nil
        }
    }

    /// Direct keyboard shortcut shown on the row, if any.
    var shortcut: String? {
        switch self {
        case .copyPassword: "↩"
        case .copyUsername: "⇧↩"
        case .copyTOTP: "⌘↩"
        case .fill: "⌥↩"
        case .fillUserTabPassword: "⌘⌥↩"
        default: nil
        }
    }

    var symbol: String {
        switch self {
        case .copyPassword, .copyUsername, .copyTOTP: "doc.on.doc"
        case .fill, .fillUserTabPassword, .fillUsername, .fillPassword, .fillTOTP: "keyboard"
        case .openURL: "safari"
        }
    }
}

enum PillID: String, CaseIterable, Identifiable {
    case copy, fill, userTabPassword
    var id: String { rawValue }
    var label: String {
        switch self {
        case .copy: String(localized: "Copy")
        case .fill: String(localized: "Fill")
        case .userTabPassword: String(localized: "User ⇥ Pass")
        }
    }
    var symbol: String {
        switch self {
        case .copy: "doc.on.doc"
        case .fill: "paperplane"
        case .userTabPassword: "keyboard"
        }
    }
    /// Figma icon in the asset catalog (template-tinted); nil = placeholder SF Symbol until a Figma icon exists.
    var asset: String? {
        switch self {
        case .copy: "IconCopy"
        case .fill: "IconSend"
        case .userTabPassword: nil
        }
    }
    /// Keycap shown inside the pill, if any (the default action only).
    var key: String? { self == .copy ? "↩" : nil }
    var isPrimary: Bool { self == .copy }
}

/// Rows of the Values card in the detail pane.
enum ValueRowID: String, CaseIterable, Identifiable {
    case otp, username, password, website
    var id: String { rawValue }
    var label: String {
        switch self {
        case .otp: String(localized: "OTP")
        case .username: String(localized: "Username")
        case .password: String(localized: "Password")
        case .website: String(localized: "Website")
        }
    }

    /// Name spoken for the row: "OTP" is read letter by letter, so spell out what it is.
    var spokenLabel: String {
        switch self {
        case .otp: String(localized: "One-time code")
        default: label
        }
    }
}

/// Security preferences that change how secrets are shown and copied (SPEC.md §4).
enum SecuritySettings {
    static let requireTouchIDKey = "security.requireTouchIDForSecrets"
    /// "Require Touch ID to reveal or copy password and OTP". Default OFF: values are visible whenever the vault is
    /// unlocked (the unlock opened the fill window) and copying inside the window needs no extra prompt. ON restores
    /// the strict rule: masked until a fresh LAContext check, and a fresh check for every copy.
    static var requireTouchID: Bool { UserDefaults.standard.bool(forKey: requireTouchIDKey) }
}

@MainActor
@Observable
final class CommandPanelModel {
    enum Mode: Equatable { case search, actions(VaultSearchResult) }
    struct Notice: Equatable { var text: String; var isError: Bool }

    static let resultLimit = 50

    @ObservationIgnored let source: VaultSearchSource
    @ObservationIgnored let secrets: VaultSecretProvider
    @ObservationIgnored var runFill: ((FillPlan, VaultSearchResult) -> Void)?
    @ObservationIgnored var runCopy: ((SecretKind, VaultSearchResult) -> Void)?
    @ObservationIgnored var runOpenURL: ((VaultSearchResult) -> Void)?
    @ObservationIgnored var runUnlock: (() -> Void)?
    @ObservationIgnored var runClose: (() -> Void)?

    var query = "" { didSet { if query != oldValue { refresh() } } }
    private(set) var results: [VaultSearchResult] = []
    /// 0 = best match / most recent, at the top of the list.
    var selected = 0 { didSet { if selected != oldValue { prepareValues() } } }
    var mode: Mode = .search
    var actionIndex = 0
    var hoveredPill: PillID?
    var hoveredValue: ValueRowID?
    /// Brief replacement text for a value row ("Copied", or why it failed), cleared after ~1 s.
    struct Flash: Equatable { var text: String; var isError: Bool }
    private(set) var flashes: [ValueRowID: Flash] = [:]
    /// Live OTP code, only after a fresh biometric reveal, for one item, auto-masked after `revealWindow`.
    struct RevealedOTP: Equatable { var itemID: String; var code: String; var period: Int }
    private(set) var revealedOTP: RevealedOTP?
    static let revealWindow: Duration = .seconds(30)
    /// Password text shown in the Values card (relaxed mode only), for the selected item only.
    private(set) var plainPassword: (itemID: String, value: String)?
    @ObservationIgnored private var revealTask: Task<Void, Never>?
    @ObservationIgnored private var valuesTask: Task<Void, Never>?
    @ObservationIgnored private var flashTasks: [ValueRowID: Task<Void, Never>] = [:]
    var notice: Notice?
    var focusToken = 0
    /// Drives the open/close animation of the content (the window itself never resizes).
    var presented = false
    /// Pill whose label shows "✓ Copied" for ~0.5 s after a copy it triggered.
    var pillFlash: PillID?
    /// Called after a successful copy when "Close after copy" is on (the controller dismisses after the flash).
    @ObservationIgnored var pillTriggered = false
    @ObservationIgnored var runCloseAfterCopy: (() -> Void)?
    /// Double-click on the search bar: drop the dragged offset and re-center on the position setting.
    @ObservationIgnored var resetPosition: (() -> Void)?
    static let copiedFlash: Duration = .milliseconds(500)
    static var copiedText: String { String(localized: "Copied") }
    @ObservationIgnored var hoverStats: [String: Int] = [:]
    /// Name of the app that will receive the fill; nil when the panel was opened from bisel itself.
    var targetName: String?

    /// Set when the pointer (not the keyboard) moved the selection, so the list does not scroll under the pointer.
    @ObservationIgnored var pointerDriven = false
    @ObservationIgnored var rowFrames: [String: CGRect] = [:]
    @ObservationIgnored var pillFrames: [PillID: CGRect] = [:]
    @ObservationIgnored var valueFrames: [ValueRowID: CGRect] = [:]
    @ObservationIgnored var listFrame: CGRect = .zero
    /// Scroll offset of the list (panel space), kept current by the view; rows are fixed-height so hit-testing is arithmetic.
    @ObservationIgnored var scrollOffset: CGFloat = 0
    @ObservationIgnored var rowPitch: CGFloat = 49
    /// Empty space above the first row inside the list's scroll content (kept in sync by the view).
    @ObservationIgnored var listTopInset: CGFloat = 0
    @ObservationIgnored var lastKeyboardAt: ContinuousClock.Instant = .now

    var isUnlocked: Bool { source.isUnlocked }
    var actions: [PanelAction] { PanelAction.allCases }
    var selectedResult: VaultSearchResult? { results.indices.contains(selected) ? results[selected] : nil }

    init(source: VaultSearchSource, secrets: VaultSecretProvider) {
        self.source = source
        self.secrets = secrets
    }

    /// Full reset, run on every show AND every hide: opens as the recents list with the first item selected,
    /// empty query, no stale state.
    func reset(targetName: String?) {
        self.targetName = targetName
        mode = .search
        notice = nil
        actionIndex = 0
        hoveredPill = nil
        hoveredValue = nil
        prepareValues()
        flashTasks.values.forEach { $0.cancel() }
        flashTasks = [:]
        flashes = [:]
        if query.isEmpty { refresh() } else { query = "" }
        focusToken += 1
    }

    func refresh() {
        let t0 = ContinuousClock.now
        results = source.search(query, limit: Self.resultLimit)
        selected = 0
        notice = nil
        prepareValues()
        let dt = ContinuousClock.now - t0
        Log.search.debug("search returned \(self.results.count) results in \(dt.ms, format: .fixed(precision: 3)) ms")
        announceResultsSoon()
    }

    // MARK: accessibility

    @ObservationIgnored private var announceTask: Task<Void, Never>?

    /// Polite result-count announcement once typing pauses ("12 results, GitHub selected"), so VoiceOver users hear
    /// that the list changed without being interrupted per keystroke. Silent when the panel is not showing.
    private func announceResultsSoon() {
        announceTask?.cancel()
        guard presented, PanelAnnouncer.isActive else { return }
        announceTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(450))
            guard !Task.isCancelled, let self, self.presented else { return }
            if let first = self.selectedResult {
                PanelAnnouncer.announce(String(localized: "\(self.results.count) results, \(first.title) selected"), priority: .low)
            } else {
                PanelAnnouncer.announce(String(localized: "No matches"), priority: .low)
            }
        }
    }

    /// What VoiceOver says for list row `index`: login, user and site, and the position (the list is lazy, so the
    /// total would otherwise be unknown).
    func spokenDescription(ofResultAt index: Int) -> String {
        guard results.indices.contains(index) else { return "" }
        let r = results[index]
        let parts = [r.username, r.domain].filter { !$0.isEmpty }
        let position = String(localized: "\(index + 1) of \(results.count)")
        return (parts + [position]).joined(separator: ", ")
    }

    func spokenDescription(ofActionAt index: Int) -> String {
        guard actions.indices.contains(index) else { return "" }
        let a = actions[index]
        return [a.spokenShortcut.map { String(localized: "Shortcut: \($0)") }, String(localized: "\(index + 1) of \(actions.count)")]
            .compactMap { $0 }.joined(separator: ", ")
    }

    /// VoiceOver / Voice Control activation of a list row: select it (the same as a click).
    func selectResult(at index: Int) {
        guard results.indices.contains(index) else { return }
        pointerDriven = true
        selected = index
    }

    /// VoiceOver custom action on a row: select it, then run the key's action.
    func activateResult(at index: Int, _ key: ActivationKey) {
        selectResult(at: index)
        activate(key)
    }

    func activateAction(at index: Int) {
        guard actions.indices.contains(index) else { return }
        pointerDriven = true
        actionIndex = index
        activate(.plain)
    }

    /// Speaks the live one-time code on request (never automatically; the digits are not in the accessibility tree).
    func speakOTP() {
        guard let otp = revealedOTP else { return }
        PanelAnnouncer.announce(otp.code.map(String.init).joined(separator: " "), priority: .high)
    }

    private func announceSelection() {
        guard presented, PanelAnnouncer.isActive else { return }
        switch mode {
        case .search:
            guard let r = selectedResult else { return }
            PanelAnnouncer.announce("\(r.title), \(spokenDescription(ofResultAt: selected))", priority: .medium)
        case .actions:
            PanelAnnouncer.announce("\(actions[actionIndex].title), \(spokenDescription(ofActionAt: actionIndex))", priority: .medium)
        }
    }

    /// `delta` +1 = one row down (next result), -1 = one row up. No wrap-around.
    func moveSelection(_ delta: Int) {
        lastKeyboardAt = .now
        switch mode {
        case .search:
            guard !results.isEmpty else { return }
            let old = selected
            selected = min(max(selected + delta, 0), results.count - 1)
            if selected != old { announceSelection() }
        case .actions:
            let old = actionIndex
            actionIndex = min(max(actionIndex + delta, 0), actions.count - 1)
            if actionIndex != old { announceSelection() }
        }
    }

    /// Esc: leave actions, else clear the query, else tell the caller to close. True when the panel should close.
    func escape() -> Bool {
        if case .actions = mode { mode = .search; return false }
        if !query.isEmpty { query = ""; return false }
        return true
    }

    func toggleActions() {
        switch mode {
        case .search:
            guard let r = selectedResult else { return }
            actionIndex = 0
            mode = .actions(r)
        case .actions: mode = .search
        }
        switch mode {
        case .actions: PanelAnnouncer.announce(String(localized: "Actions"), priority: .medium)
        case .search: announceSelection()
        }
    }

    // MARK: pointer (positions are in the view's top-left "panelRoot" space)

    /// Row under `p`, by arithmetic on the fixed row pitch and the live scroll offset (no per-row geometry to go
    /// stale after filtering, scrolling or lazy row reuse).
    private func rowID(at p: CGPoint) -> String? {
        guard listFrame.contains(p) else { return nil }
        let y = p.y - listFrame.minY + scrollOffset - listTopInset
        guard y >= 0 else { return nil }
        let idx = Int(y / rowPitch)
        switch mode {
        case .search: return results.indices.contains(idx) ? results[idx].id : nil
        case .actions: return actions.indices.contains(idx) ? "action.\(idx)" : nil
        }
    }

    private func pill(at p: CGPoint) -> PillID? {
        selectedResult == nil ? nil : pillFrames.first(where: { $0.value.contains(p) })?.key
    }

    func hover(at p: CGPoint) {
        guard isUnlocked else { return }
        let valueHit = selectedResult == nil ? nil : valueFrames.first(where: { $0.value.contains(p) })?.key
        if hoveredValue != valueHit { hoveredValue = valueHit; if let v = valueHit { hoverStats["value.\(v.rawValue)", default: 0] += 1 } }
        let pillHit = pill(at: p)
        if hoveredPill != pillHit { hoveredPill = pillHit; Log.panel.notice("pointer hover pill \(pillHit?.rawValue ?? "none", privacy: .public)") }
        guard let id = rowID(at: p) else { return }
        if id.hasPrefix("action.") {
            if let i = Int(id.dropFirst(7)), i != actionIndex { pointerDriven = true; actionIndex = i }
        } else if let i = results.firstIndex(where: { $0.id == id }), i != selected {
            pointerDriven = true
            selected = i
            hoverStats["row\(i)", default: 0] += 1
        }
    }

    /// Click: a pill performs its action, a row selects and performs the default action (like Enter).
    /// Returns true when the click was consumed.
    func click(at p: CGPoint) -> Bool {
        guard isUnlocked else { return false }
        if selectedResult != nil, let v = valueFrames.first(where: { $0.value.contains(p) })?.key {
            Log.panel.notice("click value \(v.rawValue, privacy: .public)")
            activateValue(v)
            return true
        }
        if let pl = pill(at: p) { Log.panel.notice("click pill \(pl.rawValue, privacy: .public)"); perform(pill: pl); return true }
        guard let id = rowID(at: p) else { return false }
        pointerDriven = true
        if id.hasPrefix("action.") {
            // The ⌘K actions menu: a click runs the action.
            if let i = Int(id.dropFirst(7)) { actionIndex = i }
            activate(.plain)
        } else if let i = results.firstIndex(where: { $0.id == id }) {
            // A list row only SELECTS (the detail pane shows it): no copy, no fill, no close.
            selected = i
            Log.panel.notice("click row selected=\(self.selected)")
        } else { return false }
        return true
    }

    // MARK: actions

    func perform(pill: PillID) {
        guard let r = selectedResult else { return }
        switch pill {
        case .copy: pillTriggered = true; runCopy?(.password, r)
        case .fill: runFill?(.auto, r)
        case .userTabPassword: runFill?(.userTabPassword, r)
        }
    }

    // MARK: Values card (click a row to copy; password and OTP need a fresh biometric check, SPEC.md §4)

    /// What the row shows when idle. Passwords and unrevealed OTPs are NEVER rendered: masked dots only.
    func displayValue(_ row: ValueRowID, for item: VaultSearchResult) -> String {
        switch row {
        case .username: item.username.isEmpty ? Self.none : item.username
        case .website: item.domain.isEmpty ? Self.none : item.domain
        case .password:
            if let p = plainPassword, p.itemID == item.id { p.value } else { "••••••••" }
        case .otp: revealedOTP?.itemID == item.id ? (revealedOTP?.code ?? "••••••") : "••••••"
        }
    }

    private static let none = "—"

    func isOTPRevealed(for item: VaultSearchResult) -> Bool { revealedOTP?.itemID == item.id }
    func otpPeriod(for item: VaultSearchResult) -> Int { secrets.totpPeriod(for: item.id) }

    func activateValue(_ row: ValueRowID) {
        guard let item = selectedResult else { return }
        Task { await performValue(row, item) }
    }

    private func performValue(_ row: ValueRowID, _ item: VaultSearchResult) async {
        do {
            switch row {
            case .username:
                copy(try await secrets.secret(.username, for: item.id), row: row, item: item)
            case .website:
                guard let url = secrets.url(for: item.id) else { return }
                copy(url.absoluteString, row: row, item: item)
            case .password:
                if SecuritySettings.requireTouchID { try await BiometricGate.authenticate(reason: String(localized: "Copy password")) }
                copy(try await secrets.secret(.password, for: item.id), row: row, item: item)
            case .otp:
                if isOTPRevealed(for: item) {
                    if SecuritySettings.requireTouchID { try await BiometricGate.authenticate(reason: String(localized: "Copy one-time code")) }
                    copy(try await secrets.secret(.totp, for: item.id), row: row, item: item)
                } else {
                    try await BiometricGate.authenticate(reason: String(localized: "Reveal one-time code"))
                    let code = try await secrets.secret(.totp, for: item.id)
                    guard selectedResult?.id == item.id else { return }
                    revealOTP(code, item: item, window: Self.revealWindow)
                }
            }
        } catch {
            flash(row, error.localizedDescription, isError: true, duration: .seconds(2))
        }
    }

    private func copy(_ value: String, row: ValueRowID, item: VaultSearchResult) {
        SecureClipboard.shared.copySecret(value)
        source.recordUse(id: item.id)
        flash(row, Self.copiedText, isError: false, duration: Self.copiedFlash)  // a click on a Values row never closes the panel
    }

    static let closeAfterCopyKey = "panel.closeAfterCopy"
    /// Setting "Close after copying with a shortcut" (default on). Clicks on Values rows and pills never close the
    /// panel, so several values can be copied in a row by clicking.
    static var closeAfterCopy: Bool {
        UserDefaults.standard.object(forKey: closeAfterCopyKey) as? Bool ?? true
    }

    /// Confirmation for copies started by a key or a pill: the matching Values row (and the Copy pill, if it was the
    /// trigger) shows "✓ Copied" in place of its value, then the panel closes if the setting says so.
    func flashCopied(_ kind: SecretKind, viaPill: Bool) {
        let row: ValueRowID = switch kind { case .password: .password; case .username: .username; case .totp: .otp }
        flash(row, Self.copiedText, isError: false, duration: Self.copiedFlash)
        if viaPill {
            pillFlash = .copy
            Task { [weak self] in
                try? await Task.sleep(for: Self.copiedFlash)
                self?.pillFlash = nil
            }
        }
        if !viaPill, Self.closeAfterCopy { runCloseAfterCopy?() }  // shortcut-triggered copies close the panel
    }

    func flashFailure(_ kind: SecretKind, _ message: String) {
        let row: ValueRowID = switch kind { case .password: .password; case .username: .username; case .totp: .otp }
        flash(row, message, isError: true, duration: .seconds(2))
    }

    private func flash(_ row: ValueRowID, _ text: String, isError: Bool, duration: Duration) {
        flashes[row] = Flash(text: text, isError: isError)
        // The visual flash is a few hundred ms and the panel may close right after: say it, with what was copied.
        PanelAnnouncer.announce(isError ? text : String(localized: "\(row.spokenLabel) copied"), priority: .high)
        flashTasks[row]?.cancel()
        flashTasks[row] = Task { [weak self] in
            try? await Task.sleep(for: duration)
            guard !Task.isCancelled else { return }
            self?.flashes[row] = nil
        }
    }

    /// Shows the live code with its countdown; refreshes at each period boundary without asking again (the reveal
    /// was authenticated) and masks again after `revealWindow`, on selection change, query change or close.
    private func revealOTP(_ code: String, item: VaultSearchResult, window: Duration?) {
        let period = secrets.totpPeriod(for: item.id)
        revealedOTP = RevealedOTP(itemID: item.id, code: code, period: period)
        revealTask?.cancel()
        revealTask = Task { [weak self] in
            let deadline = window.map { ContinuousClock.now + $0 }
            while !Task.isCancelled, deadline.map({ ContinuousClock.now < $0 }) ?? true {
                let now = Date().timeIntervalSince1970
                let wait = Double(period) - now.truncatingRemainder(dividingBy: Double(period)) + 0.05
                try? await Task.sleep(for: .seconds(min(wait, 5)))
                guard !Task.isCancelled, let self, let cur = self.revealedOTP, cur.itemID == item.id else { return }
                if let fresh = try? await self.secrets.secret(.totp, for: item.id), fresh != cur.code {
                    self.revealedOTP = RevealedOTP(itemID: item.id, code: fresh, period: period)
                }
            }
            self?.maskOTP()
        }
    }

    /// Relaxed mode: when an item is selected, show its password and live OTP right away (vault is unlocked).
    /// Strict mode (`SecuritySettings.requireTouchID`): nothing is loaded; values stay masked until a fresh check.
    private func prepareValues() {
        maskOTP()
        valuesTask?.cancel()
        valuesTask = nil
        guard !SecuritySettings.requireTouchID, source.isUnlocked, let item = selectedResult else { return }
        let id = item.id
        valuesTask = Task { [weak self] in
            guard let self else { return }
            if let pw = try? await secrets.secret(.password, for: id), !Task.isCancelled, selectedResult?.id == id {
                plainPassword = (id, pw)
            }
            if let code = try? await secrets.secret(.totp, for: id), !Task.isCancelled, selectedResult?.id == id {
                revealOTP(code, item: item, window: nil)
            }
        }
    }

    func maskOTP() {
        revealTask?.cancel()
        revealTask = nil
        if revealedOTP != nil { revealedOTP = nil }
        if plainPassword != nil { plainPassword = nil }
    }

    /// ↩ copy password · ⇧↩ copy username · ⌘↩ copy OTP · ⌥↩ fill focused field · ⌘⌥↩ fill username, Tab, password.
    /// In the actions menu, ↩ runs the highlighted action.
    func activate(_ key: ActivationKey) {
        if !source.isUnlocked { runUnlock?(); return }
        switch mode {
        case .actions(let item):
            if key == .plain { perform(actions[actionIndex], on: item) }
        case .search:
            guard let r = selectedResult else { return }
            switch key {
            case .plain: runCopy?(.password, r)
            case .shift: runCopy?(.username, r)
            case .command: runCopy?(.totp, r)
            case .option: runFill?(.auto, r)
            case .commandOption: runFill?(.userTabPassword, r)
            }
        }
    }

    func perform(_ action: PanelAction, on item: VaultSearchResult) {
        switch action {
        case .fill: runFill?(.auto, item)
        case .fillUserTabPassword: runFill?(.userTabPassword, item)
        case .fillUsername: runFill?(.explicit(.username), item)
        case .fillPassword: runFill?(.explicit(.password), item)
        case .fillTOTP: runFill?(.explicit(.totp), item)
        case .copyUsername: runCopy?(.username, item)
        case .copyPassword: runCopy?(.password, item)
        case .copyTOTP: runCopy?(.totp, item)
        case .openURL: runOpenURL?(item)
        }
    }

    enum ActivationKey { case plain, shift, command, option, commandOption }
}
