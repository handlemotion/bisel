import AppKit
import Observation
import BiselCore

enum PanelAction: String, CaseIterable, Identifiable {
    case copyPassword, copyUsername, copyTOTP, fill, fillUserTabPassword, fillUsername, fillPassword, fillTOTP, openURL, moveToTrash

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
        case .moveToTrash: String(localized: "Move to Trash")
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

    /// The actions that can work for this item: no one-time code, no OTP actions; no password, no password actions; and so on.
    static func available(for item: VaultSearchResult) -> [PanelAction] {
        allCases.filter { a in
            switch a {
            case .copyTOTP, .fillTOTP: item.hasTOTP
            case .copyPassword, .fillPassword, .fillUserTabPassword: item.hasPassword
            case .copyUsername, .fillUsername: !item.username.isEmpty
            case .openURL: !item.domain.isEmpty
            case .fill, .moveToTrash: true
            }
        }
    }

    var symbol: String {
        switch self {
        case .copyPassword, .copyUsername, .copyTOTP: "doc.on.doc"
        case .fill, .fillUserTabPassword, .fillUsername, .fillPassword, .fillTOTP: "keyboard"
        case .openURL: "safari"
        case .moveToTrash: "trash"
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

    @ObservationIgnored let source: VaultSearchSource
    @ObservationIgnored let secrets: VaultSecretProvider
    /// Add / edit / delete / generate, see ACTIONS.md.
    @ObservationIgnored let items: PanelItemActions
    @ObservationIgnored var runFill: ((FillPlan, VaultSearchResult) -> Void)?
    @ObservationIgnored var runCopy: ((SecretKind, VaultSearchResult) -> Void)?
    @ObservationIgnored var runOpenURL: ((VaultSearchResult) -> Void)?
    @ObservationIgnored var runUnlock: (() -> Void)?
    /// ⌘, and the empty box's Return: settings, on the given page.
    @ObservationIgnored var runOpenSettings: ((SettingsPage) -> Void)?
    @ObservationIgnored var runClose: (() -> Void)?

    var query = "" {
        didSet {
            guard query != oldValue else { return }
            leaveNewLogin()   // typing a search is looking for something else: Return and the arrows are the list's again
            refresh()
        }
    }
    private(set) var results: [VaultSearchResult] = []
    /// 0 = best match (first A to Z with no query), at the top of the list.
    var selected = 0 { didSet { if selected != oldValue { prepareValues() } } }
    var mode: Mode = .search
    /// The unsaved new login. Clicking away or searching leaves the form and takes its row out of the list, as nothing was
    /// created, but what was typed waits here: + and ⌘N bring it back until Cancel or the panel closes.
    private(set) var newLogin: ItemEditorModel?
    /// The form is up: in place of the detail pane, with its row on top of the list, and it takes the keys.
    private(set) var newLoginSelected = false
    var isEditingNew: Bool { newLogin != nil && newLoginSelected }
    @ObservationIgnored private var untouchedDraft: ItemDraft?
    /// The login being made sits above the results, as the list's first row.
    var leadingRows: Int { isEditingNew ? 1 : 0 }
    /// A list row under the pointer while the form is up: there, hovering shows a row but does not select it.
    var hoveredRow: String?
    /// The form input a click landed on, for the form to focus: a whole Values row counts, not just its text.
    var formFocus: String?
    /// Leaving the form takes a row out of the list, so the rows move under a still pointer. Where the click was: hovering
    /// does not select until the pointer really moves, or the row just clicked would lose to the one that slid under it.
    @ObservationIgnored private var hoverHold: CGPoint?
    private static let hoverHoldDistance: CGFloat = 12
    var actionIndex = 0
    var hoveredPill: PillID?
    var hoveredValue: ValueRowID?
    var hoveredNewLogin = false
    enum FormButton: Hashable { case cancel, save, reveal, generate }
    var hoveredFormButton: FormButton?
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
    @ObservationIgnored var newLoginFrame: CGRect = .zero
    @ObservationIgnored var formButtonFrames: [FormButton: CGRect] = [:]
    /// Where the pointer is an I-beam: the search field and the form's inputs.
    @ObservationIgnored var textFrames: [String: CGRect] = [:]
    @ObservationIgnored var listFrame: CGRect = .zero
    /// Scroll offset of the list, kept current by the view.
    @ObservationIgnored var scrollOffset: CGFloat = 0
    @ObservationIgnored var lastKeyboardAt: ContinuousClock.Instant = .now

    var isUnlocked: Bool { source.isUnlocked }
    /// Unlocked, loaded, and nothing in it: the panel shows the import state instead of an empty list.
    var boxIsEmpty: Bool { source.isUnlocked && source.isEmpty }
    /// The + in the search bar and ⌘N. The dev fixture has no vault to write to.
    var canCreate: Bool { source.isUnlocked && items.isAvailable }
    var actions: [PanelAction] {
        if case .actions(let item) = mode { return availableActions(for: item) }
        return PanelAction.allCases
    }

    /// `PanelAction.available`, less what this source cannot do (the dev fixture has no trash).
    func availableActions(for item: VaultSearchResult) -> [PanelAction] {
        PanelAction.available(for: item).filter { $0 != .moveToTrash || items.isAvailable }
    }

    var selectedResult: VaultSearchResult? { results.indices.contains(selected) ? results[selected] : nil }

    init(source: VaultSearchSource, secrets: VaultSecretProvider) {
        self.source = source
        self.secrets = secrets
        items = PanelItemActions(source as? VaultItemActions)
        items.onChange = { [weak self] in self?.refresh() }
    }

    /// Full reset, run on every show AND every hide: opens as the full A to Z list with the first item selected,
    /// empty query, no stale state.
    func reset(targetName: String?) {
        self.targetName = targetName
        mode = .search
        newLogin = nil
        newLoginSelected = false
        hoveredRow = nil
        hoverHold = nil
        notice = nil
        actionIndex = 0
        hoveredPill = nil
        hoveredValue = nil
        hoveredNewLogin = false
        hoveredFormButton = nil
        prepareValues()
        flashTasks.values.forEach { $0.cancel() }
        flashTasks = [:]
        flashes = [:]
        if query.isEmpty { refresh() } else { query = "" }
        focusToken += 1
    }

    /// `keepingSelection`: a background reload keeps the highlighted login where it is, if it is still in the results.
    func refresh(keepingSelection: Bool = false) {
        let t0 = ContinuousClock.now
        let keep = keepingSelection ? selectedResult?.id : nil
        results = source.search(query, limit: .max)   // the list is lazy: rows are only built as they scroll in
        selected = keep.flatMap { id in results.firstIndex { $0.id == id } } ?? 0
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

    /// Looked up once: every row on screen builds this text on every render, whether or not anything reads it.
    private static let positionFormat = String(localized: "%lld of %lld")

    /// What VoiceOver says for list row `index`: login, user and site, and the position (the list only holds the rows on
    /// screen, so the total would otherwise be unknown).
    func spokenDescription(ofResultAt index: Int) -> String {
        guard results.indices.contains(index) else { return "" }
        let r = results[index]
        let parts = [r.username, r.domain].filter { !$0.isEmpty }
        return (parts + [String(format: Self.positionFormat, index + 1, results.count)]).joined(separator: ", ")
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
        leaveNewLogin()
        pointerDriven = selected != index
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

    /// Esc: leave the New login form, else leave actions, else clear the query, else tell the caller to close. True when the panel should close.
    func escape() -> Bool {
        if isEditingNew { closeNewLogin(); return false }
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

    /// Row under `p`, from the frames the rows on screen report.
    private func rowID(at p: CGPoint) -> String? {
        guard listFrame.contains(p) else { return nil }
        let wantsAction = mode != .search
        return rowFrames.first { $0.key.hasPrefix("action.") == wantsAction && $0.value.contains(p) }?.key
    }

    /// Position in `results` of a list row's frame id ("row.12"), which counts rows from the top of the list.
    private func resultIndex(_ id: String) -> Int? {
        id.hasPrefix("row.") ? Int(id.dropFirst(4)).map { $0 - leadingRows }.flatMap { results.indices.contains($0) ? $0 : nil } : nil
    }

    private func pill(at p: CGPoint) -> PillID? {
        selectedResult == nil ? nil : pillFrames.first(where: { $0.value.contains(p) })?.key
    }

    func isOverText(_ p: CGPoint) -> Bool {
        textFrames.values.contains { $0.contains(p) } && !formButtonFrames.values.contains { $0.contains(p) }
    }

    func hover(at p: CGPoint) {
        guard isUnlocked else { return }
        let button = isEditingNew ? formButtonFrames.first { $0.value.contains(p) }?.key : nil
        if hoveredFormButton != button { hoveredFormButton = button }
        let row = isEditingNew ? rowID(at: p) : nil
        if hoveredRow != row { hoveredRow = row }
        guard !isEditingNew else { return }
        if let hold = hoverHold {
            guard hypot(p.x - hold.x, p.y - hold.y) > Self.hoverHoldDistance else { return }
            hoverHold = nil
        }
        let onNewLogin = newLoginFrame.contains(p)
        if hoveredNewLogin != onNewLogin { hoveredNewLogin = onNewLogin }
        let valueHit = selectedResult == nil ? nil : valueFrames.first(where: { $0.value.contains(p) })?.key
        if hoveredValue != valueHit { hoveredValue = valueHit; if let v = valueHit { hoverStats["value.\(v.rawValue)", default: 0] += 1 } }
        let pillHit = pill(at: p)
        if hoveredPill != pillHit { hoveredPill = pillHit; Log.panel.notice("pointer hover pill \(pillHit?.rawValue ?? "none", privacy: .public)") }
        guard let id = rowID(at: p) else { return }
        if id.hasPrefix("action.") {
            if let i = Int(id.dropFirst(7)), i != actionIndex { pointerDriven = true; actionIndex = i }
        } else if let i = resultIndex(id), i != selected {
            pointerDriven = true
            selected = i
            hoverStats["row\(i)", default: 0] += 1
        }
    }

    /// Click: a pill performs its action, a row selects and performs the default action (like Enter).
    /// Returns true when the click was consumed.
    func click(at p: CGPoint) -> Bool {
        guard isUnlocked else { return false }
        if isEditingNew { return clickInForm(at: p) }
        if selectedResult != nil, let v = valueFrames.first(where: { $0.value.contains(p) })?.key {
            Log.panel.debug("click value")
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
        } else if let i = resultIndex(id) {
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

    // MARK: new login

    /// The title starts from what was searched, and the password from the generator: Return alone can save it.
    /// With typing left from an earlier visit this goes back to it.
    func openNewLogin() {
        guard canCreate, !isEditingNew else { return }
        if newLogin == nil {
            guard let editor = items.newEditor() else { return }
            editor.draft.title = query.trimmingCharacters(in: .whitespacesAndNewlines)
            editor.generatePassword()
            untouchedDraft = editor.draft
            newLogin = editor
        }
        mode = .search
        hoveredPill = nil
        hoveredValue = nil
        hoveredNewLogin = false
        hoveredRow = nil
        newLoginSelected = true
        PanelAnnouncer.announce(String(localized: "New login"), priority: .medium)
    }

    /// The form goes and so does its row. A draft nobody typed in goes too, so the next + starts fresh.
    private func leaveNewLogin() {
        guard newLoginSelected else { return }
        newLoginSelected = false
        if newLogin?.draft == untouchedDraft { newLogin = nil }
        hoveredFormButton = nil
        hoveredRow = nil
        formFocus = nil
        focusToken += 1
    }

    /// Cancel and Esc: the draft is dropped, typed or not.
    func closeNewLogin() {
        leaveNewLogin()
        newLogin = nil
    }

    /// A list row selects, and leaves the form. In the form a click stays unconsumed, for the field or button under it;
    /// `formFocus` also focuses the input when it landed beside the text, where the field itself would not take it.
    private func clickInForm(at p: CGPoint) -> Bool {
        if let id = rowID(at: p) {
            guard let i = resultIndex(id) else { return false }
            hoverHold = p
            selectResult(at: i)
            return true
        }
        guard !formButtonFrames.values.contains(where: { $0.contains(p) }),
              let id = textFrames.first(where: { $0.value.contains(p) })?.key else { return false }
        if id == Self.searchField { focusToken += 1 } else { formFocus = id }
        return false
    }

    static let searchField = "search"

    /// Saved: back to the full list with the new login selected, so ↩ copies its password and ⌥↩ fills it.
    /// Anything else leaves the form up with `editor.state` saying why.
    func saveNewLogin() {
        guard let editor = newLogin else { return }
        Task {
            await editor.save()
            guard editor === newLogin, case .done(.saved(let item, _)) = editor.state else { return }
            closeNewLogin()
            query = ""
            selected = results.firstIndex { $0.id == item.id } ?? 0
            Toast.shared.show(String(localized: "Saved \(item.title)"))
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
        if isEditingNew { if key == .plain { saveNewLogin() }; return }
        if boxIsEmpty { if key == .plain { runOpenSettings?(.backup) }; return }   // Import lives on the Backup & Import page
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
        case .moveToTrash: moveToTrash(item)
        }
    }

    /// Asks for Touch ID, then the selection stays where it was: on the next item, not back at the top of the list.
    private func moveToTrash(_ item: VaultSearchResult) {
        let position = selected
        Task {
            switch await items.trash(item) {
            case .trashed:
                mode = .search
                selected = max(min(position, results.count - 1), 0)
                Toast.shared.show(String(localized: "Moved \(item.title) to Trash"))
            case .failed(let text): Toast.shared.show(text, isError: true)
            case .cancelled, .locked: break   // a locked box already shows its unlock state
            }
        }
    }

    enum ActivationKey { case plain, shift, command, option, commandOption }
}
