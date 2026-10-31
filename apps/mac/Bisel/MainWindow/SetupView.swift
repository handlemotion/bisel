import AppKit
import SwiftUI
import UniformTypeIdentifiers
import BiselCore

/// First run on this Mac, as a short route (Figma "Bisel", node 8:2): welcome → the recovery phrase (Download, Continue) →
/// import → done. Nothing to type: the Mac's name is the Mac's own and the box goes to this Apple Account's iCloud
/// (`BoxSetup`, BiselCore/SETUP.md). The server is not part of first run: it is opt-in, from Settings.
/// "I already have a box" is the one detour: the 24 words. When iCloud already holds the box, Create offers only adding this
/// Mac to it (pairing) or restoring it; when iCloud cannot take a new box, "Keep it on this Mac only", never chosen for the person.
struct SetupView: View {
    let service: VaultService
    private let theme = Theme.biselDark   // onboarding is always the black frame

    enum Step { case welcome, recover, pair }
    /// What the welcome screen offers after Create was refused.
    enum Offer: Equatable {
        /// iCloud cannot take the box for a reason the person can't fix from here: "Keep it on this Mac only" next to Create.
        case thisMacOnly
        /// This Apple Account's iCloud already holds a box: add this Mac to it, or restore it. Never a second box (v1).
        case existingBox
    }
    @State private var step: Step = SetupView.initialStep
    @State private var offer: Offer?
    @State private var words = Array(repeating: "", count: 24)
    /// The code the other device shows, typed while comparing codes.
    @State private var otherCode = ""
    @State private var error: String?
    @State private var working = false
    /// True for a moment while the screen fades out before the next step takes its place.
    @State private var leaving = false
    /// Waits for the screen before this one to fade out; once the set-up is on screen, steps swap on their own timing.
    @State private var lead = 0.2

    private static var initialStep: Step {
        #if DEBUG
        if ProcessInfo.processInfo.environment["BISEL_DEV_STEP"] == "recover" { return .recover }   // screenshots of each step
        #endif
        return .welcome
    }

    private var deviceName: String { Host.current().localizedName ?? "Mac" }

    /// The step on screen. A pairing in progress (also one this Mac comes back to after a relaunch) always shows its step.
    private var current: Step {
        switch service.setupState {
        case .pairing, .compareCode, .working(.finishingPairing): return .pair
        default: return step == .pair ? .welcome : step
        }
    }

    /// Polls for the other device's approval while the 8 words are up.
    private var waitingForApproval: Bool { if case .pairing = service.setupState { true } else { false } }

    var body: some View {
        frame
            .environment(\.cascadeLead, lead)
            .task(id: waitingForApproval) { if waitingForApproval { await pollApproval() } }
            .task {
                #if DEBUG
                switch ProcessInfo.processInfo.environment["BISEL_DEV_STEP"] {   // screenshots of the refused-Create choices
                case "mac-only": offer = .thisMacOnly; error = describe(SetupError.iCloud(.notSignedIn))
                case "has-box": offer = .existingBox; error = describe(SetupError.iCloudHasBox([]))
                default: break
                }
                #endif
                try? await Task.sleep(for: .seconds(1))
                lead = 0
                #if DEBUG
                if ProcessInfo.processInfo.environment["BISEL_DEV_STEP_TOUR"] != nil {   // swaps steps on a timer so the transitions can be captured
                    try? await Task.sleep(for: .seconds(2)); go(.recover)
                    try? await Task.sleep(for: .seconds(3)); go(.welcome)
                    try? await Task.sleep(for: .seconds(3)); go(.recover)
                }
                #endif
            }
    }

    private var frame: some View {
        OnboardingFrame(progress: current == .welcome ? 0.2 : 0.5, title: title, message: message, centered: current != .welcome, dim: leaving) {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                switch current {
                case .welcome:
                    VStack(alignment: .leading, spacing: theme.spacing.l) {
                        OnboardingRow(icon: "IconKeyboardDown", text: "Start by using cmd + shift + space", delay: 0.12)
                        OnboardingRow(icon: "IconKeyhole", text: "Autofills natively in Safari or in Chromium via extensions", delay: 0.18)
                        OnboardingRow(icon: "IconCloudSync2", text: "Syncs directly iPhones and other Macs", delay: 0.24)
                    }
                    .padding(theme.spacing.l)
                case .recover:
                    PhraseInputGrid(words: $words)
                case .pair:
                    pairing
                }
                ErrorLine(text: error)
                if current == .welcome, offer == .thisMacOnly {
                    Text("This Mac will hold the only copy of your box. Export a backup once it's made; you can move it to iCloud later.")
                        .font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.warning.color)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("setup-mac-only-warning")
                }
            }
        } actions: {
            switch current {
            case .welcome where offer == .existingBox:
                Button(action: addThisMac) {
                    HStack(spacing: 8) { PillGlyph(); Text("Add this Mac") }
                }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(busy).accessibilityIdentifier("setup-add-mac")
                Button("Restore with the 24 words") { go(.recover) }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-recover")
            case .welcome:
                Button(action: create) {
                    HStack(spacing: 8) { PillGlyph(); Text("Create a box") }
                }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(busy).accessibilityIdentifier("setup-go")
                // UI: restoring a `.bisel-backup` file (`service.restore(backup:phrase:deviceName:)`, and `restoreOnThisMacOnly`
                // when iCloud can't take it) needs a screen Rodrigo designs (SETUP.md "Screens to design").
                Button("I already have one") { go(.recover) }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-recover")
                if offer == .thisMacOnly {
                    Button("Keep it on this Mac only", action: keepOnThisMac)
                        .buttonStyle(PillButtonStyle(primary: false)).disabled(busy).accessibilityIdentifier("setup-mac-only")
                }
            case .recover:
                Button("Back") { go(.welcome) }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-back")
                Button("Upload file", action: uploadPhrase)
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-upload")
                Spacer(minLength: 0)
                Button(action: recover) {
                    Text("Connect")
                }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(busy || words.contains(where: \.isEmpty))
                .accessibilityIdentifier("setup-recover")
            case .pair:
                Button("Cancel", action: cancelPairing)
                    .buttonStyle(PillButtonStyle(primary: false)).disabled(working).accessibilityIdentifier("pair-cancel")
                Spacer(minLength: 0)
                switch service.setupState {
                case .compareCode:
                    Button("Confirm", action: confirmCode)
                        .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                        .disabled(busy || otherCode.trimmingCharacters(in: .whitespaces).isEmpty)
                        .accessibilityIdentifier("pair-confirm")
                case .working(.finishingPairing):
                    // The approval is here and Touch ID was cancelled: opening the box asks once more.
                    Button { Task { await checkApproval() } } label: { Label("Unlock with Touch ID", systemImage: "touchid") }
                        .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                        .disabled(working).accessibilityIdentifier("pair-unlock")
                default:
                    EmptyView()
                }
            }
        }
    }

    /// The 8 words and the fingerprint while waiting for the other device; this Mac's code and a field for the other one's after.
    @ViewBuilder private var pairing: some View {
        switch service.setupState {
        case .pairing(let offer):
            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: 4), alignment: .leading, spacing: 6) {
                ForEach(Array(offer.secret.words.enumerated()), id: \.offset) { i, w in
                    PhraseCellChrome(number: i + 1) {
                        Text(w).font(theme.font(theme.fonts.value, weight: .medium)).textSelection(.disabled)
                            .accessibilityIdentifier("pair-word-\(i + 1)")
                    }
                }
            }
            Caption("Fingerprint \(offer.fingerprint)")
            Caption("Waiting for your other device…")
        case .compareCode(let mine):
            Caption("This Mac's code")
            Text(mine).font(theme.font(theme.fonts.detailTitle - 4, weight: .medium)).textSelection(.enabled)
                .accessibilityIdentifier("pair-my-code")
            TextField("", text: $otherCode)
                .onboardingField(theme, placeholder: "Code on your other device", text: otherCode)
                .onSubmit(confirmCode)
                .accessibilityIdentifier("pair-their-code")
        default:
            Caption("Approved. Unlock with Touch ID to open your box on this Mac.")
        }
    }

    private var busy: Bool { service.isBusy || working }

    private var title: String {
        switch current {
        case .welcome: "Welcome to Bisel"
        case .recover: "Use your box"
        case .pair: if case .compareCode = service.setupState { "Compare the codes" } else { "Add this Mac" }
        }
    }

    private var message: String {
        switch current {
        case .welcome:
            "Bisel is the password manager we meant to be easy to reach while staying amazingly secure, working fully on a command menu taking less time to reach your info."
        case .recover:
            "Paste your 24 words into any cell, or upload the file you saved."
        case .pair:
            if case .compareCode = service.setupState {
                "Type the code your other device shows. It has to match this Mac's code exactly."
            } else {
                "On a device that already has your box, approve this Mac with these 8 words. It shows the same fingerprint."
            }
        }
    }

    /// Fades the current step out, then swaps in the next one, whose texts and cells fade in one after another.
    private func go(_ next: Step) {
        error = nil
        withAnimation(.easeInOut(duration: 0.3)) { leaving = true }
        Task {
            try? await Task.sleep(for: .milliseconds(330))
            // Nothing is visible now: swap without animating, so old and new views never cross-fade or move.
            var t = Transaction(); t.disablesAnimations = true
            withTransaction(t) { step = next; leaving = false }
        }
    }

    private func create() {
        error = nil
        let name = deviceName
        Task {
            do {
                try await service.createBox(deviceName: name)
                offer = nil
            } catch SetupError.iCloudHasBox {
                // This Apple Account's iCloud already holds the box: join it or restore it. A second box is never offered (v1).
                offer = .existingBox
                self.error = describe(SetupError.iCloudHasBox([]))
            } catch SetupError.iCloud(let why) {
                // Reasons the person can't fix right now get "Keep it on this Mac only"; offline, full or busy iCloud: try again.
                offer = Self.thisMacOnlyHelps(why) ? .thisMacOnly : nil
                self.error = describe(SetupError.iCloud(why))
            } catch {
                self.error = describe(error)
            }
        }
    }

    private static func thisMacOnlyHelps(_ why: HomeUnavailable) -> Bool {
        switch why {
        case .restricted, .notSignedIn, .turnedOffForApp, .notInThisBuild: true
        case .offline, .quotaFull, .temporarilyUnavailable: false
        }
    }

    /// The person's explicit choice, after the warning line: the box is made on this Mac only (`putInICloud` can move it later).
    private func keepOnThisMac() {
        error = nil
        let name = deviceName
        Task {
            do { try await service.createBoxOnThisMacOnly(deviceName: name); offer = nil }
            catch { self.error = describe(error) }
        }
    }

    /// Asks to join the box in this Apple Account's iCloud; the other device approves with the 8 words.
    private func addThisMac() {
        error = nil; working = true
        let name = deviceName
        Task {
            defer { working = false }
            do {
                do { _ = try await service.startICloudEnrollment(deviceName: name) }
                catch SetupError.chooseBox(let boxes) where !boxes.isEmpty {
                    // One box per Apple Account (v1): an account still holding several joins the first; no chooser.
                    _ = try await service.startICloudEnrollment(deviceName: name, box: boxes[0])
                }
                otherCode = ""
                step = .pair   // already on screen: `current` follows the set-up state
            } catch { self.error = describe(error) }
        }
    }

    /// Every few seconds while the 8 words are up, until the other device approves (`.compareCode`, after Touch ID).
    private func pollApproval() async {
        while !Task.isCancelled, waitingForApproval {
            if await checkApproval() { return }
            try? await Task.sleep(for: .seconds(3))
        }
    }

    /// One look for the approval. True when there is nothing more to wait for (approved, Touch ID cancelled, or pairing ended).
    @discardableResult
    private func checkApproval() async -> Bool {
        working = true; defer { working = false }
        do {
            let approved = try await service.finishICloudEnrollment()
            if approved { error = nil }
            return approved
        } catch SetupError.cancelled {
            return true   // "Unlock with Touch ID" asks again
        } catch let e as SetupError where e == .approvalUnproven || e == .pairingExpired {
            // An alarm (something other than the person's device answered) or a stale request: stop, say so, start over.
            await endPairing(saying: e)
            return true
        } catch {
            self.error = describe(error)   // offline, iCloud busy: keep waiting
            return false
        }
    }

    private func confirmCode() {
        let code = otherCode.trimmingCharacters(in: .whitespaces)
        guard !code.isEmpty, case .compareCode = service.setupState else { return }
        error = nil; working = true
        Task {
            defer { working = false }
            do { try await service.confirmICloudEnrollment(code: code); otherCode = "" }
            catch SetupError.codeMismatch { await endPairing(saying: SetupError.codeMismatch) }   // the box locked itself here
            catch { self.error = describe(error) }
        }
    }

    private func cancelPairing() {
        Task { await endPairing(saying: nil) }
    }

    /// This Mac forgets its half-made keys; back to the choices, with the reason when there is one.
    private func endPairing(saying reason: Error?) async {
        try? await service.cancelICloudEnrollment()
        otherCode = ""
        step = .welcome
        error = reason.map(describe)
    }

    /// The 24 words open the box in this Apple Account's iCloud (`BoxSetup.restore`).
    private func recover() {
        error = nil
        let phrase = words.joined(separator: " "), name = deviceName
        Task {
            do { try await service.restore(phrase: phrase, deviceName: name); words = Array(repeating: "", count: 24) }
            catch { self.error = describe(error) }
        }
    }

    private func uploadPhrase() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.plainText]
        panel.begin { response in
            guard response == .OK, let url = panel.url, let text = try? String(contentsOf: url, encoding: .utf8) else { return }
            let parsed = RecoveryPhraseText.words(in: text)
            guard !parsed.isEmpty else { error = "No recovery words found in that file"; return }
            error = nil
            for i in 0..<24 { words[i] = i < parsed.count ? parsed[i] : "" }
        }
    }
}

/// The recovery phrase, once. Download saves it as a text file; Continue moves on.
struct PhraseGateView: View {
    let service: VaultService
    let phrase: RecoveryPhrase
    var title = "Your recovery phrase"
    var onDone: () -> Void
    private let theme = Theme.biselDark
    /// Decided once, when the screen appears: while it fades out after Back the box is already gone, and the buttons must not
    /// re-flow (the Save pill would slide left into Back's place).
    @State private var canGoBack: Bool
    @State private var saved: String?

    init(service: VaultService, phrase: RecoveryPhrase, title: String = "Your recovery phrase", onDone: @escaping () -> Void) {
        self.service = service; self.phrase = phrase; self.title = title; self.onDone = onDone
        _canGoBack = State(initialValue: service.freshBox)
    }
    @State private var copied = false

    var body: some View {
        OnboardingFrame(progress: title == "Your recovery phrase" ? 0.6 : nil, title: title,
                        message: "Your only way back in if you lose every device. Shown once, never kept.",
                        centered: true) {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 6), count: 4), alignment: .leading, spacing: 6) {
                    ForEach(Array(phrase.words.enumerated()), id: \.offset) { i, w in
                        PhraseCellChrome(number: i + 1) {
                            Text(w).font(theme.font(theme.fonts.value, weight: .medium)).textSelection(.disabled)
                                .accessibilityIdentifier("phrase-word-\(i + 1)")
                        }
                    }
                }
                if let saved { Caption("Saved as \(saved)") }
            }
        } actions: {
            if canGoBack {
                Button("Back") { Task { await service.discardNewBox() } }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("phrase-back")
            }
            Menu {
                Button("Copy", action: copy).accessibilityIdentifier("phrase-copy")
                Button("Download…", action: download).accessibilityIdentifier("phrase-download")
            } label: { Text(copied ? "Copied" : "Save") }
                .menuStyle(.button).menuIndicator(.hidden)
                .buttonStyle(PillButtonStyle(primary: false)).fixedSize()
                .accessibilityIdentifier("phrase-save")
            Spacer(minLength: 0)
            Button("Continue", action: onDone)
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("phrase-continue")
        }
    }

    /// The words on one line, so pasting them into the recovery cells spreads them. Concealed, this Mac only, cleared after 30 s.
    private func copy() {
        SecureClipboard.shared.copySecret(phrase.words.joined(separator: " "))
        copied = true
        Task { try? await Task.sleep(for: .seconds(2)); copied = false }
    }

    private func download() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Bisel recovery phrase.txt"
        panel.allowedContentTypes = [.plainText]
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            let lines = phrase.words.enumerated().map { "\($0.offset + 1). \($0.element)" }.joined(separator: "\n")
            let text = "Bisel recovery phrase\n\n\(lines)\n\nThese 24 words are the only way back into your box. Keep this file somewhere safe and offline.\n"
            do {
                try text.write(to: url, atomically: true, encoding: .utf8)
                saved = url.lastPathComponent
            } catch { saved = nil }
        }
    }
}

/// Last step: bring passwords over from another manager, or skip. Import also lives in the settings window.
struct OnboardingImportView: View {
    let service: VaultService
    var onFinish: () -> Void
    private let theme = Theme.biselDark
    @State private var picking = false
    @State private var fileName: String?
    @State private var outcome: ImportOutcome?
    @State private var error: String?
    @State private var done: String?
    @State private var working = false
    @State private var progress = 0

    var body: some View {
        OnboardingFrame(progress: 0.9, title: "Bring your passwords",
                        message: "Import a 1Password export (.1pux) or a CSV from Apple Passwords, Chrome and others. Everything is encrypted on this Mac first, and the export file stays on your disk, so delete it afterwards.") {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                if let fileName { Caption(DisplayText.clean(fileName)) }
                if let o = outcome {
                    Text("Found \(o.items.count) items, \(o.logins) logins and \(o.notes) notes")
                        .font(theme.font(theme.fonts.search)).foregroundStyle(theme.colors.secondaryText.color)
                        .accessibilityIdentifier("import-summary")
                }
                if let done { Text(done).font(theme.font(theme.fonts.search)).foregroundStyle(theme.colors.success.color).accessibilityIdentifier("import-done") }
                ErrorLine(text: error)
            }
        } actions: {
            if done == nil {
                Button("Choose file…") { picking = true }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("import-choose")
            }
            Spacer(minLength: 0)
            if let o = outcome, done == nil {
                Button(working ? "Importing \(progress)/\(o.items.count)" : "Import \(o.items.count) items") { run(o) }
                    .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                    .disabled(working || o.items.isEmpty).accessibilityIdentifier("import-run")
            } else {
                Button(done == nil ? "Skip for now" : "Done", action: onFinish)
                    .buttonStyle(PillButtonStyle(primary: done != nil)).keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("import-finish")
            }
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [UTType(filenameExtension: "1pux") ?? .zip, .commaSeparatedText, .plainText]) { r in
            if case .success(let url) = r { load(url) }
        }
    }

    private func load(_ url: URL) {
        error = nil; outcome = nil; fileName = url.lastPathComponent
        guard let format = ImportFormat(url: url) else { error = "Unsupported file type (use .1pux or .csv)"; return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do { outcome = try format.parse(url: url) } catch { self.error = error.localizedDescription }
    }

    private func run(_ o: ImportOutcome) {
        working = true; progress = 0
        Task {
            defer { working = false }
            do {
                try await service.saveMany(o.items) { progress = $0 }
                done = "Imported \(o.items.count) items."
                outcome = nil
            } catch { self.error = describe(error) }
        }
    }
}

struct LockedView: View {
    let service: VaultService
    private let theme = Theme.biselDark
    @State private var error: String?
    @State private var working = false

    var body: some View {
        OnboardingFrame(progress: nil, title: "Bisel is locked", message: "Use Touch ID to open your box.") {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                ErrorLine(text: error)
                SyncStatusView(service: service, compact: true)
            }
        } actions: {
            Button { unlock() } label: { Label("Unlock with Touch ID", systemImage: "touchid") }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(working).accessibilityIdentifier("unlock-button")
        }
    }

    private func unlock() {
        error = nil; working = true
        Task {
            defer { working = false }
            do { try await service.unlock() }
            catch KeyStoreError.userCancelled {}
            catch BiometricGate.Failure.denied {}
            catch { self.error = describe(error) }
        }
    }
}
