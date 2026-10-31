import AppKit
import SwiftUI
import UniformTypeIdentifiers
import BiselCore

/// First run on this Mac, as a short route (Figma "Bisel", node 8:2): welcome → the recovery phrase (Download, Continue) →
/// import → done. Nothing to type: the Mac's name is the Mac's own and the box goes to this Apple Account's iCloud
/// (`BoxSetup`, BiselCore/SETUP.md). The server is not part of first run: it is opt-in, from Settings.
/// "I already have a box" is the one detour: the 24 words, nothing else.
struct SetupView: View {
    let service: VaultService
    private let theme = Theme.biselDark   // onboarding is always the black frame

    enum Step { case welcome, recover }
    @State private var step: Step = SetupView.initialStep
    @State private var words = Array(repeating: "", count: 24)
    @State private var error: String?
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

    var body: some View {
        frame
            .environment(\.cascadeLead, lead)
            .task {
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
        OnboardingFrame(progress: step == .welcome ? 0.2 : 0.5, title: title, message: message, centered: step == .recover, dim: leaving) {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                switch step {
                case .welcome:
                    VStack(alignment: .leading, spacing: theme.spacing.l) {
                        OnboardingRow(icon: "IconKeyboardDown", text: "Start by using cmd + shift + space", delay: 0.12)
                        OnboardingRow(icon: "IconKeyhole", text: "Autofills natively in Safari or in Chromium via extensions", delay: 0.18)
                        OnboardingRow(icon: "IconCloudSync2", text: "Syncs directly iPhones and other Macs", delay: 0.24)
                    }
                    .padding(theme.spacing.l)
                case .recover:
                    PhraseInputGrid(words: $words)
                }
                ErrorLine(text: error)
            }
        } actions: {
            switch step {
            case .welcome:
                Button(action: create) {
                    HStack(spacing: 8) { PillGlyph(); Text("Create a box") }
                }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(service.isBusy).accessibilityIdentifier("setup-go")
                // UI: "I already have one" leads to the 24 words only. Adding this Mac to the box in iCloud with the 8 words or a QR
                // code (D6; `service.startICloudEnrollment` → `finishICloudEnrollment` → `.compareCode` → `confirmICloudEnrollment`)
                // and restoring a `.bisel-backup` file (`service.restore(backup:phrase:deviceName:)`) need screens Rodrigo designs
                // (SETUP.md "Screens to design").
                Button("I already have one") { go(.recover) }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-recover")
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
                .disabled(service.isBusy || words.contains(where: \.isEmpty))
                .accessibilityIdentifier("setup-recover")
            }
        }
    }

    private var title: String { step == .welcome ? "Welcome to Bisel" : "Use your box" }

    private var message: String {
        step == .welcome
            ? "Bisel is the password manager we meant to be easy to reach while staying amazingly secure, working fully on a command menu taking less time to reach your info."
            : "Paste your 24 words into any cell, or upload the file you saved."
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
            // UI: `SetupError.iCloudHasBox`: this Apple Account's iCloud already holds a box. Rodrigo's "a box already exists in
            // iCloud" choice goes here: add this Mac to it (`service.startICloudEnrollment`), restore it with the 24 words (the
            // `.recover` step), or, deliberately, a second box (`service.createBoxAnyway`). Until then: its message.
            // UI: `SetupError.iCloud(reason)`: iCloud cannot take the box (signed out, off for Bisel, restricted, offline, full,
            // unavailable). "Keep it on this Mac only" (`service.createBoxOnThisMacOnly`) needs a control Rodrigo designs.
            do { try await service.createBox(deviceName: name) } catch { self.error = describe(error) }
        }
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
                if let fileName { Caption(fileName) }
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
