import AppKit
import SwiftUI
import UniformTypeIdentifiers
import BiselCore

/// First run on this Mac, as a short route (Figma "Bisel", node 8:2): welcome → the recovery phrase (Download, Continue) →
/// import → done. Nothing to type: the Mac's name is the Mac's own and the server is always box.bisel.app.
/// "I already have a box" is the one detour: the 24 words, nothing else.
struct SetupView: View {
    let service: VaultService
    private let theme = Theme.biselDark   // onboarding is always the black frame

    enum Step { case welcome, recover }
    @State private var step: Step = SetupView.initialStep
    @State private var phrase = ""
    @State private var error: String?

    private static var initialStep: Step {
        #if DEBUG
        if ProcessInfo.processInfo.environment["BISEL_DEV_STEP"] == "recover" { return .recover }   // screenshots of each step
        #endif
        return .welcome
    }

    private var deviceName: String { Host.current().localizedName ?? "Mac" }

    var body: some View {
        OnboardingFrame(progress: step == .welcome ? 0.2 : 0.5, title: title, message: message) {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                switch step {
                case .welcome:
                    VStack(alignment: .leading, spacing: theme.spacing.l) {
                        OnboardingRow(icon: "IconKeyboardDown", text: "Start by using cmd + shift + space")
                        OnboardingRow(icon: "IconKeyhole", text: "Autofills natively in Safari or in Chromium via extensions")
                        OnboardingRow(icon: "IconCloudSync2", text: "Syncs directly iPhones and other Macs")
                    }
                    .padding(theme.spacing.l)
                case .recover:
                    VStack(alignment: .leading, spacing: theme.spacing.s) {
                        Caption("Recovery phrase (24 words)")
                        SecureField("", text: $phrase).onboardingField(theme, placeholder: "word1 word2 word3 …", text: phrase)
                            .accessibilityIdentifier("setup-phrase")
                    }
                }
                ErrorLine(text: error)
            }
        } actions: {
            switch step {
            case .welcome:
                Button(action: create) {
                    if service.isBusy { ProgressView().controlSize(.small) } else { HStack(spacing: 8) { PillGlyph(); Text("Create a box") } }
                }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(service.isBusy).accessibilityIdentifier("setup-go")
                Button("I already have one") { error = nil; step = .recover }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-recover")
            case .recover:
                Button("Back") { error = nil; step = .welcome }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-back")
                Spacer(minLength: 0)
                Button(action: recover) {
                    if service.isBusy { ProgressView().controlSize(.small) } else { Text("Connect") }
                }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(service.isBusy || phrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityIdentifier("setup-recover")
            }
        }
    }

    private var title: String { step == .welcome ? "Welcome to Bisel" : "Use your box" }

    private var message: String {
        step == .welcome
            ? "Bisel is the password manager we meant to be easy to reach while staying amazingly secure, working fully on a command menu taking less time to reach your info."
            : "Type or paste your 24-word recovery phrase and this Mac joins your box."
    }

    private func create() {
        error = nil
        let name = deviceName
        Task {
            do { try await service.bootstrapLocal(deviceName: name) } catch { self.error = describe(error) }
        }
    }

    private func recover() {
        error = nil
        let (url, bad) = ServerURLCheck.parse(BiselEnvironment.defaultServer)
        guard let url else { error = bad; return }
        let words = phrase, name = deviceName
        Task {
            do { try await service.recover(server: url, phrase: words, deviceName: name); phrase = "" }
            catch { self.error = describe(error) }
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
    @State private var saved: String?

    var body: some View {
        OnboardingFrame(progress: title == "Your recovery phrase" ? 0.6 : nil, title: title,
                        message: "These 24 words are the only way back into your box if you lose every device. Keep them somewhere safe, we show them once and never keep a copy.") {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: theme.spacing.s), count: 4), alignment: .leading, spacing: theme.spacing.s) {
                    ForEach(Array(phrase.words.enumerated()), id: \.offset) { i, w in
                        HStack(spacing: theme.spacing.s) {
                            Text("\(i + 1)").font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.tertiaryText.color)
                                .frame(width: 20, alignment: .trailing)
                            Text(w).font(theme.font(theme.fonts.value, weight: .medium)).textSelection(.disabled)
                                .accessibilityIdentifier("phrase-word-\(i + 1)")
                        }
                        .padding(.vertical, theme.spacing.s).padding(.horizontal, theme.spacing.s)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: theme.radii.field, style: .continuous).fill(theme.colors.field.color))
                    }
                }
                if let saved { Caption("Saved as \(saved)") }
            }
        } actions: {
            Button("Download", action: download)
                .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("phrase-download")
            Spacer(minLength: 0)
            Button("Continue", action: onDone)
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("phrase-continue")
        }
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
