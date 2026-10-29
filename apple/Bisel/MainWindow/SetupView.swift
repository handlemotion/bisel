import SwiftUI
import UniformTypeIdentifiers
import BiselCore

/// First run on this Mac, as a short route (Figma "Bisel", node 8:2):
/// welcome → use locally (name this Mac) | connect to a box (server + recovery phrase) | restore a backup file,
/// then the recovery phrase for a new box (PhraseGateView). The progress bar follows the route.
struct SetupView: View {
    let service: VaultService
    @Environment(\.theme) private var theme

    enum Step { case welcome, local, connect, restore }
    @State private var step: Step = SetupView.initialStep
    @State private var server = ""   // never persisted outside the vault store: the hostname is a secret (SPEC §6, review M17)
    @State private var token = ""
    @State private var deviceName = Host.current().localizedName ?? "Mac"
    @State private var phrase = ""
    @State private var backupURL: URL?
    @State private var picking = false
    @State private var error: String?
    @State private var debugPath = ""

    private static var initialStep: Step {
        #if DEBUG
        switch ProcessInfo.processInfo.environment["BISEL_DEV_STEP"] {   // screenshots of each route step
        case "local": return .local
        case "connect": return .connect
        case "restore": return .restore
        default: break
        }
        #endif
        return .welcome
    }

    var body: some View {
        OnboardingFrame(progress: progress, title: title, message: message) {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                switch step {
                case .welcome: EmptyView()
                case .local:
                    field("This Mac's name", "MacBook", $deviceName, id: "setup-device")
                case .connect:
                    field("Server", "https://box.example.com", $server, id: "setup-server")
                    phraseEditor
                    field("This Mac's name", "MacBook", $deviceName, id: "setup-device")
                case .restore:
                    HStack {
                        Button("Choose backup file…") { picking = true }
                            .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-pick-backup")
                        Text(backupURL?.lastPathComponent ?? "None selected")
                            .font(theme.font(theme.fonts.detail)).foregroundStyle(theme.colors.secondaryText.color).lineLimit(1)
                    }
                    #if DEBUG
                    TextField("", text: $debugPath, prompt: Text("debug: backup file path")).onboardingField(theme)
                        .accessibilityIdentifier("setup-debug-path").onSubmit { backupURL = URL(fileURLWithPath: debugPath) }
                    #endif
                    field("Server", "https://box.example.com", $server, id: "setup-server")
                    secureField("Bootstrap token", "Set with wrangler secret BOOTSTRAP_TOKEN", $token, id: "setup-token")
                    phraseEditor
                    field("This Mac's name", "MacBook", $deviceName, id: "setup-device")
                }
                ErrorLine(text: error)
                if step == .local {
                    Text(footer).font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.tertiaryText.color)
                }
            }
        } actions: {
            switch step {
            case .welcome:
                Button { go(.connect) } label: { Label("Connect to Box", systemImage: "shippingbox") }
                    .buttonStyle(PillButtonStyle()).accessibilityIdentifier("setup-mode-recover")
                Button("Use locally") { go(.local) }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-create")
            case .local, .connect, .restore:
                Button(action: submit) {
                    if service.isBusy { ProgressView().controlSize(.small) } else { Text(actionTitle) }
                }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(service.isBusy || !ready).accessibilityIdentifier("setup-go")
                Button("Back") { go(.welcome) }
                    .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-back")
                if step == .connect {
                    Button("Restore backup") { go(.restore) }
                        .buttonStyle(PillButtonStyle(primary: false)).accessibilityIdentifier("setup-mode-restore")
                }
            }
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [UTType(filenameExtension: "bisel-backup") ?? .json, .json]) { r in
            if case .success(let u) = r { backupURL = u }
        }
    }

    // MARK: copy and route

    private var progress: Double { step == .welcome ? 0.2 : 0.5 }

    private var title: String {
        switch step {
        case .welcome: "Welcome to Bisel"
        case .local: "Use this Mac"
        case .connect: "Connect to a box"
        case .restore: "Restore a backup"
        }
    }

    private var message: String {
        switch step {
        case .welcome: "Bisel is the password manager you don’t wait for. You set up a box once, and open it with your biometrics on your Apple device."
        case .local: "Your keys are made on this Mac. Nothing leaves it until you connect a server."
        case .connect: "Enter your box’s server and its 24-word recovery phrase to bring it to this Mac."
        case .restore: "Re-create the box on a fresh server from a .bisel-backup file and its recovery phrase."
        }
    }

    private var actionTitle: String {
        switch step { case .local: "Create box"; case .connect: "Connect"; case .restore: "Restore"; case .welcome: "" }
    }

    private var footer: String {
        BiselEnvironment.usesSoftwareKeys ? "Debug build: device keys are kept in a plain file, not the Secure Enclave." : "Device keys are created in the Secure Enclave and need Touch ID."
    }

    private var ready: Bool {
        guard !deviceName.isEmpty else { return false }
        switch step {
        case .welcome: return false
        case .local: return true
        case .connect: return !server.isEmpty && !phraseText.isEmpty
        case .restore: return !server.isEmpty && !token.isEmpty && !phraseText.isEmpty && backupURL != nil
        }
    }

    private var phraseText: String { phrase.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func go(_ to: Step) { error = nil; step = to }

    // MARK: fields

    /// Masked: the phrase is a secret, so it is censored on screen (and in screenshots) while typed or pasted.
    private var phraseEditor: some View {
        secureField("Recovery phrase (24 words)", "word1 word2 word3 …", $phrase, id: "setup-phrase")
    }

    private func field(_ title: String, _ prompt: String, _ text: Binding<String>, id: String) -> some View {
        VStack(alignment: .leading, spacing: theme.spacing.xs) {
            Caption(title)
            TextField("", text: text, prompt: Text(prompt)).onboardingField(theme).accessibilityIdentifier(id)
        }
    }

    private func secureField(_ title: String, _ prompt: String, _ text: Binding<String>, id: String) -> some View {
        VStack(alignment: .leading, spacing: theme.spacing.xs) {
            Caption(title)
            SecureField("", text: text, prompt: Text(prompt)).onboardingField(theme).accessibilityIdentifier(id)
        }
    }

    // MARK: submit

    private func submit() {
        error = nil
        let name = deviceName.trimmingCharacters(in: .whitespaces)
        if step == .local {
            Task {
                do { try await service.bootstrapLocal(deviceName: name) } catch { self.error = describe(error) }
            }
            return
        }
        let (url, bad) = ServerURLCheck.parse(server)
        guard let url else { error = bad; return }
        let tok = token.trimmingCharacters(in: .whitespacesAndNewlines)
        let words = phrase
        let file = backupURL
        let route = step
        Task {
            do {
                switch route {
                case .welcome, .local: break
                case .connect: try await service.recover(server: url, phrase: words, deviceName: name)
                case .restore:
                    guard let file else { return }
                    let scoped = file.startAccessingSecurityScopedResource()
                    defer { if scoped { file.stopAccessingSecurityScopedResource() } }
                    try await service.importBackup(from: file, phrase: words, server: url, token: tok, deviceName: name)
                }
                phrase = ""; token = ""
            } catch {
                self.error = describe(error)
            }
        }
    }
}

/// The recovery phrase, once. Nothing else is reachable until the user confirms.
struct PhraseGateView: View {
    let service: VaultService
    let phrase: RecoveryPhrase
    var title = "Your recovery phrase"
    var onDone: () -> Void
    @Environment(\.theme) private var theme
    @State private var stored = false
    /// The words are censored until asked for, so a screenshot or screen share never catches them by accident.
    @State private var revealed = false
    /// Three random positions the user must re-enter, so "I have stored it" means the words were really written down (review M5).
    @State private var picks = Array((1...24).shuffled().prefix(3)).sorted()
    @State private var answers = ["", "", ""]

    private var confirmed: Bool {
        stored && zip(picks, answers).allSatisfy { pos, a in
            a.trimmingCharacters(in: .whitespaces).lowercased() == phrase.words[pos - 1]
        }
    }

    var body: some View {
        OnboardingFrame(progress: title == "Your recovery phrase" ? 0.8 : nil, title: title,
                        message: "These 24 words are the only way back into your box if every device is lost. Write them down or store them somewhere safe. They are shown once and never saved by Bisel.") {
            VStack(alignment: .leading, spacing: theme.spacing.l) {
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: theme.spacing.s), count: 3), alignment: .leading, spacing: theme.spacing.s) {
                    ForEach(Array(phrase.words.enumerated()), id: \.offset) { i, w in
                        HStack(spacing: theme.spacing.s) {
                            Text("\(i + 1)").font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.tertiaryText.color)
                                .frame(width: 20, alignment: .trailing)
                            Text(revealed ? w : String(repeating: "•", count: 7))
                                .font(theme.font(theme.fonts.value, weight: .medium)).textSelection(.disabled)
                                .accessibilityLabel(w)
                                .accessibilityIdentifier("phrase-word-\(i + 1)")
                        }
                        .padding(.vertical, theme.spacing.s).padding(.horizontal, theme.spacing.s)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: theme.radii.field, style: .continuous).fill(theme.colors.field.color))
                    }
                }
                Toggle("Show the words", isOn: $revealed).accessibilityIdentifier("phrase-reveal")
                Toggle("I have stored it", isOn: $stored).accessibilityIdentifier("phrase-stored")
                VStack(alignment: .leading, spacing: theme.spacing.s) {
                    Caption("To check, type these words from your copy:")
                    HStack(spacing: theme.spacing.m) {
                        ForEach(0..<3, id: \.self) { i in
                            TextField("", text: $answers[i], prompt: Text("Word \(picks[i])")).onboardingField(theme)
                                .autocorrectionDisabled().accessibilityIdentifier("phrase-check-\(i + 1)")
                        }
                    }
                }
            }
        } actions: {
            Button("Continue", action: onDone)
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(!confirmed).accessibilityIdentifier("phrase-continue")
        }
    }
}

struct LockedView: View {
    let service: VaultService
    @Environment(\.theme) private var theme
    @State private var error: String?
    @State private var working = false

    var body: some View {
        OnboardingFrame(progress: nil, title: "Bisel is locked", message: "Unlock your box to search, fill and copy.") {
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
