import SwiftUI
import UniformTypeIdentifiers
import BiselCore

/// First run on this Mac: new vault (bootstrap), recovery from the phrase, or restore from a backup file (SPEC §8.4/8.5).
struct SetupView: View {
    let service: VaultService
    @Environment(\.theme) private var theme

    enum Mode: String, CaseIterable, Identifiable {
        case create = "New box", recover = "Recover", restore = "Restore backup"
        var id: String { rawValue }
    }
    @State private var mode: Mode = .create
    @State private var server = ""   // never persisted outside the vault store: the hostname is a secret (SPEC §6, review M17)
    @State private var token = ""
    @State private var deviceName = Host.current().localizedName ?? "Mac"
    @State private var phrase = ""
    @State private var backupURL: URL?
    @State private var picking = false
    @State private var error: String?
    @State private var debugPath = ""

    var body: some View {
        OnboardingCard(title: title, subtitle: blurb) {
            VStack(alignment: .leading, spacing: theme.spacing.m) {
                if mode != .create {
                    field("Server URL", "https://your-server.example", $server, id: "setup-server")
                    if mode != .recover { secureField("Bootstrap token", "Set with wrangler secret BOOTSTRAP_TOKEN", $token, id: "setup-token") }
                }
                field("This device's name", "MacBook", $deviceName, id: "setup-device")
                if mode == .restore {
                    #if DEBUG
                    TextField("", text: $debugPath, prompt: Text("debug: backup file path")).onboardingField(theme)
                        .accessibilityIdentifier("setup-debug-path").onSubmit { backupURL = URL(fileURLWithPath: debugPath) }
                    #endif
                    HStack {
                        Button("Choose backup file…") { picking = true }
                            .buttonStyle(PillButtonStyle(primary: false)).fixedSize()
                            .accessibilityIdentifier("setup-pick-backup")
                        Text(backupURL?.lastPathComponent ?? "None selected")
                            .font(theme.font(theme.fonts.detail)).foregroundStyle(theme.colors.secondaryText.color).lineLimit(1)
                    }
                }
                if mode != .create {
                    VStack(alignment: .leading, spacing: theme.spacing.xs) {
                        Caption("Recovery phrase (24 words)")
                        TextEditor(text: $phrase)
                            .font(theme.font(theme.fonts.value, weight: .regular))
                            .frame(height: 76)
                            .scrollContentBackground(.hidden)
                            .padding(theme.spacing.s)
                            .background(RoundedRectangle(cornerRadius: theme.radii.field + 2, style: .continuous).fill(theme.colors.field.color))
                            .overlay(RoundedRectangle(cornerRadius: theme.radii.field + 2, style: .continuous)
                                .strokeBorder(theme.colors.border.color, lineWidth: theme.card.hairline))
                            .accessibilityIdentifier("setup-phrase")
                    }
                }
                ErrorLine(text: error)
                Button(action: go) {
                    if service.isBusy { ProgressView().controlSize(.small) } else { Text(actionTitle) }
                }
                .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                .disabled(service.isBusy || !ready)
                .padding(.top, theme.spacing.xs)
                .accessibilityIdentifier("setup-go")
                Text(footer)
                    .font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.tertiaryText.color)
                    .frame(maxWidth: .infinity).multilineTextAlignment(.center)
                // New box is the normal path; the other two are for a Mac that is joining or rebuilding one.
                HStack(spacing: theme.spacing.l) {
                    if mode != .create { Button("Back to new box") { mode = .create; error = nil }.accessibilityIdentifier("setup-mode-create") }
                    if mode != .recover { Button("I have a recovery phrase") { mode = .recover; error = nil }.accessibilityIdentifier("setup-mode-recover") }
                    if mode != .restore { Button("Restore from a backup file") { mode = .restore; error = nil }.accessibilityIdentifier("setup-mode-restore") }
                }
                .buttonStyle(.link).font(theme.font(theme.fonts.caption))
                .frame(maxWidth: .infinity)
            }
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [UTType(filenameExtension: "bisel-backup") ?? .json, .json]) { r in
            if case .success(let u) = r { backupURL = u }
        }
    }

    private var title: String {
        switch mode {
        case .create: "Welcome to Bisel"
        case .recover: "Recover your box"
        case .restore: "Restore from a backup"
        }
    }

    private var blurb: String {
        switch mode {
        case .create: "Your keys are made on this Mac. Nothing leaves it until you connect a server."
        case .recover: "Enter your recovery phrase to rebuild the box on this Mac from the server."
        case .restore: "Re-create the box on a fresh server from a .bisel-backup file and its recovery phrase."
        }
    }
    private var actionTitle: String { switch mode { case .create: "Create box"; case .recover: "Recover"; case .restore: "Restore" } }
    private var footer: String {
        BiselEnvironment.usesSoftwareKeys ? "Debug build: device keys are kept in a plain file, not the Secure Enclave." : "Device keys are created in the Secure Enclave and need Touch ID."
    }
    private var ready: Bool {
        !deviceName.isEmpty && (mode == .create || (!server.isEmpty && (mode == .recover || !token.isEmpty)))
            && (mode == .create || !phrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            && (mode != .restore || backupURL != nil)
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

    private func go() {
        error = nil
        let name = deviceName.trimmingCharacters(in: .whitespaces)
        if mode == .create {
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
        Task {
            do {
                switch mode {
                case .create: break
                case .recover: try await service.recover(server: url, phrase: words, deviceName: name)
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
    /// Three random positions the user must re-enter, so "I have stored it" means the words were really written down (review M5).
    @State private var picks = Array((1...24).shuffled().prefix(3)).sorted()
    @State private var answers = ["", "", ""]

    private var confirmed: Bool {
        stored && zip(picks, answers).allSatisfy { pos, a in
            a.trimmingCharacters(in: .whitespaces).lowercased() == phrase.words[pos - 1]
        }
    }

    var body: some View {
        OnboardingCard(title: title,
                       subtitle: "These 24 words are the only way back into your box if every device is lost. Write them down or store them somewhere safe. They are shown once and never saved by Bisel.",
                       width: 520) {
            VStack(alignment: .leading, spacing: theme.spacing.l) {
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
                        .overlay(RoundedRectangle(cornerRadius: theme.radii.field, style: .continuous)
                            .strokeBorder(theme.colors.border.color, lineWidth: theme.card.hairline))
                    }
                }
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
                Button("Continue", action: onDone)
                    .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                    .disabled(!confirmed).accessibilityIdentifier("phrase-continue")
            }
        }
    }
}

struct LockedView: View {
    let service: VaultService
    @Environment(\.theme) private var theme
    @State private var error: String?
    @State private var working = false

    var body: some View {
        OnboardingCard(title: "Bisel is locked", subtitle: "Unlock your box to search, fill and copy.") {
            VStack(spacing: theme.spacing.m) {
                Button { unlock() } label: { Label("Unlock with Touch ID", systemImage: "touchid") }
                    .buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                    .disabled(working).accessibilityIdentifier("unlock-button")
                ErrorLine(text: error)
                SyncStatusView(service: service, compact: true)
            }
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
