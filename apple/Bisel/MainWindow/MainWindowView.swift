import KeyboardShortcuts
import SwiftUI
import BiselCore

struct MainWindowView: View {
    enum Section: String, CaseIterable, Identifiable {
        case vault = "Vault", generator = "Generator", devices = "Devices", importer = "Import", settings = "Settings"
        var id: String { rawValue }
        var symbol: String {
            switch self {
            case .vault: "key.fill"; case .generator: "wand.and.stars"; case .devices: "laptopcomputer.and.iphone"
            case .importer: "square.and.arrow.down"; case .settings: "gearshape"
            }
        }
    }

    private let service = AppModel.shared.service
    @State private var section: Section? = .vault
    @Environment(\.theme) private var theme

    var body: some View {
        Group {
            if let e = service.startupError {
                ContentUnavailableView("Bisel can't start", systemImage: "exclamationmark.triangle", description: Text(e))
            } else if usesFixture {
                fixtureNotice
            } else if service.phase == .needsSetup {
                SetupView(service: service)
            } else if let phrase = service.pendingPhrase {
                PhraseGateView(service: service, phrase: phrase) { service.confirmPhraseStored() }
            } else if service.phase == .locked {
                LockedView(service: service)
            } else {
                unlocked
            }
        }
        .frame(minWidth: 820, minHeight: 540)
        .themedPage(theme)
        .background(WindowAccessor { w in
            // Always hidden while a recovery phrase can be on screen (set-up entry, the one-time display).
            w.sharingType = (PanelCapture.hidden || service.pendingPhrase != nil || service.phase == .needsSetup) ? .none : .readOnly
            w.isRestorable = false
        })
        .navigationTitle(service.provenanceLabel.map { "Bisel  ·  \($0)" } ?? "Bisel")
    }

    private var usesFixture: Bool {
        #if BISEL_DEV_FIXTURE
        BiselEnvironment.useDevFixture
        #else
        false
        #endif
    }

    private var fixtureNotice: some View {
        ContentUnavailableView("Dev fixture is active", systemImage: "testtube.2",
                               description: Text("This run uses the fake panel fixture. Start without it to use the real vault."))
    }

    private var unlocked: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $section) { s in
                Label(s.rawValue, systemImage: s.symbol).tag(s).accessibilityIdentifier("nav-\(s.rawValue)")
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
            .safeAreaInset(edge: .bottom) {
                VStack(alignment: .leading, spacing: theme.spacing.s) {
                    SyncStatusView(service: service)
                    Button("Lock", systemImage: "lock") { service.lock(reason: "manual") }
                        .buttonStyle(.borderless).accessibilityIdentifier("lock-button")
                }
                .padding(theme.spacing.m)
            }
        } detail: {
            switch section ?? .vault {
            case .vault: VaultBrowser(service: service)
            case .generator:
                ScrollView { VStack(alignment: .leading) {
                    Text("Password generator").font(theme.font(theme.fonts.title, weight: .semibold)).padding(.bottom, theme.spacing.m)
                    GeneratorView().frame(maxWidth: 420)
                }.padding(theme.spacing.l).frame(maxWidth: .infinity, alignment: .leading) }
            case .devices: DevicesView(service: service)
            case .importer: ImportView(service: service)
            case .settings: SettingsView()
            }
        }
    }
}

struct SettingsView: View {
    @State private var themes = ThemeStore.shared
    @State private var accessibility = AppModel.shared.accessibility
    @State private var icons = IconStore.shared
    @State private var position = PanelPosition.current
    @State private var material = PanelMaterial.current
    @State private var hideFromCapture = PanelCapture.hidden
    @State private var strict = SecuritySettings.requireTouchID
    @State private var closeAfterCopy = CommandPanelModel.closeAfterCopy
    @State private var fillWindow = VaultService.fillWindowMinutes
    @State private var idleLock = VaultService.idleLockMinutes
    @State private var phraseSheet: RecoveryPhrase?
    @State private var vaultMessage: String?
    private let service = AppModel.shared.service

    var body: some View {
        Form {
            Section("Vault") {
                LabeledContent("Server") { Text(service.serverURL?.absoluteString ?? "—").textSelection(.enabled) }
                LabeledContent("This device") { Text(service.deviceName) }
                LabeledContent("Keys") { Text(BiselEnvironment.usesSoftwareKeys ? "Software (debug build, not secure)" : "Secure Enclave") }
                Picker("Keep unlocked for", selection: $fillWindow) {
                    ForEach([1, 2, 5, 10, 15, 30], id: \.self) { Text("\($0) min").tag($0) }
                }
                .onChange(of: fillWindow) { _, v in UserDefaults.standard.set(v, forKey: VaultService.fillWindowKey) }
                Picker("Lock after idle", selection: $idleLock) {
                    ForEach([1, 2, 5, 10, 15, 30], id: \.self) { Text("\($0) min").tag($0) }
                }
                .onChange(of: idleLock) { _, v in UserDefaults.standard.set(v, forKey: VaultService.idleLockKey) }
                Text("The vault also locks on sleep, screen lock and fast user switching.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Backup and recovery") {
                HStack {
                    Button("Export backup…") { exportBackup() }.accessibilityIdentifier("settings-export")
                    Button("New recovery phrase…") { newPhrase() }.accessibilityIdentifier("settings-new-phrase")
                }
                if let vaultMessage { Text(vaultMessage).font(.caption).foregroundStyle(.secondary) }
                Text("A backup holds the encrypted items and the recovery envelope. Only the recovery phrase opens it.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Command panel") {
                KeyboardShortcuts.Recorder("Global shortcut", name: .commandPanel)
                Picker("Position", selection: $position) {
                    ForEach(PanelPosition.allCases) { Text($0.label).tag($0) }
                }
                .onChange(of: position) { _, new in
                    UserDefaults.standard.set(new.rawValue, forKey: PanelPosition.defaultsKey)
                    UserDefaults.standard.removeObject(forKey: CommandPanelController.dragKey)
                }
                Picker("Material", selection: $material) {
                    ForEach(PanelMaterial.allCases) { Text($0.label).tag($0) }
                }
                .onChange(of: material) { _, new in UserDefaults.standard.set(new.rawValue, forKey: PanelMaterial.defaultsKey) }
                Toggle("Close after copying with a shortcut", isOn: $closeAfterCopy)
                    .onChange(of: closeAfterCopy) { _, new in UserDefaults.standard.set(new, forKey: CommandPanelModel.closeAfterCopyKey) }
            }
            Section("Security") {
                Toggle("Hide from screenshots and screen sharing", isOn: $hideFromCapture)
                    .onChange(of: hideFromCapture) { _, new in UserDefaults.standard.set(new, forKey: PanelCapture.defaultsKey) }
                Toggle("Require Touch ID to reveal or copy password and OTP", isOn: $strict)
                    .onChange(of: strict) { _, new in UserDefaults.standard.set(new, forKey: SecuritySettings.requireTouchIDKey) }
                Text("Off: values are visible while the vault is unlocked and copy without another prompt. On: masked until a fresh Touch ID check, and every copy asks again.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Site icons") {
                Toggle("Load site icons", isOn: $icons.enabled)
                Text("Off by default. When on, Bisel contacts each site in your vault to fetch its icon, so your network and DNS provider can see which sites you use. Icons come straight from the site (HTTPS, public addresses only, no cookies, no third-party service) and are cached on this Mac only.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Text(icons.cacheSizeDescription).foregroundStyle(.secondary)
                    Spacer()
                    Button("Clear icon cache") { icons.clearCache() }
                }
            }
            Section("Fill") {
                LabeledContent("Accessibility permission") {
                    HStack {
                        Text(accessibility.trusted ? "Granted" : "Not granted")
                            .foregroundStyle(accessibility.trusted ? .green : .orange)
                        Button("Set up…") { AppModel.shared.onboarding.show() }
                    }
                }
            }
            Section("Theme") {
                Picker("Theme", selection: $themes.selectedFamily) {
                    ForEach(themes.families, id: \.id) { Text($0.name).tag($0.id) }
                }
                Text("Follows the system light/dark appearance.").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Reveal themes folder") {
                        themes.reload()
                        NSWorkspace.shared.activateFileViewerSelecting([ThemeStore.themesDirectory])
                    }
                    Button("Write example theme files") { themes.exportTemplates() }
                    Button("Reload") { themes.reload() }
                }
                if !themes.loadErrors.isEmpty {
                    ForEach(themes.loadErrors, id: \.self) { Text($0).font(.caption).foregroundStyle(.orange) }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { accessibility.start() }
        .onDisappear { accessibility.stop() }
        .navigationTitle("Settings")
        .sheet(item: Binding(get: { phraseSheet.map { PhraseBox(phrase: $0) } }, set: { if $0 == nil { phraseSheet = nil } })) { box in
            PhraseGateView(service: service, phrase: box.phrase, title: "Your new recovery phrase") { phraseSheet = nil; service.confirmPhraseStored() }
                .frame(width: 640, height: 520).themedPage(ThemeStore.shared.current).hiddenFromCapture(force: true)
        }
    }

    private struct PhraseBox: Identifiable { let phrase: RecoveryPhrase; var id: String { phrase.text } }

    private func exportBackup() {
        #if DEBUG
        if let path = ProcessInfo.processInfo.environment["BISEL_DEV_EXPORT_PATH"] {   // flow tests: no out-of-process save panel
            Task {
                do { try await service.exportBackup(to: URL(fileURLWithPath: path)); vaultMessage = "Backup written to \(URL(fileURLWithPath: path).lastPathComponent)" }
                catch { vaultMessage = describe(error) }
            }
            return
        }
        #endif
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "bisel-\(Date().formatted(.iso8601.year().month().day())).bisel-backup"
        panel.title = "Export backup"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do { try await service.exportBackup(to: url); vaultMessage = "Backup written to \(url.lastPathComponent)" }
            catch { vaultMessage = describe(error) }
        }
    }

    private func newPhrase() {
        Task {
            do { phraseSheet = try await service.rotateRecovery(); vaultMessage = "The old phrase no longer works." }
            catch KeyStoreError.userCancelled { vaultMessage = "Cancelled" }
            catch { vaultMessage = describe(error) }
        }
    }
}
