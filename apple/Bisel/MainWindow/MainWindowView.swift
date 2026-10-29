import KeyboardShortcuts
import SwiftUI
import BiselCore

struct MainWindowView: View {
    /// The window is for settings only; the command panel (⌘⇧Space) is the way into the box.
    enum Section: String, CaseIterable, Identifiable {
        case settings = "General", devices = "Devices", importer = "Import"
        var id: String { rawValue }
        var symbol: String {
            switch self {
            case .settings: "gearshape"; case .devices: "laptopcomputer.and.iphone"; case .importer: "square.and.arrow.down"
            }
        }
    }

    private let service = AppModel.shared.service
    @State private var section: Section? = .settings
    /// After the recovery phrase of a new box: one last onboarding step to import passwords.
    @State private var showImport = false
    /// The titlebar's height, measured from the window: the scene sizes the content area, the titlebar comes on top of it,
    /// so the island's frame is its height minus this.
    @State private var titlebarInset: CGFloat = 32
    @Environment(\.dismissWindow) private var dismissWindow
    @Environment(\.theme) private var theme

    var body: some View {
        // Screens cross-fade in place (a ZStack, so they never share layout), over a solid black backing in the card phases
        // so nothing behind the window shows through while two of them overlap.
        ZStack {
            if let e = service.startupError {
                ContentUnavailableView("Bisel can't start", systemImage: "exclamationmark.triangle", description: Text(e))
            } else if usesFixture {
                fixtureNotice
            } else if service.phase == .needsSetup {
                SetupView(service: service).transition(.opacity)
            } else if let phrase = service.pendingPhrase {
                PhraseGateView(service: service, phrase: phrase) { service.confirmPhraseStored(); showImport = true }
                    .transition(.opacity)
            } else if showImport {
                OnboardingImportView(service: service) { showImport = false; dismissWindow(id: "main") }
                    .transition(.opacity)
            } else if service.phase == .locked {
                LockedView(service: service).transition(.opacity)
            } else {
                unlocked
            }
        }
        .background(cardSize == nil ? Color.clear : Theme.biselDark.colors.background.color)
        .animation(.easeInOut(duration: 0.28), value: screenKey)
        // SwiftUI owns the window size (the scene is .contentSize): the island is exactly its fixed frame, the settings window
        // grows from a 820x540 minimum. No AppKit resizing, so the hosting view can never lag behind the window.
        .frame(minWidth: cardSize?.width ?? 820, maxWidth: cardSize?.width ?? .infinity,
               minHeight: cardSize.map { $0.height - titlebarInset } ?? 540, maxHeight: cardSize.map { $0.height - titlebarInset } ?? .infinity)
        .themedPage(theme, opaque: cardSize == nil)
        .panelMaterial()
        .background(WindowAccessor { w in
            w.sharingType = .readOnly   // nothing is hidden from screenshots; sensitive values are masked in the UI instead
            w.isRestorable = false
            DockPresence.windowAppeared(w)
            style(w)
            let inset = w.frame.height - w.contentLayoutRect.height
            if cardSize != nil, abs(inset - titlebarInset) > 0.5, inset >= 0 { DispatchQueue.main.async { titlebarInset = inset } }
        })
        .toolbarBackgroundVisibility(cardSize == nil ? .automatic : .hidden, for: .windowToolbar)
        .navigationTitle(service.provenanceLabel.map { "Bisel  ·  \($0)" } ?? "Bisel")
    }

    /// Set-up, the recovery phrase and the lock screen are the glass island itself: the window is small, borderless-looking
    /// and shows the command panel's material. Everything else is the normal window.
    private var cardSize: NSSize? {
        guard service.startupError == nil, !usesFixture else { return nil }
        if service.pendingPhrase != nil { return OnboardingLayout.island }
        if showImport { return OnboardingLayout.island }
        switch service.phase {
        case .needsSetup: return OnboardingLayout.island
        case .locked: return OnboardingLayout.island
        default: return nil
        }
    }

    private func style(_ w: NSWindow) {
        if cardSize != nil {
            w.isOpaque = false
            w.backgroundColor = .clear
            w.titlebarAppearsTransparent = true
            w.titlebarSeparatorStyle = .none
            w.titleVisibility = .hidden
            w.styleMask.insert(.fullSizeContentView)
            w.styleMask.remove(.resizable)
            // No traffic lights on the onboarding screens: the window closes from the Dock.
            for b in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] { w.standardWindowButton(b)?.isHidden = true }
            w.isMovableByWindowBackground = true
            w.hasShadow = true
        } else {
            w.isOpaque = true
            w.backgroundColor = .windowBackgroundColor
            w.titlebarAppearsTransparent = false
            w.titlebarSeparatorStyle = .automatic
            w.titleVisibility = .visible
            w.styleMask.insert(.resizable)
            for b in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] { w.standardWindowButton(b)?.isHidden = false }
            w.isMovableByWindowBackground = false
        }
    }

    /// Which screen is up; changing it cross-fades.
    private var screenKey: String {
        if service.startupError != nil { return "error" }
        if service.phase == .needsSetup { return "setup" }
        if service.pendingPhrase != nil { return "phrase" }
        if showImport { return "import" }
        return service.phase == .locked ? "locked" : "unlocked"
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
                               description: Text("This run uses the fake panel fixture. Start without it to use the real box."))
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
            switch section ?? .settings {
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
    @State private var strict = SecuritySettings.requireTouchID
    @State private var closeAfterCopy = CommandPanelModel.closeAfterCopy
    @State private var fillWindow = VaultService.fillWindowMinutes
    @State private var idleLock = VaultService.idleLockMinutes
    @State private var phraseSheet: RecoveryPhrase?
    @State private var vaultMessage: String?
    @State private var connectServer = BiselEnvironment.defaultServer
    @State private var connectToken = ""
    @State private var connectError: String?
    private let service = AppModel.shared.service

    var body: some View {
        Form {
            Section("Box") {
                if service.isLocalOnly {
                    LabeledContent("Sync") { Text("Not connected: this box is on this Mac only") }
                    DisclosureGroup("Connect a server…") {
                        TextField("Server URL", text: $connectServer, prompt: Text("https://your-server.example")).accessibilityIdentifier("connect-server")
                        SecureField("Bootstrap token", text: $connectToken, prompt: Text("Set with wrangler secret BOOTSTRAP_TOKEN")).accessibilityIdentifier("connect-token")
                        ErrorLine(text: connectError)
                        Button("Connect and upload") { connect() }
                            .disabled(service.isBusy || connectServer.isEmpty || connectToken.isEmpty).accessibilityIdentifier("connect-go")
                        Text("Registers this Mac with a server you run and uploads your items, encrypted. You can add your iPhone afterwards.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    LabeledContent("Server") { Text(service.serverURL?.absoluteString ?? "—").textSelection(.enabled) }
                }
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
                Text("The box also locks on sleep, screen lock and fast user switching.").font(.caption).foregroundStyle(.secondary)
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
                Toggle("Require Touch ID to reveal or copy password and OTP", isOn: $strict)
                    .onChange(of: strict) { _, new in UserDefaults.standard.set(new, forKey: SecuritySettings.requireTouchIDKey) }
                Text("Off: values are visible while the box is unlocked and copy without another prompt. On: masked until a fresh Touch ID check, and every copy asks again.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Site icons") {
                Toggle("Load site icons", isOn: $icons.enabled)
                Text("Off by default. When on, Bisel contacts each site in your box to fetch its icon, so your network and DNS provider can see which sites you use. Icons come straight from the site (HTTPS, public addresses only, no cookies, no third-party service) and are cached on this Mac only.")
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
                .frame(width: 640, height: 520).themedPage(ThemeStore.shared.current)
        }
    }

    private struct PhraseBox: Identifiable { let phrase: RecoveryPhrase; var id: String { phrase.text } }

    private func connect() {
        connectError = nil
        let (url, bad) = ServerURLCheck.parse(connectServer)
        guard let url else { connectError = bad; return }
        let token = connectToken.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            do { try await service.connectServer(server: url, token: token); connectToken = "" }
            catch { connectError = describe(error) }
        }
    }

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
