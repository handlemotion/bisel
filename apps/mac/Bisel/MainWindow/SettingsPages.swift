import KeyboardShortcuts
import ServiceManagement
import SwiftUI
import BiselCore

/// The settings pages, each a run of form sections. One rule for where a setting goes:
///  - Account: this Mac and the recovery phrase.
///  - General: how Bisel starts and the command panel.  Appearance: theme and site icons.
///  - Fill: getting values out (Accessibility permission, copying).  Security: locking.
///  - Sync: where the box lives (iCloud status, adding a device, devices).  Backup & Import: the backup file, imports.
///  - Trash: what was deleted on this Mac.
///  - Advanced: the optional self-hosted server.  About: version and source.

struct AccountSettings: View {
    let service: VaultService
    @State private var phraseSheet: RecoveryPhrase?
    @State private var recoveryMessage: String?

    var body: some View {
        SettingsSection(title: "This Mac") {
            SettingsRow(label: "Name") { Text(DisplayText.clean(service.deviceName)).lineLimit(1) }
            SettingsRow(label: "Keys") { Text(BiselEnvironment.usesSoftwareKeys ? "Software (debug build)" : "Secure Enclave") }
        }
        SettingsSection(title: "Recovery phrase", footer: recoveryMessage) {
            SettingsRow(label: "Replace the 24 words",
                        detail: "The phrase is the only way back in if you lose every device. The old one stops working.") {
                Button("New phrase…") { newPhrase() }.accessibilityIdentifier("settings-new-phrase")
            }
        }
        .sheet(item: Binding(get: { phraseSheet.map { PhraseBox(phrase: $0) } }, set: { if $0 == nil { phraseSheet = nil } })) { box in
            PhraseGateView(service: service, phrase: box.phrase, title: "Your new recovery phrase") { phraseSheet = nil; service.confirmPhraseStored() }
                .frame(width: 640, height: 520).themedPage(ThemeStore.shared.current)
        }
    }

    private struct PhraseBox: Identifiable { let phrase: RecoveryPhrase; var id: String { phrase.text } }

    private func newPhrase() {
        Task {
            do {
                try await AppModel.shared.unlockIfLocked("Unlock your box to replace the recovery phrase")
                phraseSheet = try await service.rotateRecovery(); recoveryMessage = "The old phrase no longer works."
            }
            catch KeyStoreError.userCancelled { recoveryMessage = "Cancelled" }
            catch { recoveryMessage = describe(error) }
        }
    }
}

struct GeneralSettings: View {
    @State private var position = PanelPosition.current
    @State private var material = PanelMaterial.current
    @State private var login = LoginItem()

    var body: some View {
        SettingsSection(title: "Startup", footer: login.note) {
            SettingsRow(label: "Open Bisel at login") { Toggle("", isOn: $login.enabled).settingsSwitch() }
        }
        SettingsSection(title: "Command panel") {
            SettingsRow(label: "Shortcut") { KeyboardShortcuts.Recorder(for: .commandPanel) }
            SettingsRow(label: "Position") {
                Picker("", selection: $position) { ForEach(PanelPosition.allCases) { Text($0.label).tag($0) } }
                    .labelsHidden().fixedSize()
                    .onChange(of: position) { _, new in
                        UserDefaults.standard.set(new.rawValue, forKey: PanelPosition.defaultsKey)
                        UserDefaults.standard.removeObject(forKey: CommandPanelController.dragKey)
                    }
            }
            SettingsRow(label: "Material") {
                Picker("", selection: $material) { ForEach(PanelMaterial.allCases) { Text($0.label).tag($0) } }
                    .labelsHidden().fixedSize()
                    .onChange(of: material) { _, new in UserDefaults.standard.set(new.rawValue, forKey: PanelMaterial.defaultsKey) }
            }
        }
    }
}

/// "Open Bisel at login": the app's own login item (`SMAppService.mainApp`).
@MainActor @Observable
private final class LoginItem {
    private(set) var note: String?
    var enabled: Bool {
        get { status == .enabled }
        set {
            do { try newValue ? SMAppService.mainApp.register() : SMAppService.mainApp.unregister() }
            catch { note = error.localizedDescription }
            status = SMAppService.mainApp.status
            if status == .requiresApproval { note = String(localized: "Allow Bisel in System Settings → General → Login Items.") }
            else if status == .enabled || !newValue { note = nil }
        }
    }
    private var status = SMAppService.mainApp.status
}

struct AppearanceSettings: View {
    @State private var themes = ThemeStore.shared
    @State private var icons = IconStore.shared

    var body: some View {
        SettingsSection {
            SettingsRow(label: "Theme", detail: "Follows the system light/dark appearance.") {
                Picker("", selection: $themes.selectedFamily) { ForEach(themes.families, id: \.id) { Text($0.name).tag($0.id) } }
                    .labelsHidden().fixedSize()
            }
            SettingsRow(label: "Custom themes", detail: "JSON files in the themes folder.") {
                HStack {
                    Button("Themes folder") {
                        themes.reload()
                        NSWorkspace.shared.activateFileViewerSelecting([ThemeStore.themesDirectory])
                    }
                    Button("Write examples") { themes.exportTemplates() }
                    Button("Reload") { themes.reload() }
                }
            }
            ForEach(themes.loadErrors, id: \.self) { Text($0).font(.callout).foregroundStyle(.orange) }
        }
        SettingsSection(title: "Site icons", footer: "Bisel fetches each site's icon straight from the site (HTTPS, no cookies, no third-party service), so your network can see which sites you use. Cached on this Mac only.") {
            SettingsRow(label: "Load site icons") { Toggle("", isOn: $icons.enabled).settingsSwitch() }
            SettingsRow(label: "Cache", detail: icons.cacheSizeDescription) { Button("Clear cache") { icons.clearCache() } }
        }
    }
}

struct FillSettings: View {
    @State private var accessibility = AppModel.shared.accessibility
    @State private var clearAfter = SecureClipboard.clearSeconds
    @State private var closeAfterCopy = CommandPanelModel.closeAfterCopy

    var body: some View {
        SettingsSection(title: "Permission") {
            SettingsRow(label: "Accessibility",
                        detail: "Bisel types usernames, passwords and codes into the field you are in through the Accessibility permission.") {
                if accessibility.trusted {
                    Text("Allowed").foregroundStyle(.secondary)
                } else {
                    Button("Allow…") { AccessibilityInspector.requestAccess() }
                }
            }
        }
        .onAppear { accessibility.start() }
        .onDisappear { accessibility.stop() }
        SettingsSection(title: "Copying", footer: "Copied values are hidden from clipboard managers and never sent to your other devices.") {
            SettingsRow(label: "Clear clipboard after") {
                NumberPicker(value: $clearAfter, choices: SecureClipboard.clearSecondsChoices, unit: "s", key: SecureClipboard.clearSecondsKey)
            }
            SettingsRow(label: "Close the panel after copying with a shortcut") {
                Toggle("", isOn: $closeAfterCopy).settingsSwitch()
                    .onChange(of: closeAfterCopy) { _, new in UserDefaults.standard.set(new, forKey: CommandPanelModel.closeAfterCopyKey) }
            }
        }
    }
}

struct SecurityPage: View {
    let service: VaultService
    @State private var strict = SecuritySettings.requireTouchID
    @State private var idleLock = VaultService.idleLockMinutes
    @State private var unlockedFor = VaultService.fillWindowMinutes

    /// A change here asks for Touch ID first (the native prompt); cancelled, the setting stays as it was.
    private func guarded<T>(_ value: Binding<T>) -> Binding<T> {
        Binding(get: { value.wrappedValue }, set: { new in
            Task {
                do { try await BiometricGate.authenticate(reason: "change Bisel's security settings", grantsCredit: false) }
                catch { return }
                value.wrappedValue = new
            }
        })
    }

    var body: some View {
        SettingsSection(title: "Locking", footer: "The box also locks on sleep, screen lock and fast user switching.") {
            SettingsRow(label: "Lock now") {
                Button("Lock", systemImage: "lock") { service.lock(reason: "manual") }
                    .disabled(service.phase != .unlocked).accessibilityIdentifier("lock-button")
            }
            SettingsRow(label: "Lock after idle") { NumberPicker(value: guarded($idleLock), key: VaultService.idleLockKey) }
            SettingsRow(label: "Lock after unlocking, at most") { NumberPicker(value: guarded($unlockedFor), key: VaultService.fillWindowKey) }
        }
        SettingsSection(title: "Touch ID") {
            SettingsRow(label: "Touch ID for every reveal and copy",
                        detail: "Off: passwords and codes show and copy freely while the box is unlocked. On: each one asks for Touch ID.") {
                Toggle("", isOn: guarded($strict)).settingsSwitch()
                    .onChange(of: strict) { _, new in UserDefaults.standard.set(new, forKey: SecuritySettings.requireTouchIDKey) }
            }
        }
    }
}

struct SyncSettings: View {
    let service: VaultService

    var body: some View {
        SettingsSection(title: "iCloud", footer: "Your box is end-to-end encrypted before it reaches iCloud. Apple can't read it.") {
            LabeledContent {
                HStack {
                    Text(laneText).multilineTextAlignment(.trailing)
                    if service.isUnlocked && !service.isLocalOnly {
                        Button { Task { await service.sync(reason: "manual") } } label: { Image(systemName: "arrow.clockwise") }
                            .buttonStyle(.borderless).help("Sync now").accessibilityLabel("Sync now").accessibilityIdentifier("sync-now")
                            .disabled(service.syncState == .syncing)
                    }
                }
            } label: {
                Text("Storage")
                if !service.isLocalOnly || !service.securityAlerts.isEmpty || service.recoveryKeyChanged {
                    SyncStatusView(service: service, compact: true)   // "On this Mac only" would repeat the value
                }
            }
        }
        if service.isOnICloud { JoinRequestsCard(service: service) }
        DevicesView(service: service)
    }

    private var laneText: String {
        switch service.laneStatus {
        case .thisDeviceOnly: service.serverURL == nil ? String(localized: "This Mac only") : String(localized: "Your server")
        case .active: String(localized: "iCloud")
        case .accountUnavailable(let why): String(localized: "iCloud unavailable: \(why)")
        case .accountChanged: String(localized: "Another iCloud account is signed in")
        case .storeMissing: String(localized: "Deleted from iCloud")
        case .moved(let url): String(localized: "Moved to \(url.host() ?? url.absoluteString)")
        }
    }
}

struct BackupSettings: View {
    let service: VaultService
    @State private var backupMessage: String?

    var body: some View {
        SettingsSection(title: "Backup", footer: backupMessage) {
            SettingsRow(label: "Export a backup",
                        detail: "An encrypted .bisel-backup file that only your recovery phrase opens. Keep one off this Mac and off iCloud.") {
                Button("Export…") { exportBackup() }.accessibilityIdentifier("settings-export")
            }
            SettingsRow(label: "Last backup") { Text(backupText).foregroundStyle(.secondary) }
        }
        SettingsSection(title: "Import") { ImportView(service: service) }
    }

    private var backupText: String {
        guard let status = service.backupStatus, let at = status.lastBackupAt else { return String(localized: "None yet") }
        let changes = status.changesSinceBackup
        return at.formatted(.relative(presentation: .named))
            + (changes > 0 ? String(localized: ", \(changes) changes since") : "")
    }

    private func exportBackup() {
        Task {
            do { try await AppModel.shared.unlockIfLocked("Unlock your box to export a backup") }
            catch KeyStoreError.userCancelled { return }
            catch { backupMessage = describe(error); return }
            #if DEBUG
            if let path = ProcessInfo.processInfo.environment["BISEL_DEV_EXPORT_PATH"] {   // flow tests: no out-of-process save panel
                do { try await service.exportBackup(to: URL(fileURLWithPath: path)); backupMessage = "Backup written to \(URL(fileURLWithPath: path).lastPathComponent)" }
                catch { backupMessage = describe(error) }
                return
            }
            #endif
            let panel = NSSavePanel()
            panel.nameFieldStringValue = "bisel-\(Date().formatted(.iso8601.year().month().day())).bisel-backup"
            panel.title = "Export backup"
            guard panel.runModal() == .OK, let url = panel.url else { return }
            do { try await service.exportBackup(to: url); backupMessage = "Backup written to \(url.lastPathComponent)" }
            catch { backupMessage = describe(error) }
        }
    }
}

/// Items deleted on this Mac in the last 30 days: restore or delete for good. Both ask for Touch ID (`Vault.undoTrash`,
/// `Vault.eraseFromTrash`); titles only, nothing here decrypts a secret into the view.
struct TrashSettings: View {
    let service: VaultService
    @State private var deleted: [TrashReceipt]?
    @State private var message: String?
    @State private var erasing: TrashReceipt?

    var body: some View {
        SettingsSection(title: "Deleted items",
                        footer: message ?? String(localized: "Items stay here for 30 days after you delete them on this Mac, then they are gone.")) {
            if !service.isUnlocked {
                SettingsRow(label: String(localized: "Your box is locked"), detail: String(localized: "Unlock it to see what is in the Trash.")) {
                    Button("Unlock…") { unlock() }
                }
            } else if let deleted {
                if deleted.isEmpty { Text("The Trash is empty").foregroundStyle(.secondary) }
                ForEach(deleted) { item in
                    SettingsRow(label: DisplayText.clean(item.title), detail: age(of: item)) {
                        HStack {
                            Button("Restore") { restore(item) }
                            Button("Delete…", role: .destructive) { erasing = item }
                        }
                    }
                }
            }
        }
        // Also when the panel moves something here while the page is open.
        .task(id: "\(service.isUnlocked) \(service.rows.count)") { await load() }
        .alert(String(localized: "Permanently delete \(DisplayText.clean(erasing?.title ?? ""))?"),
               isPresented: Binding(get: { erasing != nil }, set: { if !$0 { erasing = nil } }), presenting: erasing) { item in
            Button("Delete Permanently", role: .destructive) { erase(item) }
            Button("Cancel", role: .cancel) { }
        } message: { _ in
            Text("This can't be undone. Backups you already made, and a self-hosted server's history, still hold it.")
        }
    }

    private func age(of item: TrashReceipt) -> String {
        let left = max(Int((item.deletedAt.addingTimeInterval(TrashReceipt.retention).timeIntervalSinceNow / 86_400).rounded(.up)), 1)
        return String(localized: "Deleted \(item.deletedAt.formatted(.relative(presentation: .named))), \(left) days left")
    }

    private func load() async {
        guard service.isUnlocked else { deleted = nil; return }
        do { deleted = try await service.recentlyDeleted() }
        catch { message = describe(error) }
    }

    private func unlock() {
        Task {
            do { try await AppModel.shared.unlockIfLocked("Unlock your box to open the Trash") }
            catch KeyStoreError.userCancelled { }
            catch { message = describe(error) }
        }
    }

    private func restore(_ item: TrashReceipt) {
        run { _ = try await service.undoTrash(item); message = String(localized: "\(DisplayText.clean(item.title)) is back in your box.") }
    }

    private func erase(_ item: TrashReceipt) {
        run { try await service.eraseFromTrash(item); message = String(localized: "\(DisplayText.clean(item.title)) was permanently deleted.") }
    }

    /// A cancelled Touch ID changes nothing and says nothing.
    private func run(_ body: @escaping () async throws -> Void) {
        Task {
            do { try await body() }
            catch KeyStoreError.userCancelled { return }
            catch { message = describe(error) }
            await load()
        }
    }
}

struct AdvancedSettings: View {
    let service: VaultService
    @State private var connectServer = BiselEnvironment.defaultServer
    @State private var connectToken = ""
    @State private var connectError: String?

    var body: some View {
        SettingsSection(title: "Self-hosted server", footer: service.isLocalOnly ? "Optional. Registers this Mac with your own Bisel server and uploads your items, encrypted." : nil) {
            if service.isLocalOnly {
                DisclosureGroup("Connect a server you run…") {
                    TextField("Server URL", text: $connectServer, prompt: Text("https://your-server.example")).accessibilityIdentifier("connect-server")
                    SecureField("Bootstrap token", text: $connectToken, prompt: Text("Set with wrangler secret BOOTSTRAP_TOKEN")).accessibilityIdentifier("connect-token")
                    ErrorLine(text: connectError)
                    Button("Connect and upload") { connect() }
                        .disabled(service.isBusy || connectServer.isEmpty || connectToken.isEmpty).accessibilityIdentifier("connect-go")
                }
            } else if let url = service.serverURL {
                SettingsRow(label: "Server") { Text(url.absoluteString).textSelection(.enabled).lineLimit(1) }
            } else {
                SettingsRow(label: "Server") { Text("Not used. iCloud keeps your devices in sync.").foregroundStyle(.secondary) }
            }
        }
    }

    private func connect() {
        connectError = nil
        let (url, bad) = ServerURLCheck.parse(connectServer)
        guard let url else { connectError = bad; return }
        let token = connectToken.trimmingCharacters(in: .whitespacesAndNewlines)
        Task {
            do {
                try await AppModel.shared.unlockIfLocked("Unlock your box to connect a server")
                try await service.connectServer(server: url, token: token); connectToken = ""
            }
            catch { connectError = describe(error) }
        }
    }
}

struct AboutSettings: View {
    var body: some View {
        SettingsSection {
            SettingsRow(label: "Version") { Text(Self.version).textSelection(.enabled) }
            SettingsRow(label: "Source code, AGPL-3.0") {
                Link("GitHub", destination: URL(string: "https://github.com/handlemotion/bisel")!)
            }
        }
    }

    private static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String
        return build.map { "\(short) (\($0))" } ?? short
    }
}
