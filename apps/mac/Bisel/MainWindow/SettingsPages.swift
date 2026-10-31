import KeyboardShortcuts
import ServiceManagement
import SwiftUI
import BiselCore

/// The four settings pages. One rule for where a setting goes:
///  - General: how Bisel starts and looks (login item, command panel, theme, site icons, about).
///  - Fill: getting values out (Accessibility permission, copying).
///  - Sync: where the box lives (iCloud status, devices, the optional self-hosted server).
///  - Account: keeping the box safe (this Mac, locking, recovery phrase, backup, import).

struct GeneralSettings: View {
    @State private var themes = ThemeStore.shared
    @State private var icons = IconStore.shared
    @State private var position = PanelPosition.current
    @State private var material = PanelMaterial.current
    @State private var login = LoginItem()
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.s) {
            SettingsCard(title: "Startup") {
                SettingsRow(label: "Open Bisel at login") { Toggle("", isOn: $login.enabled).settingsSwitch() }
                if let note = login.note { Caption(note) }
            }
            SettingsCard(title: "Command panel") {
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
            SettingsCard(title: "Appearance") {
                SettingsRow(label: "Theme") {
                    Picker("", selection: $themes.selectedFamily) { ForEach(themes.families, id: \.id) { Text($0.name).tag($0.id) } }
                        .labelsHidden().fixedSize()
                }
                Caption("Follows the system light/dark appearance. Custom themes are JSON files in the themes folder.")
                HStack {
                    Button("Themes folder") {
                        themes.reload()
                        NSWorkspace.shared.activateFileViewerSelecting([ThemeStore.themesDirectory])
                    }
                    Button("Write examples") { themes.exportTemplates() }
                    Button("Reload") { themes.reload() }
                }
                .controlSize(.small)
                ForEach(themes.loadErrors, id: \.self) { Text($0).font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.warning.color) }
            }
            SettingsCard(title: "Site icons") {
                SettingsRow(label: "Load site icons") { Toggle("", isOn: $icons.enabled).settingsSwitch() }
                Caption("When on, Bisel fetches each site's icon straight from the site (HTTPS, no cookies, no third-party service), so your network can see which sites you use. Cached on this Mac only.")
                SettingsRow(label: icons.cacheSizeDescription) { Button("Clear cache") { icons.clearCache() }.controlSize(.small) }
            }
            SettingsCard(title: "About") {
                SettingsRow(label: "Version") { Text(Self.version).textSelection(.enabled) }
                SettingsRow(label: "Source code, AGPL-3.0") {
                    Link("GitHub", destination: URL(string: "https://github.com/handlemotion/bisel")!).controlSize(.small)
                }
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

struct FillSettings: View {
    @State private var accessibility = AppModel.shared.accessibility
    @State private var clearAfter = SecureClipboard.clearSeconds
    @State private var closeAfterCopy = CommandPanelModel.closeAfterCopy
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.s) {
            SettingsCard(title: "Permission") {
                SettingsRow(label: accessibility.trusted ? "Accessibility: allowed" : "Accessibility: not allowed") {
                    Button(accessibility.trusted ? "Check…" : "Set up…") { AppModel.shared.onboarding.show() }.controlSize(.small)
                }
                Caption("Bisel types usernames, passwords and codes into the field you are in through the Accessibility permission.")
            }
            SettingsCard(title: "Copying") {
                SettingsRow(label: "Clear clipboard after") {
                    NumberPicker(value: $clearAfter, choices: SecureClipboard.clearSecondsChoices, unit: "s", key: SecureClipboard.clearSecondsKey)
                }
                SettingsRow(label: "Close the panel after copying with a shortcut") {
                    Toggle("", isOn: $closeAfterCopy).settingsSwitch()
                        .onChange(of: closeAfterCopy) { _, new in UserDefaults.standard.set(new, forKey: CommandPanelModel.closeAfterCopyKey) }
                }
                Caption("Copied values are hidden from clipboard managers and never sent to your other devices.")
            }
        }
        .onAppear { accessibility.start() }
        .onDisappear { accessibility.stop() }
    }
}

struct SyncSettings: View {
    let service: VaultService
    @State private var connectServer = BiselEnvironment.defaultServer
    @State private var connectToken = ""
    @State private var connectError: String?
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.s) {
            SettingsCard(title: "iCloud") {
                SettingsRow(label: "Storage") { Text(laneText).multilineTextAlignment(.trailing) }
                SyncStatusView(service: service)
                Caption("Your box is end-to-end encrypted before it reaches iCloud. Apple can't read it.")
            }
            SettingsCard { DevicesView(service: service) }
            SettingsCard(title: "Self-hosted server") {
                if service.isLocalOnly {
                    DisclosureGroup("Connect a server you run…") {
                        VStack(alignment: .leading, spacing: theme.spacing.s) {
                            TextField("Server URL", text: $connectServer, prompt: Text("https://your-server.example")).accessibilityIdentifier("connect-server")
                            SecureField("Bootstrap token", text: $connectToken, prompt: Text("Set with wrangler secret BOOTSTRAP_TOKEN")).accessibilityIdentifier("connect-token")
                            ErrorLine(text: connectError)
                            Button("Connect and upload") { connect() }
                                .disabled(service.isBusy || connectServer.isEmpty || connectToken.isEmpty).accessibilityIdentifier("connect-go")
                            Caption("Optional. Registers this Mac with your own Bisel server and uploads your items, encrypted.")
                        }
                        .textFieldStyle(.roundedBorder)
                        .padding(.top, theme.spacing.s)
                    }
                } else if let url = service.serverURL {
                    SettingsRow(label: "Server") { Text(url.absoluteString).textSelection(.enabled).lineLimit(1) }
                } else {
                    Caption("Not used. iCloud keeps your devices in sync.")
                }
            }
        }
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
}

struct AccountSettings: View {
    let service: VaultService
    @State private var strict = SecuritySettings.requireTouchID
    @State private var idleLock = VaultService.idleLockMinutes
    @State private var unlockedFor = VaultService.fillWindowMinutes
    @State private var phraseSheet: RecoveryPhrase?
    @State private var recoveryMessage: String?
    @State private var backupMessage: String?
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.s) {
            SettingsCard(title: "This Mac") {
                SettingsRow(label: "Name") { Text(DisplayText.clean(service.deviceName)).lineLimit(1) }
                SettingsRow(label: "Keys") { Text(BiselEnvironment.usesSoftwareKeys ? "Software (debug build)" : "Secure Enclave") }
            }
            SettingsCard(title: "Locking") {
                SettingsRow(label: "Lock now") {
                    Button("Lock", systemImage: "lock") { service.lock(reason: "manual") }.controlSize(.small).accessibilityIdentifier("lock-button")
                }
                SettingsRow(label: "Lock after idle") { NumberPicker(value: $idleLock, key: VaultService.idleLockKey) }
                SettingsRow(label: "Lock after unlocking, at most") { NumberPicker(value: $unlockedFor, key: VaultService.fillWindowKey) }
                Caption("The box also locks on sleep, screen lock and fast user switching.")
                SettingsRow(label: "Touch ID for every reveal and copy") {
                    Toggle("", isOn: $strict).settingsSwitch()
                        .onChange(of: strict) { _, new in UserDefaults.standard.set(new, forKey: SecuritySettings.requireTouchIDKey) }
                }
                Caption("Off: passwords and codes show and copy freely while the box is unlocked. On: each one asks for Touch ID.")
            }
            SettingsCard(title: "Recovery phrase") {
                SettingsRow(label: "Replace the 24 words") {
                    Button("New phrase…") { newPhrase() }.controlSize(.small).accessibilityIdentifier("settings-new-phrase")
                }
                if let recoveryMessage { Caption(recoveryMessage) }
                Caption("The phrase is the only way back in if you lose every device. The old one stops working.")
            }
            SettingsCard(title: "Backup") {
                SettingsRow(label: backupText) {
                    Button("Export…") { exportBackup() }.controlSize(.small).accessibilityIdentifier("settings-export")
                }
                if let backupMessage { Caption(backupMessage) }
                Caption("An encrypted .bisel-backup file that only your recovery phrase opens. Keep one off this Mac and off iCloud.")
            }
            SettingsCard(title: "Import") { ImportView(service: service) }
        }
        .sheet(item: Binding(get: { phraseSheet.map { PhraseBox(phrase: $0) } }, set: { if $0 == nil { phraseSheet = nil } })) { box in
            PhraseGateView(service: service, phrase: box.phrase, title: "Your new recovery phrase") { phraseSheet = nil; service.confirmPhraseStored() }
                .frame(width: 640, height: 520).themedPage(ThemeStore.shared.current)
        }
    }

    private struct PhraseBox: Identifiable { let phrase: RecoveryPhrase; var id: String { phrase.text } }

    private var backupText: String {
        guard let status = service.backupStatus, let at = status.lastBackupAt else { return String(localized: "No backup yet") }
        let changes = status.changesSinceBackup
        return String(localized: "Last backup \(at.formatted(.relative(presentation: .named)))")
            + (changes > 0 ? String(localized: ", \(changes) changes since") : "")
    }

    private func exportBackup() {
        #if DEBUG
        if let path = ProcessInfo.processInfo.environment["BISEL_DEV_EXPORT_PATH"] {   // flow tests: no out-of-process save panel
            Task {
                do { try await service.exportBackup(to: URL(fileURLWithPath: path)); backupMessage = "Backup written to \(URL(fileURLWithPath: path).lastPathComponent)" }
                catch { backupMessage = describe(error) }
            }
            return
        }
        #endif
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "bisel-\(Date().formatted(.iso8601.year().month().day())).bisel-backup"
        panel.title = "Export backup"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do { try await service.exportBackup(to: url); backupMessage = "Backup written to \(url.lastPathComponent)" }
            catch { backupMessage = describe(error) }
        }
    }

    private func newPhrase() {
        Task {
            do { phraseSheet = try await service.rotateRecovery(); recoveryMessage = "The old phrase no longer works." }
            catch KeyStoreError.userCancelled { recoveryMessage = "Cancelled" }
            catch { recoveryMessage = describe(error) }
        }
    }
}
