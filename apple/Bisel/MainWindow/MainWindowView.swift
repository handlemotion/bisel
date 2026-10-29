import KeyboardShortcuts
import SwiftUI

struct MainWindowView: View {
    enum Section: String, CaseIterable, Identifiable {
        case vault = "Vault", settings = "Settings"
        var id: String { rawValue }
        var symbol: String { self == .vault ? "key.fill" : "gearshape" }
    }

    @State private var section: Section? = .vault
    @Environment(\.theme) private var theme

    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $section) { s in
                Label(s.rawValue, systemImage: s.symbol).tag(s)
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 180)
        } detail: {
            switch section ?? .vault {
            case .vault: VaultPlaceholder()
            case .settings: SettingsView()
            }
        }
        .frame(minWidth: 760, minHeight: 480)
        .navigationTitle(AppModel.shared.vault.provenanceLabel.map { "Bisel  ·  \($0)" } ?? "Bisel")
        .foregroundStyle(theme.colors.text.color)
    }
}

private struct VaultPlaceholder: View {
    @Environment(\.theme) private var theme

    var body: some View {
        ContentUnavailableView {
            Label("Vault UI comes with BiselCore", systemImage: "lock.shield")
        } description: {
            Text("The command panel (\(AppModel.shared.vault.provenanceLabel ?? "vault")) and the fill engine are live. Item list, editing, devices, recovery and import land with the vault.")
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

    var body: some View {
        Form {
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
                Text("Icons are fetched directly from each site (HTTPS, no cookies, no third-party service) and cached on this Mac only.")
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
    }
}
