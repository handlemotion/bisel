import OpenDirectory
import SwiftUI
import BiselCore

/// The settings window, all native: a split view with the Mac user's account row and the pages in the sidebar, each
/// page a grouped form. System colors, fonts and controls throughout, so it follows the Mac's light/dark appearance.
enum SettingsPage: String, CaseIterable, Identifiable {
    case account, general, appearance, fill, security, sync, backup, advanced, about
    var id: String { rawValue }
    /// The page Settings opens on, and the last one shown.
    static let defaultsKey = "settings.page"
    /// Posted by `AppModel.showSettings` with the page as the object: an open window switches to it.
    static let showNotification = Notification.Name("app.bisel.settings.show")

    static var current: SettingsPage {
        UserDefaults.standard.string(forKey: defaultsKey).flatMap(SettingsPage.init(rawValue:)) ?? .general
    }

    var title: String {
        switch self {
        case .account: String(localized: "Account")
        case .general: String(localized: "General")
        case .appearance: String(localized: "Appearance")
        case .fill: String(localized: "Fill")
        case .security: String(localized: "Security")
        case .sync: String(localized: "Sync")
        case .backup: String(localized: "Backup & Import")
        case .advanced: String(localized: "Advanced")
        case .about: String(localized: "About")
        }
    }

    /// A white SF Symbol on a colored rounded square, like System Settings.
    var symbol: String {
        switch self {
        case .account: "person.crop.circle.fill"
        case .general: "gearshape.fill"
        case .appearance: "circle.lefthalf.filled"
        case .fill: "keyboard.fill"
        case .security: "touchid"
        case .sync: "icloud.fill"
        case .backup: "externaldrive.fill"
        case .advanced: "wrench.and.screwdriver.fill"
        case .about: "info"
        }
    }

    var tint: Color {
        switch self {
        case .account: .blue
        case .general, .advanced: .gray
        case .appearance: .black
        case .fill: .indigo
        case .security: .red
        case .sync: .blue
        case .backup: .green
        case .about: .cyan
        }
    }

    /// The line under the page's title.
    var summary: String {
        switch self {
        case .account: String(localized: "This Mac and your recovery phrase.")
        case .general: String(localized: "How Bisel starts, and the command panel.")
        case .appearance: String(localized: "Theme and site icons.")
        case .fill: String(localized: "Filling and copying usernames, passwords and codes.")
        case .security: String(localized: "When your box locks, and when it asks for Touch ID.")
        case .sync: String(localized: "Where your box lives, and the devices that share it.")
        case .backup: String(localized: "An encrypted backup, and passwords from other apps.")
        case .advanced: String(localized: "A self-hosted server, if you run one.")
        case .about: String(localized: "A zero-knowledge password manager for your Mac.")
        }
    }

    /// Sidebar groups below the account row.
    static let main: [SettingsPage] = [.general, .appearance, .fill, .security, .sync, .backup]
    static let more: [SettingsPage] = [.advanced, .about]
}

struct SettingsView: View {
    let service: VaultService
    /// The window's own selection: a launch argument (`-settings.page`) shadows the default and must not pin the sidebar.
    @State private var page = SettingsPage.current

    /// Pages visited before and after this one, for the toolbar's back and forward (like Raycast's settings).
    @State private var back: [SettingsPage] = []
    @State private var forward: [SettingsPage] = []

    var body: some View {
        // The sidebar is always shown: no toggle in the toolbar, and the divider cannot collapse it.
        NavigationSplitView(columnVisibility: .constant(.all)) {
            List(selection: Binding<SettingsPage?>(get: { page }, set: { if let p = $0 { go(to: p) } })) {
                AccountRow().tag(SettingsPage.account)
                Section { ForEach(SettingsPage.main) { SidebarRow(page: $0).tag($0) } }
                Section { ForEach(SettingsPage.more) { SidebarRow(page: $0).tag($0) } }
            }
            .toolbar(removing: .sidebarToggle)
        } detail: {
            Form {
                Section { } header: { PageHeader(page: page) }
                content
            }
                .formStyle(.grouped)
                .navigationTitle(page.title)
                .toolbar(removing: .title)   // the page header says it; the toolbar keeps back and forward
                .id(page)
                .toolbar {
                    ToolbarItemGroup(placement: .navigation) {
                        Button { goBack() } label: { Label("Back", systemImage: "chevron.left") }
                            .help("Back").disabled(back.isEmpty).keyboardShortcut("[", modifiers: .command)
                        Button { goForward() } label: { Label("Forward", systemImage: "chevron.right") }
                            .help("Forward").disabled(forward.isEmpty).keyboardShortcut("]", modifiers: .command)
                    }
                }
        }
        .onReceive(NotificationCenter.default.publisher(for: SettingsPage.showNotification)) { n in
            if let p = n.object as? SettingsPage { go(to: p) }
        }
    }

    private func go(to p: SettingsPage) {
        guard p != page else { return }
        back.append(page)
        forward.removeAll()
        show(p)
    }

    private func goBack() {
        guard let p = back.popLast() else { return }
        forward.append(page)
        show(p)
    }

    private func goForward() {
        guard let p = forward.popLast() else { return }
        back.append(page)
        show(p)
    }

    private func show(_ p: SettingsPage) {
        page = p
        UserDefaults.standard.set(p.rawValue, forKey: SettingsPage.defaultsKey)
    }

    @ViewBuilder private var content: some View {
        switch page {
        case .account: AccountSettings(service: service)
        case .general: GeneralSettings()
        case .appearance: AppearanceSettings()
        case .fill: FillSettings()
        case .security: SecurityPage(service: service)
        case .sync: SyncSettings(service: service)
        case .backup: BackupSettings(service: service)
        case .advanced: AdvancedSettings(service: service)
        case .about: AboutSettings()
        }
    }
}

private struct SidebarRow: View {
    let page: SettingsPage

    var body: some View {
        Label { Text(page.title) } icon: { PageIcon(page: page, size: 22) }
    }
}

/// The page's symbol in white on its color, a rounded square like System Settings' icons.
private struct PageIcon: View {
    let page: SettingsPage
    let size: CGFloat

    var body: some View {
        Image(systemName: page.symbol)
            .font(.system(size: size * 0.55, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(page.tint.gradient, in: RoundedRectangle(cornerRadius: size * 0.27, style: .continuous))
    }
}

/// The top of a page: its icon (the Mac user's picture on Account), its title and a line about it.
private struct PageHeader: View {
    let page: SettingsPage

    var body: some View {
        VStack(spacing: 8) {
            if page == .account {
                UserPictureView().frame(width: 64, height: 64)
            } else {
                PageIcon(page: page, size: 64)
            }
            Text(page == .account ? NSFullUserName() : page.title)
                .font(.system(size: 26, weight: .bold)).foregroundStyle(.primary)
                .padding(.top, 6)
            Text(page.summary).font(.body).foregroundStyle(.secondary)
        }
        .multilineTextAlignment(.center)
        .frame(maxWidth: .infinity)
        .padding(.top, -12)
        .padding(.bottom, 44)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// The Mac user's picture and name, like the account row at the top of System Settings.
private struct AccountRow: View {
    var body: some View {
        HStack(spacing: 10) {
            UserPictureView().frame(width: 32, height: 32)
            VStack(alignment: .leading, spacing: 1) {
                Text(NSFullUserName())
                Text("Account").font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
    }
}

/// The locked box in the settings window: the command panel's locked state. Return unlocks, like in the panel (opening
/// Settings while locked asks for Touch ID right away, see `AppModel.showMainWindow`).
struct SettingsLockedView: View {
    var body: some View {
        BoxLockedState { AppModel.shared.unlockFromSettings() }
            .background {
                Button("") { AppModel.shared.unlockFromSettings() }
                    .keyboardShortcut(.defaultAction).opacity(0).accessibilityHidden(true)
            }
            .navigationTitle("Settings")
    }
}

/// The Mac user's account picture (Users & Groups), or a generic person.
private struct UserPictureView: View {
    var body: some View {
        if let image = UserPicture.image {
            Image(nsImage: image).resizable().scaledToFill().clipShape(Circle())
        } else {
            Image(systemName: "person.crop.circle.fill").resizable().scaledToFit().foregroundStyle(.secondary)
        }
    }
}

@MainActor
enum UserPicture {
    static let image: NSImage? = {
        guard let node = try? ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeLocalNodes)),
              let record = try? node.record(withRecordType: kODRecordTypeUsers, name: NSUserName(),
                                            attributes: [kODAttributeTypeJPEGPhoto, kODAttributeTypePicture])
        else { return nil }
        if let data = (try? record.values(forAttribute: kODAttributeTypeJPEGPhoto))?.first as? Data, let image = NSImage(data: data) {
            return image
        }
        if let path = (try? record.values(forAttribute: kODAttributeTypePicture))?.first as? String { return NSImage(contentsOfFile: path) }
        return nil
    }()
}

// MARK: - Building blocks

/// A form section: an optional header, its rows, and an optional footer for what applies to the whole group (HIG: a note
/// about a group goes below it, not in a row of its own).
struct SettingsSection<Content: View>: View {
    var title: String?
    var footer: String?
    @ViewBuilder var content: Content

    var body: some View {
        Section {
            content
        } header: {
            // Styled explicitly: after the page header the form would draw the first section's title small and gray.
            if let title { Text(title).font(.headline).foregroundStyle(.primary) }
        } footer: {
            if let footer { SettingsNote(footer) }
        }
    }
}

/// One setting: its title, an optional description under it, and its control on the right.
struct SettingsRow<Control: View>: View {
    var label: String
    var detail: String?
    @ViewBuilder var control: Control

    var body: some View {
        LabeledContent {
            control
        } label: {
            Text(label)
            if let detail { Text(detail) }
        }
    }
}

/// An explanation in the form's secondary style (section footers).
struct SettingsNote: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}

/// A menu of numbers ("5 min", "30 s"), saved to `UserDefaults` under `key` when it changes.
struct NumberPicker: View {
    @Binding var value: Int
    var choices = [1, 2, 5, 10, 15, 30]
    var unit = "min"
    var key: String

    var body: some View {
        Picker("", selection: $value) { ForEach(choices, id: \.self) { Text("\($0) \(unit)").tag($0) } }
            .labelsHidden().pickerStyle(.menu).fixedSize()
            .onChange(of: value) { _, v in UserDefaults.standard.set(v, forKey: key) }
    }
}

extension Toggle {
    func settingsSwitch() -> some View { self.labelsHidden().toggleStyle(.switch) }
}
