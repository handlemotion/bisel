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

    /// Sidebar groups below the account row.
    static let main: [SettingsPage] = [.general, .appearance, .fill, .security, .sync, .backup]
    static let more: [SettingsPage] = [.advanced, .about]
}

struct SettingsView: View {
    let service: VaultService
    /// The window's own selection: a launch argument (`-settings.page`) shadows the default and must not pin the sidebar.
    @State private var page = SettingsPage.current

    var body: some View {
        NavigationSplitView {
            List(selection: Binding<SettingsPage?>(get: { page }, set: { if let p = $0 { select(p) } })) {
                AccountRow().tag(SettingsPage.account)
                Section { ForEach(SettingsPage.main) { SidebarRow(page: $0).tag($0) } }
                Section { ForEach(SettingsPage.more) { SidebarRow(page: $0).tag($0) } }
            }
        } detail: {
            Form { content }
                .formStyle(.grouped)
                .navigationTitle(page.title)
                .id(page)
        }
        .onReceive(NotificationCenter.default.publisher(for: SettingsPage.showNotification)) { n in
            if let p = n.object as? SettingsPage { page = p }
        }
    }

    private func select(_ p: SettingsPage) {
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
        Label {
            Text(page.title)
        } icon: {
            Image(systemName: page.symbol)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 22, height: 22)
                .background(page.tint.gradient, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
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
            if let title { Text(title) }
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
