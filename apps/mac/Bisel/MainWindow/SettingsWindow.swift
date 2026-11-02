import KeyboardShortcuts
import OpenDirectory
import SwiftUI
import BiselCore

/// The settings window (Figma "Bisel", node 16:2): a standard titled window (system corners and traffic lights) whose
/// background is the command panel's fill, a rail of round page buttons on the left (the selected one lighter), the page
/// centred in a 460 pt column. Text is a size up from the panel's.
enum SettingsPage: String, CaseIterable, Identifiable {
    case general, fill, sync, account
    var id: String { rawValue }
    static let defaultsKey = "settings.page"

    var title: String {
        switch self {
        case .general: String(localized: "General")
        case .fill: String(localized: "Fill")
        case .sync: String(localized: "Sync")
        case .account: String(localized: "Account")
        }
    }

    /// Asset catalog glyph; the account page shows the Mac user's picture instead.
    var icon: String? {
        switch self {
        case .general: "IconSettingsGear1"
        case .fill: "IconAiBotHeadLeaf"
        case .sync: "IconCloudSync"
        case .account: nil
        }
    }
}

enum SettingsLayout {
    /// The whole window, title bar included.
    static let window = NSSize(width: 820, height: 600)
    static let column: CGFloat = 460
    /// Space between the title bar and the rail and page.
    static let top: CGFloat = 16
    static let rail: CGFloat = 32
    static let railGlyph: CGFloat = 18
    static let railGap: CGFloat = 8
    static let avatar: CGFloat = 28
    static let cardRadius: CGFloat = 14
    /// Settings text is this much larger than the command panel's (13 pt body → 15 pt).
    static let textScale = 15.0 / 13.0
    /// Rail fills are the text color over the background: 11% is Figma's #1d1d1d, 37% its #5e5e5e on black.
    static let railOpacity = 0.114
    static let railHoverOpacity = 0.2
    static let railSelectedOpacity = 0.37
}

struct SettingsShell: View {
    let service: VaultService
    @AppStorage(SettingsPage.defaultsKey) private var page = SettingsPage.general
    @Environment(\.theme) private var panelTheme
    private var theme: Theme { panelTheme.scaledText(SettingsLayout.textScale) }

    var body: some View {
        ZStack(alignment: .topLeading) {
            ScrollView {
                VStack(alignment: .leading, spacing: theme.spacing.l) {
                    Text(page.title)
                        .font(theme.font(theme.fonts.detailTitle - 6, weight: .semibold))   // 22 pt
                        .accessibilityAddTraits(.isHeader)
                    content
                }
                .frame(width: SettingsLayout.column, alignment: .leading)
                .padding(.top, SettingsLayout.top)
                .padding(.bottom, theme.spacing.l)
                .frame(maxWidth: .infinity)
                .id(page)
                .transition(.opacity)
            }
            .scrollIndicators(.never)
            SettingsRail(page: $page)
                .padding(.leading, theme.spacing.l - SettingsLayout.railGap)
                .padding(.top, SettingsLayout.top - SettingsLayout.railGap)
        }
        .animation(.easeInOut(duration: 0.2), value: page)
        .font(theme.font(theme.fonts.detail))
        .environment(\.theme, theme)
        .containerBackground(for: .window) { CardFill() }
    }

    @ViewBuilder private var content: some View {
        switch page {
        case .general: GeneralSettings()
        case .fill: FillSettings()
        case .sync: SyncSettings(service: service)
        case .account: AccountSettings(service: service)
        }
    }
}

/// The locked box in the settings window: the command panel's locked state on its fill. Return unlocks, like in the panel
/// (opening Settings while locked asks for Touch ID right away, see `AppModel.showMainWindow`).
struct SettingsLockedView: View {
    var body: some View {
        BoxLockedState { AppModel.shared.unlockFromSettings() }
            .background {
                Button("") { AppModel.shared.unlockFromSettings() }
                    .keyboardShortcut(.defaultAction).opacity(0).accessibilityHidden(true)
            }
            .containerBackground(for: .window) { CardFill() }
    }
}

private struct SettingsRail: View {
    @Binding var page: SettingsPage

    var body: some View {
        VStack(spacing: SettingsLayout.railGap) {
            ForEach(SettingsPage.allCases) { p in RailButton(page: p, selected: page == p) { page = p } }
        }
        .padding(SettingsLayout.railGap)
    }
}

private struct RailButton: View {
    let page: SettingsPage
    let selected: Bool
    let action: () -> Void
    @Environment(\.theme) private var theme
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle().fill(theme.colors.text.color.opacity(fill))
                if let icon = page.icon {
                    Image(icon).renderingMode(.template).resizable().scaledToFit()
                        .frame(width: SettingsLayout.railGlyph, height: SettingsLayout.railGlyph)
                } else {
                    UserPictureView().frame(width: SettingsLayout.avatar, height: SettingsLayout.avatar)
                }
            }
            .frame(width: SettingsLayout.rail, height: SettingsLayout.rail)
            .foregroundStyle(theme.colors.text.color)
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.12), value: hovering)
        .animation(.easeOut(duration: 0.12), value: selected)
        .help(page.title)
        .accessibilityLabel(page.title)
        .accessibilityAddTraits(selected ? .isSelected : [])
        .accessibilityIdentifier("nav-\(page.rawValue)")
    }

    /// The account button has no fill of its own (the picture is the button) until it is hovered or selected.
    private var fill: Double {
        if selected { return SettingsLayout.railSelectedOpacity }
        if hovering { return SettingsLayout.railHoverOpacity }
        return page.icon == nil ? 0 : SettingsLayout.railOpacity
    }
}

/// The Mac user's account picture (Users & Groups), or a generic person.
private struct UserPictureView: View {
    @Environment(\.theme) private var theme
    var body: some View {
        if let image = UserPicture.image {
            Image(nsImage: image).resizable().scaledToFill().clipShape(Circle())
        } else {
            Image(systemName: "person.crop.circle.fill").resizable().scaledToFit()
                .foregroundStyle(theme.colors.secondaryText.color)
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

/// Figma card: #282828 (the selection color; over glass a translucent fill), 14 pt radius, 16 pt padding, a label, then its rows.
struct SettingsCard<Content: View>: View {
    var title: String?
    @ViewBuilder var content: Content
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            if let title { Text(title).font(theme.font(theme.fonts.detail, weight: .medium)) }
            content
        }
        .padding(theme.spacing.l)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: SettingsLayout.cardRadius, style: .continuous).fill(theme.selectionFill(glass: glass)))
    }
}

/// A label on the left, its control on the right.
struct SettingsRow<Control: View>: View {
    var label: String
    @ViewBuilder var control: Control
    @Environment(\.theme) private var theme

    var body: some View {
        HStack(spacing: theme.spacing.s) {
            Text(label).foregroundStyle(theme.colors.secondaryText.color).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: theme.spacing.s)
            control
        }
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
    func settingsSwitch() -> some View { self.labelsHidden().toggleStyle(.switch).controlSize(.small) }
}
