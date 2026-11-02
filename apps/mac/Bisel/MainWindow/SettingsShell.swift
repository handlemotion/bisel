import KeyboardShortcuts
import OpenDirectory
import SwiftUI
import BiselCore

/// Settings, a floating card like the command panel (same material, radius and border, no traffic lights): an icon rail
/// on the left with a label under each page, the Mac user's picture (the Account page) at its foot, the page on the right.
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
    /// The card: as wide as the command panel, a little taller.
    static let size = NSSize(width: 760, height: 520)
    /// The page column's widest; the column centres in what is left of the card after the rail.
    static let column: CGFloat = 520
    static let rail: CGFloat = 84
    static let railItem = CGSize(width: 64, height: 54)
    static let railGlyph: CGFloat = 18
    static let avatar: CGFloat = 30
    static let cardRadius: CGFloat = 12
}

struct SettingsShell: View {
    let service: VaultService
    @AppStorage(SettingsPage.defaultsKey) private var page = SettingsPage.general
    @Environment(\.theme) private var theme

    var body: some View {
        HStack(spacing: 0) {
            SettingsRail(page: $page).frame(width: SettingsLayout.rail)
            Hairline(axis: .vertical)
            ScrollView {
                VStack(alignment: .leading, spacing: theme.spacing.l) {
                    Text(page.title)
                        .font(theme.font(theme.fonts.detailTitle - 4, weight: .semibold))   // 20 pt
                        .accessibilityAddTraits(.isHeader)
                    content
                }
                .frame(maxWidth: SettingsLayout.column, alignment: .leading)
                .padding(.horizontal, theme.spacing.l * 2)
                .padding(.vertical, theme.spacing.l * 1.75)
                .frame(maxWidth: .infinity)
                .id(page)
                .transition(.opacity)
            }
            .scrollIndicators(.never)
        }
        .animation(.easeInOut(duration: 0.2), value: page)
        .font(theme.font(theme.fonts.detail))
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

private struct SettingsRail: View {
    @Binding var page: SettingsPage
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(spacing: theme.spacing.xs) {
            ForEach(SettingsPage.allCases.filter { $0.icon != nil }) { p in
                RailButton(page: p, selected: page == p) { page = p }
            }
            Spacer(minLength: 0)
            RailButton(page: .account, selected: page == .account) { page = .account }
        }
        .padding(.vertical, theme.spacing.m)
        .frame(maxHeight: .infinity)
    }
}

/// A page glyph over its name, in a rounded tile that fills when hovered or selected. The account page is the Mac user's
/// picture alone, ringed when selected.
private struct RailButton: View {
    let page: SettingsPage
    let selected: Bool
    let action: () -> Void
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Group {
                if let icon = page.icon {
                    VStack(spacing: theme.spacing.xs + 1) {
                        Image(icon).renderingMode(.template).resizable().scaledToFit()
                            .frame(width: SettingsLayout.railGlyph, height: SettingsLayout.railGlyph)
                        Text(page.title).font(theme.font(theme.fonts.caption, weight: .medium))
                    }
                    .foregroundStyle(selected ? theme.colors.text.color : theme.dimColor(theme.colors.secondaryText, glass: glass))
                    .frame(width: SettingsLayout.railItem.width, height: SettingsLayout.railItem.height)
                    .background(RoundedRectangle(cornerRadius: theme.radii.field + 2, style: .continuous).fill(fill))
                } else {
                    UserPictureView()
                        .frame(width: SettingsLayout.avatar, height: SettingsLayout.avatar)
                        .padding(3)
                        .overlay(Circle().strokeBorder(theme.colors.text.color.opacity(selected ? 0.9 : hovering ? 0.35 : 0), lineWidth: 1.5))
                        .frame(width: SettingsLayout.railItem.width, height: SettingsLayout.railItem.height)
                }
            }
            .contentShape(Rectangle())
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

    private var fill: Color {
        if selected { return theme.selectionFill(glass: glass) }
        if hovering { return theme.hoverFill(glass: glass) }
        return .clear
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

/// A group of settings: the selection fill (translucent over glass), 12 pt radius, 16 pt padding, a 13 pt label, then its rows.
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
    func settingsSwitch() -> some View { self.labelsHidden().toggleStyle(.switch).controlSize(.mini) }
}
