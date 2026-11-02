import KeyboardShortcuts
import SwiftUI
import BiselCore

/// The settings window: a standard titled window (the system's corners and traffic lights) on the theme's background,
/// which follows the Mac's light/dark appearance. One scrolling page, its sections in a 480 pt column; text is a size up
/// from the command panel's.
enum SettingsPage: String, CaseIterable, Identifiable {
    case general, fill, sync, account
    var id: String { rawValue }
    /// The section to scroll to when Settings opens (`AppModel.showSettings`).
    static let defaultsKey = "settings.page"
    static let scrollNotification = Notification.Name("app.bisel.settings.scroll")

    var title: String {
        switch self {
        case .general: String(localized: "General")
        case .fill: String(localized: "Fill")
        case .sync: String(localized: "Sync")
        case .account: String(localized: "Account")
        }
    }

    static var current: SettingsPage {
        UserDefaults.standard.string(forKey: defaultsKey).flatMap(SettingsPage.init(rawValue:)) ?? .general
    }
}

enum SettingsLayout {
    /// The whole window, title bar included.
    static let window = NSSize(width: 640, height: 640)
    static let column: CGFloat = 480
    static let cardRadius: CGFloat = 14
    /// Settings text is this much larger than the command panel's (13 pt body → 15 pt).
    static let textScale = 15.0 / 13.0
}

struct SettingsShell: View {
    let service: VaultService
    @Environment(\.theme) private var panelTheme
    private var theme: Theme { panelTheme.scaledText(SettingsLayout.textScale) }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: theme.spacing.l * 2) {
                    ForEach(SettingsPage.allCases) { page in
                        VStack(alignment: .leading, spacing: theme.spacing.m) {
                            Text(page.title)
                                .font(theme.font(theme.fonts.detailTitle - 6, weight: .semibold))   // 22 pt
                                .accessibilityAddTraits(.isHeader)
                            section(page)
                        }
                        .padding(.top, theme.spacing.s)
                        .id(page)   // scrolled to with this margin above its title
                    }
                }
                .frame(width: SettingsLayout.column, alignment: .leading)
                .padding(.bottom, theme.spacing.l)
                .frame(maxWidth: .infinity)
            }
            .onAppear { proxy.scrollTo(SettingsPage.current, anchor: .top) }
            .onReceive(NotificationCenter.default.publisher(for: SettingsPage.scrollNotification)) { _ in
                withAnimation(.easeInOut(duration: 0.25)) { proxy.scrollTo(SettingsPage.current, anchor: .top) }
            }
        }
        .font(theme.font(theme.fonts.detail))
        .environment(\.theme, theme)
        .environment(\.glassMode, false)
        .containerBackground(theme.colors.background.color, for: .window)
    }

    @ViewBuilder private func section(_ page: SettingsPage) -> some View {
        switch page {
        case .general: GeneralSettings()
        case .fill: FillSettings()
        case .sync: SyncSettings(service: service)
        case .account: AccountSettings(service: service)
        }
    }
}

/// The locked box in the settings window: the command panel's locked state. Return unlocks, like in the panel (opening
/// Settings while locked asks for Touch ID right away, see `AppModel.showMainWindow`).
struct SettingsLockedView: View {
    @Environment(\.theme) private var theme

    var body: some View {
        BoxLockedState { AppModel.shared.unlockFromSettings() }
            .background {
                Button("") { AppModel.shared.unlockFromSettings() }
                    .keyboardShortcut(.defaultAction).opacity(0).accessibilityHidden(true)
            }
            .environment(\.glassMode, false)
            .containerBackground(theme.colors.background.color, for: .window)
    }
}

// MARK: - Building blocks

/// Figma card: #282828 (the selection color), 14 pt radius, 16 pt padding, a label, then its rows.
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
