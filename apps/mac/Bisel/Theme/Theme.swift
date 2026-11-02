import SwiftUI

/// Every visual in bisel comes from a `Theme` (SPEC.md §8 Theming). Views read `@Environment(\.theme)` and never
/// hard-code a color, radius, spacing, font size or metric. Themes are plain Codable values so they can be loaded
/// from JSON files in `~/Library/Application Support/bisel/themes/` (see `ThemeStore`).
struct Theme: Codable, Hashable, Identifiable, Sendable {
    /// Unique id, e.g. "bisel.dark".
    var id: String
    /// A family pairs a light and a dark variant (same `family`, different `appearance`); the store picks the variant
    /// matching the system appearance. A family with a single variant is used as-is.
    var family: String
    var name: String
    var appearance: Appearance
    var colors: Colors
    var radii: Radii
    /// One spacing scale used for every inset and gap.
    var spacing: Spacing
    var fonts: Fonts
    /// Fixed geometry of the command panel card.
    var card: Card
    /// Glass material used when the Material setting is "glass" (the default); "solid" paints `colors.background`.
    var glass: Glass
    /// Set by `adjusted(for:)` when the system's Increase Contrast is on. Runtime state, never part of a theme file.
    var increaseContrast = false

    private enum CodingKeys: String, CodingKey { case id, family, name, appearance, colors, radii, spacing, fonts, card, glass }

    enum Appearance: String, Codable, Sendable { case light, dark }

    struct Colors: Codable, Hashable, Sendable {
        /// Card background (opaque).
        var background: HexColor
        /// 1 pt card border and every 1 pt separator inside the card.
        var border: HexColor
        var text: HexColor
        var secondaryText: HexColor
        var tertiaryText: HexColor
        /// Search placeholder.
        var placeholder: HexColor
        /// Labels in the Values card (OTP, Username, …).
        var valueLabel: HexColor
        /// Subtle hover tint of a Values row.
        var rowHover: HexColor
        /// Countdown ring around the live OTP.
        var ring: HexColor
        /// Selected / hovered row.
        var selection: HexColor
        var accent: HexColor
        var accentText: HexColor
        /// Primary pill (Fill) and its label.
        var pillPrimary: HexColor
        var pillPrimaryText: HexColor
        /// Secondary pills (Copy …) and their label.
        var pillSecondary: HexColor
        var pillSecondaryText: HexColor
        /// Backing tile behind a loaded site icon (icons are often dark-on-transparent).
        var iconTile: HexColor
        /// Keycaps and small chips.
        var badge: HexColor
        var field: HexColor
        /// Semantic colors. The OTP ring runs success → warning → danger as the code expires.
        var success: HexColor
        var warning: HexColor
        var danger: HexColor
        /// Onboarding progress bar fill. Optional so theme files written before it existed keep loading (falls back to `accent`).
        var progress: HexColor?
    }

    struct Radii: Codable, Hashable, Sendable {
        /// Card corner radius.
        var card: Double
        /// Rounded-square icon (favicon / monogram).
        var icon: Double
        var field: Double
        var badge: Double
        /// The bordered Values card.
        var valuesCard: Double
    }

    /// xs 4 / s 8 / m 12 / l 16. (Pill gap 10 and pill side paddings 9/12 come from `Card`.)
    struct Spacing: Codable, Hashable, Sendable {
        var xs: Double
        var s: Double
        var m: Double
        var l: Double
    }

    struct Fonts: Codable, Hashable, Sendable {
        enum Design: String, Codable, Sendable { case standard, rounded, serif, monospaced }
        var design: Design
        var search: Double
        var row: Double
        var detailTitle: Double
        var detail: Double
        var pill: Double
        var pillIcon: Double
        var valuesLabel: Double
        var value: Double
        var caption: Double
        /// Used by toasts and the onboarding window.
        var title: Double
        var subtitle: Double
    }

    struct Glass: Codable, Hashable, Sendable {
        enum Material: String, Codable, Sendable { case hud, popover, menu, sidebar, underWindow, fullScreenUI, sheet }
        /// NSVisualEffectView material (behind-window blur). hud / sheet are the thickest.
        var material: Material
        /// 0...1 opacity of `colors.background` laid over the blur for contrast. High enough that nothing behind is legible.
        var tintOpacity: Double
        /// Over glass the opaque selection/pill/hover/border colors become translucent fills of the text color, so the
        /// wallpaper keeps bleeding through (like the macOS reference). Opacities of `colors.text`.
        var selectionOpacity: Double
        var pillOpacity: Double
        var hoverOpacity: Double
        var borderOpacity: Double
    }

    struct Card: Codable, Hashable, Sendable {
        var width: Double
        var height: Double
        var topBarHeight: Double
        var listWidth: Double
        var rowHeight: Double
        var iconSize: Double
        var searchIconBox: Double
        var searchGlyph: Double
        var pillHeight: Double
        var pillGap: Double
        var pillLeading: Double
        var pillTrailing: Double
        var hairline: Double
        /// Detail pane: gap between the icon/title, pill and Values blocks.
        var blockGap: Double
        /// Gap between the icon and the title, and between the Values label and its card.
        var iconTitleGap: Double
        var valuesLabelGap: Double
        var valueRowHeight: Double
        var ringSize: Double
        var ringStroke: Double
    }
}

/// `#RRGGBB` or `#RRGGBBAA` in JSON.
struct HexColor: Codable, Hashable, Sendable, ExpressibleByStringLiteral {
    var rgba: UInt32

    init(stringLiteral value: String) { self.rgba = Self.parse(value) ?? 0xFF00FFFF }
    init(rgba: UInt32) { self.rgba = rgba }

    init(from decoder: Decoder) throws {
        let s = try decoder.singleValueContainer().decode(String.self)
        guard let v = Self.parse(s) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Bad color \(s)"))
        }
        rgba = v
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(String(format: "#%08X", rgba))
    }

    static func parse(_ raw: String) -> UInt32? {
        var s = raw.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("#") { s.removeFirst() }
        guard s.count == 6 || s.count == 8, let v = UInt32(s, radix: 16) else { return nil }
        return s.count == 6 ? (v << 8) | 0xFF : v
    }

    var color: Color {
        Color(.sRGB,
              red: Double((rgba >> 24) & 0xFF) / 255,
              green: Double((rgba >> 16) & 0xFF) / 255,
              blue: Double((rgba >> 8) & 0xFF) / 255,
              opacity: Double(rgba & 0xFF) / 255)
    }
}

extension Theme {
    func font(_ size: Double, weight: Font.Weight = .regular) -> Font {
        let design: Font.Design = switch fonts.design {
        case .standard: .default
        case .rounded: .rounded
        case .serif: .serif
        case .monospaced: .monospaced
        }
        return .system(size: size, weight: weight, design: design)
    }

    var colorScheme: ColorScheme { appearance == .dark ? .dark : .light }
}

private struct ThemeKey: EnvironmentKey { static let defaultValue = Theme.biselDark }
extension EnvironmentValues {
    var theme: Theme {
        get { self[ThemeKey.self] }
        set { self[ThemeKey.self] = newValue }
    }
}

/// True when the panel material setting is "glass": views swap the solid fills for translucent ones.
private struct GlassModeKey: EnvironmentKey { static let defaultValue = true }
extension EnvironmentValues {
    var glassMode: Bool {
        get { self[GlassModeKey.self] }
        set { self[GlassModeKey.self] = newValue }
    }
}

extension Theme {
    func selectionFill(glass: Bool) -> Color { glass ? colors.text.color.opacity(self.glass.selectionOpacity) : colors.selection.color }
    func pillSecondaryFill(glass: Bool) -> Color { glass ? colors.text.color.opacity(self.glass.pillOpacity) : colors.pillSecondary.color }
    func hoverFill(glass: Bool) -> Color { glass ? colors.text.color.opacity(self.glass.hoverOpacity) : colors.rowHover.color }
    /// Dim label / placeholder colors: the theme's solid color; over glass a dimmed text color. Both clear WCAG AA
    /// 4.5:1 (SPEC.md §8 Accessibility); Increase Contrast lifts them further.
    func dimColor(_ solid: HexColor, glass: Bool) -> Color { glass ? colors.text.color.opacity(dimOpacity) : solid.color }
    var dimOpacity: Double { increaseContrast ? 0.80 : (appearance == .dark ? 0.55 : 0.64) }
    func borderColor(glass: Bool) -> Color { glass ? colors.text.color.opacity(self.glass.borderOpacity) : colors.border.color }
}

// MARK: - system accessibility settings

/// The user's system display-accessibility switches that change how the panel is drawn.
struct AccessibilityPreferences: Equatable, Sendable {
    var reduceMotion = false
    var reduceTransparency = false
    var increaseContrast = false
    var differentiateWithoutColor = false
}

private struct AccessibilityPreferencesKey: EnvironmentKey { static let defaultValue = AccessibilityPreferences() }
extension EnvironmentValues {
    var accessibilityPreferences: AccessibilityPreferences {
        get { self[AccessibilityPreferencesKey.self] }
        set { self[AccessibilityPreferencesKey.self] = newValue }
    }
}

extension HexColor {
    var alpha: Double { Double(rgba & 0xFF) / 255 }

    /// Moves the RGB channels `fraction` of the way toward `other`, keeping this color's alpha.
    func mixed(with other: HexColor, _ fraction: Double) -> HexColor {
        func channel(_ shift: UInt32) -> UInt32 {
            let a = Double((rgba >> shift) & 0xFF), b = Double((other.rgba >> shift) & 0xFF)
            return UInt32((a + (b - a) * fraction).rounded())
        }
        return HexColor(rgba: channel(24) << 24 | channel(16) << 16 | channel(8) << 8 | (rgba & 0xFF))
    }

    func withAlpha(_ a: Double) -> HexColor { HexColor(rgba: (rgba & 0xFFFF_FF00) | UInt32((min(max(a, 0), 1) * 255).rounded())) }
}

extension Theme {
    /// Increase Contrast: stronger borders, separators, ring track, selection and dim text, same hues and layout.
    func adjusted(for prefs: AccessibilityPreferences) -> Theme {
        guard prefs.increaseContrast else { return self }
        var t = self
        let text = colors.text
        t.increaseContrast = true
        t.colors.border = colors.border.mixed(with: text, 0.55)
        t.colors.valueLabel = colors.valueLabel.mixed(with: text, 0.45)
        t.colors.placeholder = colors.placeholder.mixed(with: text, 0.45)
        t.colors.secondaryText = colors.secondaryText.withAlpha(0.88)
        t.colors.tertiaryText = colors.tertiaryText.withAlpha(0.78)
        t.colors.ring = colors.ring.mixed(with: text, 0.45)
        t.colors.selection = colors.selection.mixed(with: text, 0.14)
        t.colors.rowHover = colors.rowHover.mixed(with: text, 0.10)
        t.colors.pillSecondary = colors.pillSecondary.mixed(with: text, 0.10)
        t.colors.badge = colors.badge.withAlpha(min(colors.badge.alpha + 0.12, 1))
        t.glass.borderOpacity = max(glass.borderOpacity, 0.45)
        t.glass.selectionOpacity = glass.selectionOpacity + 0.10
        t.glass.hoverOpacity = glass.hoverOpacity + 0.05
        t.glass.pillOpacity = glass.pillOpacity + 0.08
        t.glass.tintOpacity = max(glass.tintOpacity, 0.70)
        return t
    }
}
