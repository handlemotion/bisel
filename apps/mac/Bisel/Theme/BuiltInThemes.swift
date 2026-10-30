import Foundation

/// Built-in theme families, each with a light and a dark variant. "Bisel" is the default; its dark variant is the
/// Figma design (760×460 card (Figma 575×406, widened), 260 pt list column, #1b1b1b hairlines, #282828 selection; placeholder/labels lifted from Figma #393939 to #767676 for WCAG AA, see FILL-MATRIX/SPEC §8 Accessibility).
extension Theme {
    static let all: [Theme] = [biselDark, biselLight, emberDark, emberLight]

    private static let scale = Spacing(xs: 4, s: 8, m: 12, l: 16)

    private static let card = Card(
        width: 760, height: 460, topBarHeight: 48, listWidth: 260, rowHeight: 48, iconSize: 24,
        searchIconBox: 24, searchGlyph: 20, pillHeight: 28, pillGap: 10, pillLeading: 9, pillTrailing: 12, hairline: 1,
        blockGap: 24, iconTitleGap: 18, valuesLabelGap: 14, valueRowHeight: 40, ringSize: 16, ringStroke: 2.5)

    private static func fonts(_ design: Fonts.Design) -> Fonts {
        Fonts(design: design, search: 15, row: 14, detailTitle: 24, detail: 13, pill: 13, pillIcon: 15,
              valuesLabel: 12, value: 13, caption: 11, title: 13, subtitle: 12)
    }

    static let biselDark = Theme(
        id: "bisel.dark", family: "bisel", name: "Bisel", appearance: .dark,
        colors: .init(
            background: "#000000", border: "#1B1B1B",
            text: "#FFFFFF", secondaryText: "#FFFFFF99", tertiaryText: "#FFFFFF80", placeholder: "#767676", valueLabel: "#767676", rowHover: "#101010", ring: "#424242",
            selection: "#282828", accent: "#7AA2FF", accentText: "#0B1020",
            pillPrimary: "#FFFFFF", pillPrimaryText: "#000000", pillSecondary: "#282828", pillSecondaryText: "#FFFFFF",
            iconTile: "#FFFFFF", badge: "#FFFFFF1F", field: "#FFFFFF0F", success: "#30D158", warning: "#FFD60A", danger: "#FF453A", progress: "#84FF00"),
        radii: .init(card: 24, icon: 6, field: 8, badge: 4, valuesCard: 8),
        spacing: scale, fonts: fonts(.standard), card: card,
        glass: .init(material: .hud, tintOpacity: 0.40, selectionOpacity: 0.14, pillOpacity: 0.14, hoverOpacity: 0.06, borderOpacity: 0.12))

    /// Mirror of the dark design: white card, near-white selection, light-gray hairlines, inverted pills.
    static let biselLight = Theme(
        id: "bisel.light", family: "bisel", name: "Bisel", appearance: .light,
        colors: .init(
            background: "#FFFFFF", border: "#E8E8E8",
            text: "#000000", secondaryText: "#00000099", tertiaryText: "#00000094", placeholder: "#767676", valueLabel: "#767676", rowHover: "#FAFAFA", ring: "#C4C4C4",
            selection: "#F2F2F2", accent: "#2F5BFF", accentText: "#FFFFFF",
            pillPrimary: "#000000", pillPrimaryText: "#FFFFFF", pillSecondary: "#F2F2F2", pillSecondaryText: "#000000",
            iconTile: "#F2F2F2", badge: "#0000000F", field: "#0000000A", success: "#1E9E45", warning: "#C28A00", danger: "#D92D20", progress: "#4FB300"),
        radii: .init(card: 24, icon: 6, field: 8, badge: 4, valuesCard: 8),
        spacing: scale, fonts: fonts(.standard), card: card,
        glass: .init(material: .popover, tintOpacity: 0.45, selectionOpacity: 0.08, pillOpacity: 0.08, hoverOpacity: 0.04, borderOpacity: 0.10))

    /// Third family: warm, rounded type, tighter card radius.
    static let emberDark = Theme(
        id: "ember.dark", family: "ember", name: "Ember", appearance: .dark,
        colors: .init(
            background: "#1E120C", border: "#3A241A",
            text: "#FFF1E6", secondaryText: "#FFF1E699", tertiaryText: "#FFF1E688", placeholder: "#947969", valueLabel: "#947969", rowHover: "#281811", ring: "#8A604B",
            selection: "#33201A", accent: "#FF8A4C", accentText: "#2A1204",
            pillPrimary: "#FF8A4C", pillPrimaryText: "#2A1204", pillSecondary: "#33201A", pillSecondaryText: "#FFF1E6",
            iconTile: "#FFF1E6", badge: "#FF8A4C2E", field: "#FFD2B012", success: "#4CD964", warning: "#FFD166", danger: "#FF5A4D"),
        radii: .init(card: 14, icon: 6, field: 6, badge: 4, valuesCard: 8),
        spacing: scale, fonts: fonts(.rounded), card: card,
        glass: .init(material: .hud, tintOpacity: 0.42, selectionOpacity: 0.14, pillOpacity: 0.14, hoverOpacity: 0.06, borderOpacity: 0.14))

    static let emberLight = Theme(
        id: "ember.light", family: "ember", name: "Ember", appearance: .light,
        colors: .init(
            background: "#FFF9F3", border: "#F0DCCB",
            text: "#2A1710", secondaryText: "#2A17109E", tertiaryText: "#2A1710A6", placeholder: "#846F62", valueLabel: "#846F62", rowHover: "#FDF3EA", ring: "#E0B99C",
            selection: "#FBEADB", accent: "#C44F0C", accentText: "#FFFFFF",
            pillPrimary: "#C44F0C", pillPrimaryText: "#FFFFFF", pillSecondary: "#FBEADB", pillSecondaryText: "#2A1710",
            iconTile: "#FBEADB", badge: "#D9560F1F", field: "#2A17100D", success: "#2E9E4F", warning: "#B7791F", danger: "#C62828"),
        radii: .init(card: 14, icon: 6, field: 6, badge: 4, valuesCard: 8),
        spacing: scale, fonts: fonts(.rounded), card: card,
        glass: .init(material: .popover, tintOpacity: 0.48, selectionOpacity: 0.08, pillOpacity: 0.08, hoverOpacity: 0.04, borderOpacity: 0.10))
}
