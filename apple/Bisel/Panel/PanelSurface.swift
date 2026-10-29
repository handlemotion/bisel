import AppKit
import SwiftUI

/// "Material" setting: glass (default) or solid.
enum PanelMaterial: String, CaseIterable, Identifiable {
    case glass, solid
    var id: String { rawValue }
    var label: String { self == .glass ? String(localized: "Glass") : String(localized: "Solid") }
    static let defaultsKey = "panel.material"
    static var current: PanelMaterial {
        UserDefaults.standard.string(forKey: defaultsKey).flatMap(PanelMaterial.init(rawValue:)) ?? .glass
    }
}

/// Card fill. Glass: behind-window blur (thick material) + a theme-colored tint strong enough that nothing behind is
/// legible. Solid: the opaque theme background (the Figma pitch-black / white).
struct CardFill: View {
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass

    var body: some View {
        if !glass {
            theme.colors.background.color
        } else {
            ZStack {
                VisualEffectView(material: theme.glass.material.nsMaterial, dark: theme.appearance == .dark)
                theme.colors.background.color.opacity(theme.glass.tintOpacity)
            }
        }
    }
}

extension View {
    /// Resolves the Material setting and Reduce Transparency into `glassMode` for everything below: glass only when
    /// the setting says glass and the system has not asked for less transparency (then the solid fill is used).
    func panelMaterial() -> some View { modifier(PanelMaterialModifier()) }
}

private struct PanelMaterialModifier: ViewModifier {
    @AppStorage(PanelMaterial.defaultsKey) private var material = PanelMaterial.glass.rawValue
    @Environment(\.accessibilityPreferences) private var prefs

    func body(content: Content) -> some View {
        content.environment(\.glassMode, material != PanelMaterial.solid.rawValue && !prefs.reduceTransparency)
    }
}

/// Card chrome for small surfaces (toasts): same fill + 1 pt border + card radius.
struct CardSurface: View {
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass
    var body: some View {
        let shape = RoundedRectangle(cornerRadius: theme.radii.card, style: .continuous)
        CardFill().clipShape(shape)
            .overlay(shape.strokeBorder(theme.borderColor(glass: glass), lineWidth: theme.card.hairline))
            .allowsHitTesting(false)
    }
}

/// 1 pt separator in the theme's border color.
struct Hairline: View {
    enum Axis { case horizontal, vertical }
    var axis: Axis = .horizontal
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass
    var body: some View {
        Rectangle().fill(theme.borderColor(glass: glass))
            .frame(width: axis == .vertical ? theme.card.hairline : nil, height: axis == .horizontal ? theme.card.hairline : nil)
    }
}

extension Theme.Glass.Material {
    var nsMaterial: NSVisualEffectView.Material {
        switch self {
        case .hud: .hudWindow
        case .popover: .popover
        case .menu: .menu
        case .sidebar: .sidebar
        case .underWindow: .underWindowBackground
        case .fullScreenUI: .fullScreenUI
        case .sheet: .sheet
        }
    }
}

struct VisualEffectView: NSViewRepresentable {
    var material: NSVisualEffectView.Material
    var dark: Bool

    func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.blendingMode = .behindWindow
        v.state = .active  // the panel never becomes the active app; keep the effect live
        return v
    }

    func updateNSView(_ v: NSVisualEffectView, context: Context) {
        v.material = material
        v.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
    }
}
