import SwiftUI

/// The Bisel mark: a chamfered square (a bevelled edge) on the primary pill color. Stands in until the final app icon.
struct BrandMark: View {
    var size: CGFloat = 64
    @Environment(\.theme) private var theme

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
            .fill(theme.colors.pillPrimary.color)
            .frame(width: size, height: size)
            .overlay(
                Bevel()
                    .fill(theme.colors.pillPrimaryText.color)
                    .frame(width: size * 0.42, height: size * 0.42)
            )
            .shadow(color: theme.colors.accent.color.opacity(0.45), radius: size * 0.35, y: size * 0.08)
            .accessibilityHidden(true)
    }

    /// Square with the top-left corner cut at 45°.
    private struct Bevel: Shape {
        func path(in r: CGRect) -> Path {
            let c = r.width * 0.38
            var p = Path()
            p.move(to: CGPoint(x: r.minX + c, y: r.minY))
            p.addLine(to: CGPoint(x: r.maxX, y: r.minY))
            p.addLine(to: CGPoint(x: r.maxX, y: r.maxY))
            p.addLine(to: CGPoint(x: r.minX, y: r.maxY))
            p.addLine(to: CGPoint(x: r.minX, y: r.minY + c))
            p.closeSubpath()
            return p
        }
    }
}

/// The onboarding screens (Figma "Bisel", node 8:2): the window is the surface, filled like the command panel (glass, or
/// solid with the Material setting). Progress bar on top, title and message, the step's content, and the actions pinned
/// bottom-left. No traffic lights; the window closes from the Dock.
struct OnboardingFrame<Content: View, Actions: View>: View {
    /// 0...1, or nil for screens that are not part of the set-up route (lock screen).
    var progress: Double?
    var title: String
    var message: String?
    @ViewBuilder var content: Content
    @ViewBuilder var actions: Actions
    @Environment(\.theme) private var theme

    private let inset: CGFloat = 20   // Figma frame padding
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 24) {
                if let progress { ProgressTrack(value: progress) }
                VStack(alignment: .leading, spacing: theme.spacing.l) {
                    Text(title)
                        .font(theme.font(theme.fonts.detailTitle))
                        .accessibilityAddTraits(.isHeader)
                    if let message {
                        // Figma body is 17 pt, a step above the search field size.
                        Text(message)
                            .font(theme.font(theme.fonts.search + 2))
                            .lineSpacing(3)
                            .foregroundStyle(theme.colors.secondaryText.color)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            ScrollView {
                content
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, theme.spacing.l)
            }
            .scrollBounceBehavior(.basedOnSize)
            .scrollIndicators(.never)
            HStack(spacing: theme.spacing.m) { actions }
                .padding(.top, theme.spacing.l)
        }
        .padding(inset)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(CardFill())
        .overlay(RoundedRectangle(cornerRadius: theme.radii.card, style: .continuous)
            .strokeBorder(theme.colors.border.color, lineWidth: theme.card.hairline).allowsHitTesting(false))
        .ignoresSafeArea()
    }
}

/// 6 pt track (pill secondary) with the progress fill, 2 pt corners.
struct ProgressTrack: View {
    var value: Double
    @Environment(\.theme) private var theme

    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                RoundedRectangle(cornerRadius: 2).fill(theme.colors.pillSecondary.color)
                RoundedRectangle(cornerRadius: 2).fill((theme.colors.progress ?? theme.colors.accent).color)
                    .frame(width: g.size.width * max(0, min(1, value)))
            }
        }
        .frame(height: 6)
        .animation(.easeInOut(duration: 0.25), value: value)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Set-up progress")
        .accessibilityValue("\(Int(value * 100)) percent")
    }
}

/// Window sizes for the card phases.
enum OnboardingLayout {
    static let setup = NSSize(width: 400, height: 560)
    static let phrase = NSSize(width: 420, height: 700)
    static let locked = NSSize(width: 400, height: 300)
}

/// Figma pill: 36 pt high, hugs its label, 14 pt. Primary (white) or secondary (#282828).
struct PillButtonStyle: ButtonStyle {
    var primary = true
    @Environment(\.theme) private var theme
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(theme.font(theme.fonts.row))
            .foregroundStyle((primary ? theme.colors.pillPrimaryText : theme.colors.pillSecondaryText).color)
            .padding(.horizontal, primary ? 12 : 14)
            .frame(height: 36)
            .background(Capsule().fill((primary ? theme.colors.pillPrimary : theme.colors.pillSecondary).color))
            .opacity(enabled ? (configuration.isPressed ? 0.8 : 1) : 0.4)
            .contentShape(Capsule())
    }
}

extension View {
    /// Text field chrome that matches the card: field fill, hairline border, field radius.
    func onboardingField(_ theme: Theme) -> some View {
        self.textFieldStyle(.plain)
            .font(theme.font(theme.fonts.detail))
            .padding(.horizontal, theme.spacing.m)
            .frame(height: 38)
            .background(RoundedRectangle(cornerRadius: theme.radii.field + 2, style: .continuous).fill(theme.colors.field.color))
            .overlay(RoundedRectangle(cornerRadius: theme.radii.field + 2, style: .continuous)
                .strokeBorder(theme.colors.border.color, lineWidth: theme.card.hairline))
    }
}
