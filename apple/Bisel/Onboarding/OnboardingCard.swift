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

/// The onboarding surface IS the window: the command panel's glass (behind-window blur + theme tint) fills it, with a
/// soft accent glow at the top, the mark, a title, a line of copy and the content. No card inside the window.
struct OnboardingCard<Content: View>: View {
    var title: String
    var subtitle: String?
    /// Width of the content column; the window is sized by `OnboardingLayout`.
    var width: CGFloat = 340
    @ViewBuilder var content: Content
    @Environment(\.theme) private var theme

    var body: some View {
        ScrollView {
            VStack(spacing: theme.spacing.l) {
                BrandMark()
                VStack(spacing: theme.spacing.s) {
                    Text(title)
                        .font(theme.font(theme.fonts.detailTitle, weight: .semibold))
                        .multilineTextAlignment(.center)
                        .accessibilityAddTraits(.isHeader)
                    if let subtitle {
                        Text(subtitle)
                            .font(theme.font(theme.fonts.row))
                            .foregroundStyle(theme.colors.secondaryText.color)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                content
            }
            .frame(maxWidth: width)
            .padding(.horizontal, theme.spacing.l * 2)
            .padding(.top, theme.spacing.l * 3)   // clears the traffic lights
            .padding(.bottom, theme.spacing.l * 2)
            .frame(maxWidth: .infinity)
        }
        .scrollBounceBehavior(.basedOnSize)
        .background(
            ZStack(alignment: .top) {
                CardFill()
                RadialGradient(colors: [theme.colors.accent.color.opacity(0.22), theme.colors.accent.color.opacity(0)],
                               center: .top, startRadius: 0, endRadius: 420)
            }
            .ignoresSafeArea()
        )
    }
}

/// Window sizes for the card phases.
enum OnboardingLayout {
    static let setup = NSSize(width: 440, height: 470)
    static let phrase = NSSize(width: 600, height: 660)
    static let locked = NSSize(width: 380, height: 380)
}

/// Full-width pill: primary (white on black in the default theme) or secondary.
struct PillButtonStyle: ButtonStyle {
    var primary = true
    @Environment(\.theme) private var theme
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(theme.font(theme.fonts.row, weight: .semibold))
            .foregroundStyle((primary ? theme.colors.pillPrimaryText : theme.colors.pillSecondaryText).color)
            .frame(maxWidth: .infinity)
            .frame(height: 40)
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
