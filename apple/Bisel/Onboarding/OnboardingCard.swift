import SwiftUI

/// The Bisel mark: a square with its top-left corner cut at 45° (a bevelled edge).
struct BevelShape: Shape {
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
    private let theme = Theme.biselDark   // onboarding is always the solid black frame from Figma

    private let inset: CGFloat = 20   // Figma frame padding
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 24) {
                if let progress { ProgressTrack(value: progress) }
                VStack(alignment: .leading, spacing: theme.spacing.m) {
                    Text(title)
                        .font(theme.font(theme.fonts.detailTitle - 4))
                        .accessibilityAddTraits(.isHeader)
                    if let message {
                        Text(message)
                            .font(theme.font(theme.fonts.search))
                            .lineSpacing(4)
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
        .background(theme.colors.background.color)
        .foregroundStyle(theme.colors.text.color)
        .environment(\.theme, theme)
        .preferredColorScheme(.dark)
        .ignoresSafeArea()
    }
}

/// One line of the welcome list: a 20 pt icon centred on a line of copy.
struct OnboardingRow: View {
    var icon: String
    var text: String
    @Environment(\.theme) private var theme

    var body: some View {
        HStack(spacing: theme.spacing.l) {
            Image(icon).renderingMode(.template).resizable().scaledToFit().frame(width: 20, height: 20)
            Text(text).font(theme.font(theme.fonts.search))
            Spacer(minLength: 0)
        }
        .foregroundStyle(theme.colors.secondaryText.color)
    }
}

/// 8 pt pill track (pill secondary) with the progress fill.
struct ProgressTrack: View {
    var value: Double
    @Environment(\.theme) private var theme

    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(theme.colors.pillSecondary.color)
                Capsule().fill((theme.colors.progress ?? theme.colors.accent).color)
                    .frame(width: g.size.width * max(0, min(1, value)))
            }
        }
        .frame(height: 8)
        .animation(.easeInOut(duration: 0.25), value: value)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Set-up progress")
        .accessibilityValue("\(Int(value * 100)) percent")
    }
}

/// Window sizes for the card phases.
enum OnboardingLayout {
    static let setup = NSSize(width: 646, height: 420)   // Figma frame is 646 wide
    static let phrase = NSSize(width: 646, height: 580)
    static let locked = NSSize(width: 560, height: 280)
}

/// Figma pill: 36 pt high, hugs its label, 14 pt. Primary (white) or secondary (#282828). Lifts a little on hover.
struct PillButtonStyle: ButtonStyle {
    var primary = true

    func makeBody(configuration: Configuration) -> some View {
        PillBody(configuration: configuration, primary: primary)
    }

    private struct PillBody: View {
        let configuration: ButtonStyleConfiguration
        let primary: Bool
        @Environment(\.theme) private var theme
        @Environment(\.isEnabled) private var enabled
        @State private var hovering = false

        var body: some View {
            let fill = (primary ? theme.colors.pillPrimary : theme.colors.pillSecondary).color
            let label = (primary ? theme.colors.pillPrimaryText : theme.colors.pillSecondaryText).color
            configuration.label
                .font(theme.font(theme.fonts.row))
                .foregroundStyle(label)
                .padding(.bottom, 2)   // the line box carries descender space, so cap-height text reads low; lifts it 1 pt
                .padding(.horizontal, primary ? 12 : 14)
                .frame(height: 36)
                .background(Capsule().fill(fill))
                .overlay(Capsule().fill((primary ? Color.black : Color.white).opacity(hovering && enabled ? (primary ? 0.10 : 0.12) : 0)))
                .opacity(enabled ? (configuration.isPressed ? 0.75 : 1) : 0.4)
                .contentShape(Capsule())
                .onHover { hovering = $0 }
                .animation(.easeOut(duration: 0.12), value: hovering)
        }
    }
}

/// The glyph Figma puts in front of "Connect to Box": a 14 pt square with only the top-left corner rounded.
struct PillGlyph: View {
    @Environment(\.theme) private var theme
    var body: some View {
        UnevenRoundedRectangle(topLeadingRadius: 14)
            .fill(theme.colors.pillPrimaryText.color.opacity(0.15))
            .frame(width: 14, height: 14)
            .accessibilityHidden(true)
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
