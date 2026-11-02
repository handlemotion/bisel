import SwiftUI

/// The locked box, filling its card: the command panel and Settings show the same one. Return (handled by each surface's
/// key monitor) and the accessibility action unlock with Touch ID.
struct BoxLockedState: View {
    let unlock: () -> Void
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(spacing: theme.spacing.s) {
            Image(systemName: "touchid").font(.system(size: 28)).foregroundStyle(theme.colors.accent.color)
            Text("Box locked").font(theme.font(theme.fonts.detailTitle / 1.5, weight: .semibold))
            Text("Press Return to unlock with Touch ID")
                .font(theme.font(theme.fonts.detail)).foregroundStyle(theme.colors.secondaryText.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { unlock() }
        .accessibilityIdentifier("panel.locked")
    }
}
