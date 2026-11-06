import LocalAuthentication
import LocalAuthenticationEmbeddedUI
import SwiftUI

/// The locked box, filling its card: the command panel and Settings show the same one. With a `context` it is waiting for a finger,
/// and Touch ID shows here rather than in a system sheet. Return (handled by each surface's key monitor) and the accessibility
/// action unlock, or try again.
struct BoxLockedState: View {
    var context: LAContext?
    var ready: (LAContext) -> Void = { _ in }
    let unlock: () -> Void
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(spacing: theme.spacing.s) {
            if let context {
                TouchIDView(context: context, ready: ready).frame(width: 28, height: 28).id(ObjectIdentifier(context))
            } else {
                Image(systemName: "touchid").font(.system(size: 28)).foregroundStyle(theme.colors.accent.color)
            }
            Text("Box locked").font(theme.font(theme.fonts.detailTitle / 1.5, weight: .semibold))
            Text(context == nil ? "Press Return to unlock with Touch ID" : "Touch the sensor to unlock")
                .font(theme.font(theme.fonts.detail)).foregroundStyle(theme.colors.secondaryText.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { unlock() }
        .accessibilityIdentifier("panel.locked")
    }
}

/// `LAAuthenticationView` must be paired before the context is evaluated, so `ready` runs only once it exists.
private struct TouchIDView: NSViewRepresentable {
    let context: LAContext
    let ready: (LAContext) -> Void

    func makeNSView(context _: Context) -> LAAuthenticationView {
        let view = LAAuthenticationView(context: context, controlSize: .regular)
        DispatchQueue.main.async { [context, ready] in ready(context) }
        return view
    }

    func updateNSView(_: LAAuthenticationView, context _: Context) {}
}
