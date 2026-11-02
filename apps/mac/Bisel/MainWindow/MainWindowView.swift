import KeyboardShortcuts
import SwiftUI
import BiselCore

struct MainWindowView: View {
    /// Set-up and the recovery phrase (dark glass cards), then Settings (a native window); the command panel (⌘⇧Space) is
    /// the way into the box.
    private let service = AppModel.shared.service
    /// After the recovery phrase of a new box: one last onboarding step to import passwords.
    @State private var showImport = false
    /// Between the phrase and the import: the Accessibility step, only while the permission is off.
    @State private var showAccess = false
    /// The titlebar's height, measured from the window: the scene sizes the content area, the titlebar comes on top of it,
    /// so the island's frame is its height minus this.
    @State private var titlebarInset: CGFloat = 32
    @State private var styled = StyledWindow()
    @Environment(\.dismissWindow) private var dismissWindow
    @Environment(\.theme) private var theme

    var body: some View {
        // Screens cross-fade in place (a ZStack, so they never share layout), over a solid black backing in the card phases
        // so nothing behind the window shows through while two of them overlap.
        ZStack {
            if let e = service.startupError {
                ContentUnavailableView("Bisel can't start", systemImage: "exclamationmark.triangle", description: Text(e))
            } else if usesFixture {
                fixtureNotice
            } else if inSetup {
                SetupView(service: service).transition(Self.swap)
            } else if let phrase = service.pendingPhrase {
                PhraseGateView(service: service, phrase: phrase) { phraseStored() }
                    .transition(Self.swap)
            } else if showAccess {
                OnboardingAccessibilityView(monitor: AppModel.shared.accessibility) { showAccess = false; showImport = true }
                    .transition(Self.swap)
            } else if showImport {
                OnboardingImportView(service: service) {
                    // A closed `Window` keeps its view state, so `showImport` must be reset or every later "Open Bisel" lands
                    // here again. Reset after the close so the settings card never flashes in its place.
                    dismissWindow(id: "main")
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { showImport = false }
                }
                .transition(Self.swap)
            } else if service.phase == .locked {
                SettingsLockedView().transition(Self.swap)
            } else {
                unlocked
            }
        }
        .background(cardSize == nil ? Color.clear : Theme.biselDark.colors.background.color)
        .animation(.easeInOut(duration: 0.3), value: screenKey)
        .environment(\.cascadeLead, 0.3)   // a new screen waits for the old one to fade out
        // SwiftUI owns the window size (the scene is .contentSize): the island and Settings are each exactly their fixed frame.
        // No AppKit resizing, so the hosting view can never lag behind the window.
        .frame(width: cardSize?.width ?? Self.settingsSize.width,
               height: cardSize.map { $0.height - titlebarInset } ?? Self.settingsSize.height)
        .modifier(ThemedScreens(theme: theme, active: !isSettings, opaque: cardSize == nil))
        .panelMaterial()
        .background(WindowAccessor { w in
            w.sharingType = .readOnly   // nothing is hidden from screenshots; sensitive values are masked in the UI instead
            w.isRestorable = false
            DockPresence.windowAppeared(w)
            // Only when the screen kind changes: re-applying the style mask on every update fights the split view's
            // sidebar animation.
            let mode = cardSize == nil ? "window" : "island.\(screenKey)"
            if styled.window !== w || styled.mode != mode {
                style(w)
                styled.window = w
                styled.mode = mode
            }
            let inset = w.frame.height - w.contentLayoutRect.height
            if cardSize != nil, abs(inset - titlebarInset) > 0.5, inset >= 0 { DispatchQueue.main.async { titlebarInset = inset } }
        })
        .onReceive(NotificationCenter.default.publisher(for: .init("app.bisel.dev.tour.continue"))) { _ in
            #if DEBUG
            phraseStored()   // what the Continue button does
            #endif
        }
        .toolbarBackgroundVisibility(cardSize == nil ? .automatic : .hidden, for: .windowToolbar)
    }

    /// Set-up and the recovery phrase are the glass island itself: the window is small, borderless-looking and shows the
    /// command panel's material. Settings (locked or not) and the error and fixture notices use the normal window.
    private var cardSize: NSSize? {
        guard service.startupError == nil, !usesFixture else { return nil }
        if service.pendingPhrase != nil || showAccess || showImport || inSetup { return OnboardingLayout.island }
        return nil
    }

    private func style(_ w: NSWindow) {
        if cardSize != nil {
            w.isOpaque = false
            w.backgroundColor = .clear
            w.titlebarAppearsTransparent = true
            w.titlebarSeparatorStyle = .none
            w.titleVisibility = .hidden
            w.title = ""
            w.styleMask.insert(.fullSizeContentView)
            w.styleMask.remove(.resizable)
            // No traffic lights on the onboarding screens (the window closes from the Dock).
            for b in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] { w.standardWindowButton(b)?.isHidden = true }
            w.isMovableByWindowBackground = true
            w.hasShadow = true
            w.invalidateShadow()   // the shadow follows the drawn card, whose shape changes with the screen
        } else {
            // A standard window: the system's corners, traffic lights, colors and light/dark appearance.
            w.appearance = nil
            w.isOpaque = true
            w.backgroundColor = .windowBackgroundColor
            w.styleMask.insert(.fullSizeContentView)
            w.titlebarAppearsTransparent = false
            w.titlebarSeparatorStyle = .automatic
            w.titleVisibility = .visible
            w.styleMask.remove(.resizable)
            for b in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] { w.standardWindowButton(b)?.isHidden = false }
            w.isMovableByWindowBackground = false
        }
    }

    /// Settings' fixed size (the error and fixture notices use it too).
    private static let settingsSize = CGSize(width: 820, height: 580)

    /// The phrase is stored: on to the Accessibility step when the permission is off, else straight to the import.
    private func phraseStored() {
        if AppModel.shared.accessibility.trusted { showImport = true } else { showAccess = true }
        service.confirmPhraseStored()
    }

    /// First run, and a pairing until the codes are compared: the box key arrives (and the vault counts as set up) before
    /// the person has checked the other device's code, so that step must not give way to the settings.
    private var inSetup: Bool {
        if service.phase == .needsSetup { return true }
        switch service.setupState {
        case .pairing, .compareCode, .working(.finishingPairing): return true
        default: return false
        }
    }

    /// Settings, locked or not: native colors, fonts and title, so the Bisel theme is left out.
    private var isSettings: Bool { service.startupError == nil && !usesFixture && (screenKey == "locked" || screenKey == "unlocked") }

    /// The old screen fades out; the new one is simply there and fades in on its own cascade, after `cascadeLead`.
    private static let swap = AnyTransition.asymmetric(insertion: .identity, removal: .opacity)

    /// Which screen is up; changing it fades the old one out.
    private var screenKey: String {
        if service.startupError != nil { return "error" }
        if inSetup { return "setup" }
        if service.pendingPhrase != nil { return "phrase" }
        if showAccess { return "access" }
        if showImport { return "import" }
        return service.phase == .locked ? "locked" : "unlocked"
    }

    private var usesFixture: Bool {
        #if BISEL_DEV_FIXTURE
        BiselEnvironment.useDevFixture
        #else
        false
        #endif
    }

    private var fixtureNotice: some View {
        ContentUnavailableView("Dev fixture is active", systemImage: "testtube.2",
                               description: Text("This run uses the fake panel fixture. Start without it to use the real box."))
    }

    private var unlocked: some View {
        SettingsView(service: service)
    }
}



/// Which window was last styled, and for what screen kind. A plain class: changing it must not update the view.
private final class StyledWindow {
    weak var window: NSWindow?
    var mode = ""
}

/// The Bisel theme (colors, tint, light/dark) and window title for every screen but Settings, which stays native.
private struct ThemedScreens: ViewModifier {
    let theme: Theme
    let active: Bool
    let opaque: Bool
    private let service = AppModel.shared.service

    func body(content: Content) -> some View {
        if active {
            content.themedPage(theme, opaque: opaque)
                // Onboarding screens have no window title at all (it would be drawn in the titlebar, over the progress bar).
                .navigationTitle(!opaque ? "" : (service.provenanceLabel.map { "Bisel  ·  \($0)" } ?? "Bisel"))
        } else {
            content
        }
    }
}
