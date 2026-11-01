import KeyboardShortcuts
import SwiftUI
import BiselCore

struct MainWindowView: View {
    /// The window is for settings only; the command panel (⌘⇧Space) is the way into the box.
    private let service = AppModel.shared.service
    /// After the recovery phrase of a new box: one last onboarding step to import passwords.
    @State private var showImport = false
    /// The titlebar's height, measured from the window: the scene sizes the content area, the titlebar comes on top of it,
    /// so the island's frame is its height minus this.
    @State private var titlebarInset: CGFloat = 32
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
                PhraseGateView(service: service, phrase: phrase) { showImport = true; service.confirmPhraseStored() }
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
                LockedView(service: service).transition(Self.swap)
            } else {
                unlocked
            }
        }
        .background(cardSize == nil || isSettings ? Color.clear : Theme.biselDark.colors.background.color)   // settings draws its own card
        .animation(.easeInOut(duration: 0.3), value: screenKey)
        .environment(\.cascadeLead, 0.3)   // a new screen waits for the old one to fade out
        // SwiftUI owns the window size (the scene is .contentSize): the island is exactly its fixed frame, the settings window
        // grows from a 820x540 minimum. No AppKit resizing, so the hosting view can never lag behind the window.
        .frame(minWidth: cardSize?.width ?? 820, maxWidth: cardSize?.width ?? .infinity,
               minHeight: cardSize.map { $0.height - titlebarInset } ?? 540, maxHeight: cardSize.map { $0.height - titlebarInset } ?? .infinity)
        .themedPage(theme, opaque: cardSize == nil)
        .panelMaterial()
        .background(WindowAccessor { w in
            w.sharingType = .readOnly   // nothing is hidden from screenshots; sensitive values are masked in the UI instead
            w.isRestorable = false
            DockPresence.windowAppeared(w)
            style(w)
            let inset = w.frame.height - w.contentLayoutRect.height
            if cardSize != nil, abs(inset - titlebarInset) > 0.5, inset >= 0 { DispatchQueue.main.async { titlebarInset = inset } }
        })
        .onReceive(NotificationCenter.default.publisher(for: .init("app.bisel.dev.tour.continue"))) { _ in
            #if DEBUG
            showImport = true; service.confirmPhraseStored()   // what the Continue button does
            #endif
        }
        .toolbarBackgroundVisibility(cardSize == nil ? .automatic : .hidden, for: .windowToolbar)
        // Onboarding screens have no window title at all (it would be drawn in the titlebar, over the progress bar).
        .navigationTitle(cardSize != nil ? "" : (service.provenanceLabel.map { "Bisel  ·  \($0)" } ?? "Bisel"))
    }

    /// Set-up, the recovery phrase and the lock screen are the glass island itself: the window is small, borderless-looking
    /// and shows the command panel's material. Settings is a card of its own (with traffic lights). Only the error and
    /// fixture notices use the normal window.
    private var cardSize: NSSize? {
        guard service.startupError == nil, !usesFixture else { return nil }
        if service.pendingPhrase != nil || showImport || inSetup { return OnboardingLayout.island }
        switch service.phase {
        case .needsSetup: return OnboardingLayout.island
        case .locked: return OnboardingLayout.island
        default: return SettingsLayout.window
        }
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
            // No traffic lights on the onboarding screens (the window closes from the Dock); settings keeps close and minimise.
            w.standardWindowButton(.closeButton)?.isHidden = !isSettings
            w.standardWindowButton(.miniaturizeButton)?.isHidden = !isSettings
            w.standardWindowButton(.zoomButton)?.isHidden = true
            w.isMovableByWindowBackground = true
            w.hasShadow = true
            w.invalidateShadow()   // the shadow follows the drawn card, whose shape changes with the screen
        } else {
            w.isOpaque = true
            w.backgroundColor = .windowBackgroundColor
            w.titlebarAppearsTransparent = false
            w.titlebarSeparatorStyle = .automatic
            w.titleVisibility = .visible
            w.styleMask.insert(.resizable)
            for b in [NSWindow.ButtonType.closeButton, .miniaturizeButton, .zoomButton] { w.standardWindowButton(b)?.isHidden = false }
            w.isMovableByWindowBackground = false
        }
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

    /// The unlocked box: the settings card.
    private var isSettings: Bool { cardSize == SettingsLayout.window }

    /// The old screen fades out; the new one is simply there and fades in on its own cascade, after `cascadeLead`.
    private static let swap = AnyTransition.asymmetric(insertion: .identity, removal: .opacity)

    /// Which screen is up; changing it fades the old one out.
    private var screenKey: String {
        if service.startupError != nil { return "error" }
        if inSetup { return "setup" }
        if service.pendingPhrase != nil { return "phrase" }
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
        SettingsShell(service: service)
    }
}


