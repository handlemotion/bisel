import KeyboardShortcuts
import SwiftUI
#if BISEL_CLOUDKIT
import BiselCloudKit
#endif

@main
struct BiselApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var themes = ThemeStore.shared

    #if BISEL_LANE_CONTRACT
    // The opt-in CloudKit contract run takes the process over before any scene, AppModel or vault exists.
    init() { LaneContractRun.runIfRequested() }
    #endif

    var body: some Scene {
        MenuBarExtra {
            MenuBarContent()
        } label: {
            // The label exists from launch (menu content only exists once opened), so it can hand non-view code the
            // `openWindow` action in time for the first-run set-up window.
            Image("MenuBarIcon").modifier(OpenWindowBridge())
        }

        Window("Bisel", id: "main") {
            MainWindowView()
                .environment(\.theme, themes.current)
                .modifier(OpenWindowBridge())
        }
        .defaultLaunchBehavior(.suppressed)
        .defaultSize(width: 920, height: 600)
        .windowResizability(.contentSize)
    }
}

/// Lets non-view code (the panel's "unlock" action, the menu) open the SwiftUI `Window`.
private struct OpenWindowBridge: ViewModifier {
    @Environment(\.openWindow) private var openWindow
    func body(content: Content) -> some View {
        content.onAppear { AppModel.shared.openMainWindow = { openWindow(id: "main") } }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        MainActor.assumeIsolated { AppModel.shared.start() }
        #if BISEL_CLOUDKIT
        // CloudKit's silent pushes for the box's zone. Without the push entitlement registration fails (logged) and the 60 s poll
        // carries on alone (docs/SYNC-LANES.md §15, "What needs Rodrigo").
        NSApp.registerForRemoteNotifications()
        #endif
    }

    #if BISEL_CLOUDKIT
    func application(_ application: NSApplication, didFailToRegisterForRemoteNotificationsWithError error: any Error) {
        Log.app.notice("push registration failed: \(error.localizedDescription)")
    }

    func application(_ application: NSApplication, didReceiveRemoteNotification userInfo: [String: Any]) {
        CloudKitLane.handleRemoteNotification(userInfo)   // the vault service syncs on the signal
    }
    #endif

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { AppModel.shared.terminate() }
    }
}

private struct MenuBarContent: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Command Panel") { AppModel.shared.panelController.show() }
        // Before a box exists the window is set-up, not settings.
        Button(AppModel.shared.service.phase == .needsSetup ? "Set Up Bisel…" : "Settings…") {
            AppModel.shared.openMainWindow = { openWindow(id: "main") }
            AppModel.shared.showMainWindow()
        }
        .keyboardShortcut(",")
        Button("Sync Now") { Task { await AppModel.shared.service.sync(reason: "menu") } }
        Button("Lock") { AppModel.shared.service.lock(reason: "menu") }
        Divider()
        Button("Accessibility Setup…") { AppModel.shared.onboarding.show() }
        Button("Reload Themes") { ThemeStore.shared.reload() }
        #if DEBUG
        Divider()
        Button("Debug: Log Focused Field in 3 s") { DebugTools.logFocusedFieldAfterDelay() }
        #endif
        Divider()
        Button("Quit Bisel") { NSApp.terminate(nil) }
    }
}
