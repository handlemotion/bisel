import KeyboardShortcuts
import SwiftUI

@main
struct BiselApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var themes = ThemeStore.shared

    var body: some Scene {
        MenuBarExtra {
            MenuBarContent()
        } label: {
            // The label exists from launch (menu content only exists once opened), so it can hand non-view code the
            // `openWindow` action in time for the first-run set-up window.
            Image(systemName: "lock.shield.fill").modifier(OpenWindowBridge())
        }

        Window("Bisel", id: "main") {
            MainWindowView()
                .environment(\.theme, themes.current)
                .modifier(OpenWindowBridge())
        }
        .defaultLaunchBehavior(.suppressed)
        .defaultSize(width: 920, height: 600)
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
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { AppModel.shared.terminate() }
    }
}

private struct MenuBarContent: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Command Panel") { AppModel.shared.panelController.show() }
        Button("Open Bisel") {
            AppModel.shared.openMainWindow = { openWindow(id: "main") }
            AppModel.shared.showMainWindow()
        }
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
