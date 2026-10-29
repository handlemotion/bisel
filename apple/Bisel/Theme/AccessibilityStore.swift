import AppKit
import Observation

/// Live view of the system's display-accessibility switches (System Settings → Accessibility → Display / Motion).
/// Updated from `accessibilityDisplayOptionsDidChangeNotification`, so a change applies while the panel is open.
@MainActor
@Observable
final class AccessibilityStore {
    static let shared = AccessibilityStore()

    private(set) var preferences: AccessibilityPreferences

    @ObservationIgnored private var observer: NSObjectProtocol?

    private init() {
        preferences = Self.read()
        observer = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func refresh() {
        let new = Self.read()
        if new != preferences { preferences = new }
    }

    private static func read() -> AccessibilityPreferences {
        let ws = NSWorkspace.shared
        var p = AccessibilityPreferences(
            reduceMotion: ws.accessibilityDisplayShouldReduceMotion,
            reduceTransparency: ws.accessibilityDisplayShouldReduceTransparency,
            increaseContrast: ws.accessibilityDisplayShouldIncreaseContrast,
            differentiateWithoutColor: ws.accessibilityDisplayShouldDifferentiateWithoutColor)
        #if DEBUG
        // Verification aid: BISEL_DEV_A11Y=reduceMotion,reduceTransparency,increaseContrast,differentiateWithoutColor
        // forces switches on without touching System Settings.
        if let forced = ProcessInfo.processInfo.environment["BISEL_DEV_A11Y"]?.split(separator: ",").map(String.init) {
            if forced.contains("reduceMotion") { p.reduceMotion = true }
            if forced.contains("reduceTransparency") { p.reduceTransparency = true }
            if forced.contains("increaseContrast") { p.increaseContrast = true }
            if forced.contains("differentiateWithoutColor") { p.differentiateWithoutColor = true }
        }
        #endif
        return p
    }
}
