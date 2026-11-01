import Foundation
import Sparkle

/// In-app updates through Sparkle (RELEASE.md, "Updates"). The feed, the EdDSA public key and the daily background check are in
/// Info.plist (project.yml); Sparkle verifies the feed's and the archive's signatures before anything is extracted. The app is not
/// sandboxed, so the installer runs without Sparkle's XPC services.
@MainActor @Observable
final class Updater: NSObject {
    static let shared = Updater()

    /// Drives "Check for Updates…": false while a check or an install is under way, and in a Debug build without a feed.
    private(set) var canCheckForUpdates = false

    @ObservationIgnored private var controller: SPUStandardUpdaterController!
    @ObservationIgnored private var observation: NSKeyValueObservation?

    private override init() {
        super.init()
        controller = SPUStandardUpdaterController(startingUpdater: Self.startsUpdater, updaterDelegate: self, userDriverDelegate: self)
        observation = controller.updater.observe(\.canCheckForUpdates, options: [.initial, .new]) { [weak self] updater, _ in
            let can = updater.canCheckForUpdates
            MainActor.assumeIsolated { self?.canCheckForUpdates = can }
        }
    }

    func checkForUpdates() { controller.checkForUpdates(nil) }

    #if DEBUG
    /// Debug only: `BISEL_DEV_FEED_URL=<url>` points the updater at a local appcast (the update test in RELEASE.md). Without it a
    /// Debug build never starts the updater, so an Xcode run is not offered the shipped release.
    nonisolated private static var feedOverride: String? { ProcessInfo.processInfo.environment["BISEL_DEV_FEED_URL"] }
    private static var startsUpdater: Bool { feedOverride != nil }
    #else
    private static let startsUpdater = true
    #endif
}

extension Updater: SPUUpdaterDelegate {
    #if DEBUG
    nonisolated func feedURLString(for updater: SPUUpdater) -> String? { Self.feedOverride }
    #endif
}

extension Updater: SPUStandardUserDriverDelegate {
    /// A menu-bar app: an update found by the background check is shown without taking focus from what the person is typing in.
    nonisolated var supportsGentleScheduledUpdateReminders: Bool { true }
}
