import BiselCore
import Foundation

/// The app's side of `BrowserSaveBroker`: the same Touch ID prompt AutoFill shows, then a reload and a sync.
@MainActor
final class AppBrowserSaveHost: BrowserSaveHost {
    private let service: VaultService
    private let prompts: AppAutoFillHost

    init(service: VaultService) { self.service = service; prompts = AppAutoFillHost(service: service) }

    func authenticate(_ reason: String) async throws { try await prompts.authenticate(reason) }
    func loginSaved() async { await service.didChangeLocally(reason: "browser") }

    static var socketPath: String {
        #if DEBUG
        BrowserLink.socketPath(debug: true)
        #else
        BrowserLink.socketPath(debug: false)
        #endif
    }

    /// Debug only: an unsigned dev build cannot satisfy the signature check. `scripts/check-release-hooks.sh` proves this is not in Release.
    static var clientRequirement: String? {
        #if DEBUG
        if ProcessInfo.processInfo.environment["BISEL_DEV_AGENT_UNSIGNED"] == "1" { return nil }
        #endif
        return AgentPeer.browserHostRequirement
    }
}

/// Tells Chrome where the native host is, on every launch, so it follows the app if it moved. Only where Chrome is installed. A dev build
/// leaves the manifest alone unless asked: there is one per user, and it would take the installed app's place.
enum BrowserHostManifest {
    static func install() {
        #if DEBUG
        guard ProcessInfo.processInfo.environment["BISEL_DEV_BROWSER_HOST"] == "1" else { return }
        #endif
        let support = (AgentSocket.supportDirectory as NSString).deletingLastPathComponent
        let chrome = support + "/Google/Chrome"
        guard FileManager.default.fileExists(atPath: chrome) else { return }
        let host = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/bisel-browser-host").path
        let directory = URL(fileURLWithPath: chrome + "/NativeMessagingHosts", isDirectory: true)
        let file = directory.appendingPathComponent(BrowserLink.hostName + ".json")
        guard let manifest = try? BrowserLink.manifest(hostPath: host), (try? Data(contentsOf: file)) != manifest else { return }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try manifest.write(to: file, options: .atomic)
        } catch {
            Log.app.error("chrome host manifest could not be written")
        }
    }
}
