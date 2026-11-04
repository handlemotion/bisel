import Foundation
import BiselCore

/// The "Allow agents" switch. It lives in the Keychain, not UserDefaults, because any process of this user can write defaults, and
/// an agent is exactly who must not be able to turn this on.
enum AgentAccess {
    private static let key = "agent-access"

    private static var store: any SecretStore {
        #if BISEL_SOFTWARE_KEYS
        FileSecretStore(directory: BiselEnvironment.dataDirectory)
        #else
        KeychainSecretStore(accessGroup: BiselEnvironment.keychainGroup)
        #endif
    }

    static var isAllowed: Bool { ((try? store.get(key)) ?? nil) != nil }

    static func set(_ allowed: Bool) throws {
        if allowed { try store.set(key, Data([1])) } else { try store.delete(key) }
    }

    /// Debug builds have their own socket, so a dev build and the installed app can run side by side.
    static var socketPath: String {
        #if DEBUG
        AgentSocket.path(name: "agent-dev")
        #else
        AgentSocket.path(name: "agent")
        #endif
    }

    /// Debug only: an unsigned dev build cannot satisfy the signature check. `scripts/check-release-hooks.sh` proves this is not in Release.
    static var clientRequirement: String? {
        #if DEBUG
        if ProcessInfo.processInfo.environment["BISEL_DEV_AGENT_UNSIGNED"] == "1" { return nil }
        #endif
        return AgentPeer.toolRequirement
    }
}
