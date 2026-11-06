import AuthenticationServices
import BiselCore

/// The app's side of `AutoFillBroker`: the Touch ID prompt, and the socket the extension reaches it on.
@MainActor
final class AppAutoFillHost: AutoFillHost {
    private static let promptTimeout: Duration = .seconds(60)

    private let service: VaultService

    init(service: VaultService) { self.service = service }

    /// Always a real prompt: it neither spends nor grants the panel's single-use credit.
    func authenticate(_ reason: String) async throws {
        switch service.phase {
        case .needsSetup: throw AgentError(.locked)
        case .locked: try await service.unlock(reason: reason)
        case .unlocked:
            let start = ContinuousClock.now
            do {
                try await BiometricGate.authenticate(reason: reason, grantsCredit: false, timeout: Self.promptTimeout)
            } catch {
                throw AgentError(ContinuousClock.now - start >= Self.promptTimeout ? .timeout : .denied)
            }
        }
    }

    func passkeysChanged() async {
        await service.reload()
        await service.sync(reason: "passkey")
    }

    /// Nil where the app has no App Group: BiselDev runs unsigned and has no extension to talk to.
    static var socketPath: String? {
        #if BISEL_SOFTWARE_KEYS
        nil
        #else
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AutoFillSocket.appGroup).map {
            #if DEBUG
            AutoFillSocket.path(container: $0, debug: true)
            #else
            AutoFillSocket.path(container: $0, debug: false)
            #endif
        }
        #endif
    }
}

/// The system's credential identity store. The system keeps it as plaintext outside the box (SECURITY.md), so it gets only
/// `AutoFillIdentity`, and only while the box is unlocked.
struct SystemIdentityStore: AutoFillIdentitySink {
    func isEnabled() async -> Bool { await ASCredentialIdentityStore.shared.state().isEnabled }

    func replace(_ identities: [AutoFillIdentity]) async throws {
        try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities.map { identity -> any ASCredentialIdentity in
            if let passkey = identity.passkey {
                return ASPasskeyCredentialIdentity(relyingPartyIdentifier: identity.domain, userName: identity.username,
                                                   credentialID: passkey.credentialID, userHandle: passkey.userHandle,
                                                   recordIdentifier: identity.recordID)
            }
            return ASPasswordCredentialIdentity(serviceIdentifier: ASCredentialServiceIdentifier(identifier: identity.domain, type: .domain),
                                                user: identity.username, recordIdentifier: identity.recordID)
        })
    }

    func clear() async throws { try await ASCredentialIdentityStore.shared.removeAllCredentialIdentities() }
}
