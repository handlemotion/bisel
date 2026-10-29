import Foundation
import BiselCore

/// Where this process keeps its vault, and which key store backs it.
enum BiselEnvironment {
    /// The one server every box uses. Not a setting: the person only ever chooses to connect or not.
    static let defaultServer = "https://box.bisel.app"

    /// `~/Library/Application Support/bisel/vault`. SPEC §7 wants the App Group container from day one; that needs a
    /// Team ID, so until the app is signed the store lives here (see SPEC §8, "Storage").
    /// Debug only: `BISEL_DATA_DIR=<dir>` points a run at a throwaway store (flow tests, screenshots).
    static var dataDirectory: URL {
        #if DEBUG
        if let dir = ProcessInfo.processInfo.environment["BISEL_DATA_DIR"], !dir.isEmpty {
            return URL(fileURLWithPath: dir, isDirectory: true)
        }
        #endif
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("bisel/vault", isDirectory: true)
    }

    static func makeKeyStore(directory: URL) -> any DeviceKeyStore {
        #if BISEL_SOFTWARE_KEYS
        Log.app.fault("BISEL_SOFTWARE_KEYS: this build keeps device keys in a PLAIN FILE in \(directory.path, privacy: .public). DEBUG/UNSIGNED ONLY. Not a Secure Enclave run.")
        return SoftwareDeviceKeyStore(directory: directory)
        #else
        // Needs a signed build (-34018 otherwise). Access group stays nil until a Team ID exists (SPEC §8).
        return SecureEnclaveDeviceKeyStore(accessGroup: nil)
        #endif
    }

    static var usesSoftwareKeys: Bool {
        #if BISEL_SOFTWARE_KEYS
        true
        #else
        false
        #endif
    }

    /// Real vault unless a Debug build was asked for the panel dev fixture (`BISEL_DEV_FIXTURE=1`).
    static var useDevFixture: Bool {
        #if BISEL_DEV_FIXTURE
        ProcessInfo.processInfo.environment["BISEL_DEV_FIXTURE"] == "1"
        #else
        false
        #endif
    }
}

/// Adapts the app's `BiometricGate` (fresh `LAContext`, `.deviceOwnerAuthenticationWithBiometrics`, no passcode
/// fallback) to BiselCore's gate protocol, so edit / delete / revoke inside the core ask for Touch ID.
struct AppGate: BiselKeyStore.BiometricGate {
    func authenticate(reason: String) async throws {
        do { try await BiometricGate.authenticate(reason: reason, grantsCredit: false) }
        catch BiometricGate.Failure.denied { throw KeyStoreError.userCancelled }
        catch { throw KeyStoreError.failed(error.localizedDescription) }
    }
}

/// Short, human error text. Never includes vault data.
func describe(_ error: Error) -> String {
    switch error {
    case let e as KeyStoreError:
        switch e {
        case .userCancelled: return "Cancelled"
        case .noKeys: return "This Mac has no device keys for this box"
        case .unavailable(let m): return "Touch ID unavailable: \(m)"
        case .failed(let m): return m
        }
    case let e as SyncError:
        switch e {
        case .notAuthorized: return "The server refused this request (wrong server or token, wrong recovery phrase, revoked device, or clock off by more than 60 s)"
        case .network(let m): return "Can't reach the server: \(m)"
        case .tooLarge: return "Item is too large (limit 256 KiB)"
        case .conflict: return "The item changed on another device"
        case .exists: return "Already exists"
        case .notFound: return "Not found"
        case .server(let status, let code): return "Server error \(status)\(code.map { ": \($0)" } ?? "")"
        case .malformedResponse: return "Unexpected server response"
        }
    case let e as BiselVault.VaultError:
        switch e {
        case .locked: return "Box is locked"
        case .notFound: return "Item not found"
        case .notConfigured: return "This Mac isn't set up yet"
        case .alreadyConfigured: return "This Mac already has a box"
        case .noServer: return "This box is on this Mac only. Connect a server in Settings first"
        case .noTOTP: return "This item has no one-time code"
        case .badBackup(let m): return m
        case .unsupportedPayloadVersion(let v): return "Item format v\(v) is newer than this app"
        case .needsUnlockToResolveConflict: return "Unlock to resolve a sync conflict"
        }
    case BiselCryptoError.invalidRecoveryPhrase: return "That isn't a valid 24-word recovery phrase"
    case BiselCryptoError.authenticationFailed: return "Wrong key (the data could not be authenticated)"
    default: return error.localizedDescription
    }
}
