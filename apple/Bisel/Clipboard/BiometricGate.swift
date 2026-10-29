import Foundation
import LocalAuthentication

/// Fresh-biometric check for sensitive actions (SPEC.md §4 "Unlock model" step 3): a brand new `LAContext`
/// per call, policy `.deviceOwnerAuthenticationWithBiometrics` (no passcode fallback). If biometrics are
/// unavailable the action is refused.
@MainActor
enum BiometricGate {
    enum Failure: Error, LocalizedError {
        case unavailable(String), denied
        var errorDescription: String? {
            switch self {
            case .unavailable(let why): "Biometrics unavailable: \(why)"
            case .denied: "Authentication was not completed"
            }
        }
    }

    static func authenticate(reason: String) async throws {
        #if DEBUG
        // DEBUG-ONLY escape hatch so headless flow runs can exercise copy/fill without a fingerprint.
        // Compiled out of Release. Loud on purpose.
        if ProcessInfo.processInfo.environment["BISEL_DEV_SKIP_BIOMETRIC"] == "1" {
            Log.app.fault("BISEL_DEV_SKIP_BIOMETRIC=1: biometric check BYPASSED (debug build only)")
            return
        }
        #endif
        let ctx = LAContext()
        ctx.localizedFallbackTitle = ""  // hides the "Enter Password" fallback button
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) else {
            throw Failure.unavailable(err?.localizedDescription ?? "unknown")
        }
        do {
            let ok = try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            if !ok { throw Failure.denied }
        } catch let e as LAError {
            throw e.code == .userCancel || e.code == .appCancel ? Failure.denied : Failure.unavailable(e.localizedDescription)
        }
    }
}
