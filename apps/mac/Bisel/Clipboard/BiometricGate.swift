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

    /// A successful check is a single-use credit for the *next* `consumeCredit` within a few seconds. The panel asks for Touch ID
    /// before it calls `VaultService.secret`, which gates strict mode itself (security review M6); the credit stops that one user
    /// action from prompting twice without letting a later, separate copy or fill skip its own prompt.
    private static var credit: ContinuousClock.Instant?
    static func consumeCredit(maxAge: Duration = .seconds(3)) -> Bool {
        defer { credit = nil }
        guard let c = credit else { return false }
        return ContinuousClock.now - c <= maxAge
    }

    /// `grantsCredit: false` for every caller that is not the command panel (unlock, edit/delete/revoke gates, main-window copy), so
    /// a prompt for something else can never pay for a later password read.
    static func authenticate(reason: String, grantsCredit: Bool = true) async throws {
        try await evaluate(reason: reason)
        if grantsCredit { credit = .now }
    }

    #if DEBUG
    /// Number of times a real prompt was requested (flow runs assert strict-mode behaviour with it).
    static var promptCount = 0
    #endif

    private static func evaluate(reason: String) async throws {
        #if DEBUG
        promptCount += 1
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
