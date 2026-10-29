import Foundation
import LocalAuthentication

/// Fresh `LAContext` evaluation with `.deviceOwnerAuthenticationWithBiometrics`: no passcode fallback.
public struct LocalAuthenticationGate: BiometricGate {
    public init() {}

    public func authenticate(reason: String) async throws {
        let context = LAContext()
        context.localizedFallbackTitle = ""          // hide the "Enter Password" fallback button
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw KeyStoreError.unavailable(error?.localizedDescription ?? "biometrics unavailable")
        }
        do {
            _ = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let e as LAError where e.code == .userCancel || e.code == .appCancel || e.code == .systemCancel {
            throw KeyStoreError.userCancelled
        } catch {
            throw KeyStoreError.failed(error.localizedDescription)
        }
    }
}
