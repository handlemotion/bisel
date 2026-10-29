import AppKit
import SwiftUI

/// Composition root. Today the vault is the dev fixture (Debug) or a permanently locked stub (Release);
/// BiselCore's vault replaces `vault` when it lands.
@MainActor
final class AppModel {
    static let shared = AppModel()

    typealias Vault = VaultSearchSource & VaultSecretProvider
    let vault: any Vault
    let panelModel: CommandPanelModel
    let panelController: CommandPanelController
    let accessibility = AccessibilityMonitor()
    private(set) lazy var onboarding = OnboardingWindowController(monitor: accessibility)

    /// Set by the SwiftUI scene so non-view code can open the main window.
    var openMainWindow: (() -> Void)?

    private init() {
        #if BISEL_DEV_FIXTURE
        vault = DevFixtureVault()
        #else
        vault = LockedVault()
        #endif
        panelModel = CommandPanelModel(source: vault, secrets: vault)
        panelController = CommandPanelController(model: panelModel)
        wirePanelActions()
    }

    func start() {
        Log.app.notice("bisel started; accessibility trusted=\(AccessibilityInspector.isTrusted())")
        if !AccessibilityInspector.isTrusted() { onboarding.show() }
        #if DEBUG
        DebugTools.runAutopilotIfRequested()
        #endif
    }

    func showMainWindow() {
        openMainWindow?()
        NSApp.activate()
    }

    func terminate() { SecureClipboard.shared.clearOnTerminate() }

    // MARK: panel actions

    private func wirePanelActions() {
        panelModel.runUnlock = { [weak self] in
            self?.panelController.hide()
            self?.showMainWindow()
        }

        panelModel.runClose = { [weak self] in self?.panelController.hide("api") }

        panelModel.runFill = { [weak self] plan, item in
            guard let self else { return }
            let target = panelController.fillTarget
            panelController.hide("fill", immediate: true)
            guard let target else {
                Toast.shared.show("Open the panel over the app you want to fill", isError: true)
                return
            }
            let vault = self.vault
            let id = item.id
            Task {
                let outcome = await FillEngine.shared.fill(plan, into: target) { kind in
                    if SecuritySettings.requireTouchID && kind.requiresFreshBiometricWhenFilled() {
                        try await BiometricGate.authenticate(reason: "Fill a one-time code")
                    }
                    return try await vault.secret(kind, for: id)
                }
                self.finish(outcome, itemID: id)
            }
        }

        panelModel.runCloseAfterCopy = { [weak self] in self?.panelController.hideAfterCopy() }

        panelModel.runCopy = { [weak self] kind, item in
            guard let self else { return }
            let vault = self.vault
            let what = kind == .totp ? "One-time code" : kind.rawValue.capitalized
            Task {
                do {
                    if SecuritySettings.requireTouchID && kind.requiresFreshBiometricWhenCopied() {
                        try await BiometricGate.authenticate(reason: "Copy \(what.lowercased())")
                    }
                    let value = try await vault.secret(kind, for: item.id)
                    SecureClipboard.shared.copySecret(value)
                    vault.recordUse(id: item.id)
                    let viaPill = self.panelModel.pillTriggered
                    self.panelModel.pillTriggered = false
                    if self.panelController.isVisible {
                        self.panelModel.flashCopied(kind, viaPill: viaPill)  // ✓ Copied on the row, then close if set
                    } else {
                        Toast.shared.show("\(what) copied. Clears in 30 s")
                    }
                } catch {
                    self.panelModel.pillTriggered = false
                    if self.panelController.isVisible { self.panelModel.flashFailure(kind, error.localizedDescription) }
                    else { Toast.shared.show(error.localizedDescription, isError: true) }
                }
            }
        }

        panelModel.runOpenURL = { [weak self] item in
            guard let self else { return }
            panelController.hide()
            if let url = vault.url(for: item.id) { NSWorkspace.shared.open(url) }
        }
    }

    private func finish(_ outcome: FillOutcome, itemID: String) {
        switch outcome {
        case .filled(let text):
            vault.recordUse(id: itemID)
            Log.fill.notice("\(text, privacy: .public)")
        case .needsAccessibility:
            onboarding.show()
        case .notATextField(let why):
            Toast.shared.show(why, isError: true)
        case .failed(let why):
            Toast.shared.show(why, isError: true)
        }
    }
}
