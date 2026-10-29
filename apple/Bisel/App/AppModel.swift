import AppKit
import KeyboardShortcuts
import SwiftUI
import BiselCore

/// Composition root. The panel is backed by `VaultService` (BiselCore's `Vault` actor); a Debug build can swap in
/// the fake dev fixture with `BISEL_DEV_FIXTURE=1` (never compiled into Release).
@MainActor
final class AppModel {
    static let shared = AppModel()

    typealias PanelVault = VaultSearchSource & VaultSecretProvider
    let service = VaultService()
    let vault: any PanelVault
    let panelModel: CommandPanelModel
    let panelController: CommandPanelController
    let accessibility = AccessibilityMonitor()
    private(set) lazy var onboarding = OnboardingWindowController(monitor: accessibility)

    /// Set by the SwiftUI scene so non-view code can open the main window.
    var openMainWindow: (() -> Void)?

    private init() {
        #if BISEL_DEV_FIXTURE
        vault = BiselEnvironment.useDevFixture ? DevFixtureVault() : service
        #else
        vault = service
        #endif
        panelModel = CommandPanelModel(source: vault, secrets: vault)
        panelController = CommandPanelController(model: panelModel)
        wirePanelActions()
        #if DEBUG
        // Scripted flow runs (BISEL_DEV_FLOW) must not grab the global hotkey or open windows on someone's screen.
        if ProcessInfo.processInfo.environment["BISEL_DEV_FLOW"] != nil { KeyboardShortcuts.disable(.commandPanel) }
        #endif
    }

    func start() {
        Log.app.notice("bisel started; accessibility trusted=\(AccessibilityInspector.isTrusted())")
        service.onLockStateChange = { [weak self] in self?.panelModel.refresh() }
        Task {
            await service.start()
            #if DEBUG
            if ProcessInfo.processInfo.environment["BISEL_DEV_AUTOUNLOCK"] == "1", service.phase == .locked {
                Log.app.fault("BISEL_DEV_AUTOUNLOCK=1 (debug build only)")
                try? await service.unlock(reason: "dev autounlock")
            }
            #endif
            // First launch: the main window is where set-up happens. Accessibility onboarding follows once a vault exists.
            if isScriptedFlow { return }
            if service.phase == .needsSetup && !BiselEnvironment.useDevFixture { showMainWindow() }
            else if !AccessibilityInspector.isTrusted() { onboarding.show() }
        }
        // Panel opened → sync (SPEC §6: on panel open).
        NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { [weak self] note in
            guard note.object is CommandPanel else { return }
            MainActor.assumeIsolated { if let self, self.service.isUnlocked { Task { await self.service.sync(reason: "panel") } } }
        }
        #if DEBUG
        DebugTools.installSnapshotListener()
        DebugTools.runOnboardingTourIfRequested(service)
        DebugFlow.runIfRequested()
        DebugTools.runAutopilotIfRequested()
        #endif
    }

    func showMainWindow() {
        Task {
            // `openMainWindow` is installed by the menu-bar label a moment after launch.
            for _ in 0..<20 where openMainWindow == nil { try? await Task.sleep(for: .milliseconds(150)) }
            openMainWindow?()
            NSApp.activate()
        }
    }

    private var isScriptedFlow: Bool {
        #if DEBUG
        ProcessInfo.processInfo.environment["BISEL_DEV_FLOW"] != nil
        #else
        false
        #endif
    }

    func terminate() { SecureClipboard.shared.clearOnTerminate() }

    // MARK: panel actions

    private func wirePanelActions() {
        panelModel.runUnlock = { [weak self] in self?.unlockFromPanel() }

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
            let hosts = vault.hosts(for: id)
            Task {
                let outcome = await FillEngine.shared.fill(plan, into: target, itemHosts: hosts) { kind in
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
            if let url = vault.url(for: item.id) {
                if let why = URLPolicy.openWithPolicy(url.absoluteString) { Toast.shared.show(why, isError: true) }
            } else {
                Toast.shared.show("This item has no web address that can be opened", isError: true)
            }
        }
    }

    /// Touch ID right in the panel; with no vault on this Mac yet, send the user to set-up in the main window.
    private func unlockFromPanel() {
        guard service.phase != .needsSetup else {
            panelController.hide()
            showMainWindow()
            return
        }
        guard !panelController.authenticating else { return }
        panelController.authenticating = true
        Task {
            defer { panelController.authenticating = false }
            do { try await service.unlock(reason: "Unlock your box to use the command panel") }
            catch KeyStoreError.userCancelled {}
            catch BiometricGate.Failure.denied {}
            catch { Toast.shared.show(describe(error), isError: true) }
        }
    }

    private func finish(_ outcome: FillOutcome, itemID: String) {
        switch outcome {
        case .filled(let text):
            vault.recordUse(id: itemID)
            Log.fill.notice("\(text)")
        case .needsAccessibility:
            onboarding.show()
        case .notATextField(let why):
            Toast.shared.show(why, isError: true)
        case .failed(let why):
            Toast.shared.show(why, isError: true)
        }
    }
}
