import LocalAuthentication
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
    /// Polls from the start (scripted dev flows skip `start()`), so the pill, the Fill page and set-up never read a stale value.
    let accessibility: AccessibilityMonitor = {
        let m = AccessibilityMonitor()
        m.start()
        return m
    }()

    /// Set by the SwiftUI scene so non-view code can open the main window.
    var openMainWindow: (() -> Void)?

    /// Answers the `bisel` tool (docs/AGENT-CLI.md). Nil only when the box store could not open.
    private(set) var agentBroker: AgentBroker?
    private var agentListener: AgentListener?
    private var autoFillListener: SocketListener<AutoFillRequest, AutoFillResult>?

    private init() {
        #if DEBUG
        PanelBoxPerf.mark("launch.app model begins")
        #endif
        #if BISEL_DEV_FIXTURE
        vault = BiselEnvironment.useDevFixture ? DevFixtureVault() : service
        #else
        vault = service
        #endif
        panelModel = CommandPanelModel(source: vault, secrets: vault)
        #if DEBUG
        PanelBoxPerf.mark("launch.vault service built")
        #endif
        panelController = CommandPanelController(model: panelModel)
        wirePanelActions()
        #if DEBUG
        PanelBoxPerf.mark("launch.panel built")
        // Scripted flow runs (BISEL_DEV_FLOW) must not grab the global hotkey or open windows on someone's screen.
        if ProcessInfo.processInfo.environment["BISEL_DEV_FLOW"] != nil { KeyboardShortcuts.disable(.commandPanel) }
        #endif
    }

    func start() {
        Log.app.notice("bisel started; accessibility trusted=\(AccessibilityInspector.isTrusted())")
        service.onLockStateChange = { [weak self] in
            self?.panelModel.refresh()
            if let broker = self?.agentBroker { Task { await broker.resetSearchWindow() } }
        }
        service.onRowsChange = { [weak self] in self?.panelModel.refresh(keepingSelection: true) }
        startAgentListener()
        startAutoFillListener()
        Task { await LoginItem.shared.refresh() }
        Task {
            await service.start()
            #if DEBUG
            PanelBoxPerf.mark("launch.phase known")
            if ProcessInfo.processInfo.environment["BISEL_DEV_AUTOUNLOCK"] == "1", service.phase == .locked {
                Log.app.fault("BISEL_DEV_AUTOUNLOCK=1 (debug build only)")
                try? await service.unlock(reason: "dev autounlock")
            }
            #endif
            // First launch: the main window is where set-up happens (Accessibility is one of its steps; later the panel's pill).
            if isScriptedFlow { return }
            if service.phase == .needsSetup && !BiselEnvironment.useDevFixture { showMainWindow() }
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

    private func startAgentListener() {
        guard let vault = service.vault else { return }
        let broker = AgentBroker(vault: vault, host: AppAgentHost(service: service))
        let listener = AgentListener(path: AgentAccess.socketPath, clientRequirement: AgentAccess.clientRequirement) { request in
            await broker.handle(request)
        }
        do {
            try listener.start()
            agentBroker = broker
            agentListener = listener
        } catch {
            Log.app.error("agent socket could not start")
        }
    }

    /// The AutoFill extension's way in. It asks here for everything: it has no keys and no store of its own (docs/SPEC.md §8, "AutoFill").
    private func startAutoFillListener() {
        guard let vault = service.vault, let path = AppAutoFillHost.socketPath else { return }
        let broker = AutoFillBroker(vault: vault, host: AppAutoFillHost(service: service), isPublicSuffix: DomainName.isPublicSuffix)
        let listener = SocketListener<AutoFillRequest, AutoFillResult>(path: path, clientRequirement: AgentPeer.autoFillRequirement) { request in
            await broker.handle(request)
        }
        do {
            try listener.start()
            autoFillListener = listener
        } catch {
            Log.app.error("autofill socket could not start")
        }
    }

    /// The settings window on one page (an open window switches to it).
    func showSettings(_ page: SettingsPage) {
        UserDefaults.standard.set(page.rawValue, forKey: SettingsPage.defaultsKey)
        NotificationCenter.default.post(name: SettingsPage.showNotification, object: page)
        showMainWindow()
    }

    func showMainWindow() {
        Task {
            // `openMainWindow` is installed by the menu-bar label a moment after launch.
            for _ in 0..<20 where openMainWindow == nil { try? await Task.sleep(for: .milliseconds(150)) }
            openMainWindow?()
            NSApp.activate()
        }
    }

    /// Settings works on a locked box: an action that needs the box (export, a new phrase, import, devices) asks for Touch ID
    /// with the unlock prompt right then. Throws `KeyStoreError.userCancelled` when the person cancels.
    func unlockIfLocked(_ reason: String) async throws {
        if service.phase == .locked { try await service.unlock(reason: reason) }
    }

    private var isScriptedFlow: Bool {
        #if DEBUG
        ProcessInfo.processInfo.environment["BISEL_DEV_FLOW"] != nil
        #else
        false
        #endif
    }

    func terminate() {
        SecureClipboard.shared.clearOnTerminate()
        // Quitting leaves nothing of the box in the system's store. Bounded: a stuck store must not hold up quitting; the next launch clears it.
        let identities = service.autoFillIdentities, done = DispatchSemaphore(value: 0)
        identities.clear()
        Task.detached {
            await identities.settled()
            done.signal()
        }
        _ = done.wait(timeout: .now() + 1)
    }

    // MARK: panel actions

    private func wirePanelActions() {
        panelModel.runUnlock = { [weak self] in self?.unlockFromPanel() }
        panelModel.runEmbeddedUnlock = { [weak self] in self?.unlockInPanel(with: $0) }
        panelModel.runOpenSettings = { [weak self] page in
            self?.panelController.hide("settings", immediate: true)
            self?.showSettings(page)
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
                        Toast.shared.show("\(what) copied. Clears in \(SecureClipboard.clearSeconds) s")
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
        guard !panelController.authenticating, panelModel.unlockContext == nil else { return }
        // Touch ID shows in the card, so there is no sheet on top of it. The card starts `unlockInPanel` once its view exists.
        guard BiselEnvironment.usesSoftwareKeys else { panelModel.unlockContext = LAContext(); return }
        panelController.authenticating = true
        Task {
            defer { panelController.authenticating = false }
            do { try await service.unlock(reason: "Unlock your box to use the command panel") }
            catch KeyStoreError.userCancelled {}
            catch BiometricGate.Failure.denied {}
            catch { Toast.shared.show(describe(error), isError: true) }
        }
    }

    private func unlockInPanel(with context: LAContext) {
        Task {
            defer { if panelModel.unlockContext === context { panelModel.unlockContext = nil } }
            do { try await service.unlock(reason: "Unlock your box to use the command panel", prompt: EmbeddedPrompt(context)) }
            catch KeyStoreError.userCancelled {}
            catch { Toast.shared.show(describe(error), isError: true) }
        }
    }

    private func finish(_ outcome: FillOutcome, itemID: String) {
        switch outcome {
        case .filled(let text):
            vault.recordUse(id: itemID)
            Log.fill.notice("\(text)")
        case .needsAccessibility:
            showSettings(.fill)   // the Permission card, with the button that opens System Settings
        case .notATextField(let why):
            Toast.shared.show(why, isError: true)
        case .failed(let why):
            Toast.shared.show(why, isError: true)
        }
    }
}
