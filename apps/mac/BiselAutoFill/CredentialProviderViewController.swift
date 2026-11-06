import AppKit
import AuthenticationServices
import BiselAgent

/// The system AutoFill provider (docs/SPEC.md §8, "AutoFill"). It holds no keys and opens no store: it asks the running app over the
/// App Group socket, and the app does Touch ID and answers with one password. The screen is the plainest one the system needs.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let status = NSTextField(wrappingLabelWithString: "")
    private let choices = NSStackView()
    private var services: [String] = []

    override func loadView() {
        choices.orientation = .vertical
        choices.alignment = .leading
        let cancel = NSButton(title: String(localized: "Cancel"), target: self, action: #selector(cancelTapped))
        cancel.keyEquivalent = "\u{1b}"
        let stack = NSStackView(views: [status, choices, cancel])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        stack.widthAnchor.constraint(greaterThanOrEqualToConstant: 320).isActive = true
        view = stack
    }

    // MARK: passwords

    /// Never silent: every password needs Touch ID, so the system comes back through `prepareInterfaceToProvideCredential`.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        cancel(.userInteractionRequired)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        guard credentialRequest.type == .password, let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
              let id = identity.recordIdentifier else {
            if credentialRequest.type != .password { declinePasskey() } else { cancel(.credentialIdentityNotFound) }
            return
        }
        services = [identity.serviceIdentifier.identifier]
        fetch(id)
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        services = serviceIdentifiers.map(\.identifier)
        show(String(localized: "Waiting for Touch ID in Bisel"))
        Task {
            switch await AppLink.ask(.list(services: services)) {
            case .candidates(let list) where list.isEmpty: show(String(localized: "No logins for this site"))
            case .candidates(let list): showChoices(list)
            case .refused(let code): refused(code)
            case .credential: cancel(.failed)
            }
        }
    }

    /// `.domain` and `.URL` requests alike: passkey parameters are ignored until the passkey step below.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        prepareCredentialList(for: serviceIdentifiers)
    }

    private func fetch(_ id: String) {
        show(String(localized: "Waiting for Touch ID in Bisel"))
        Task {
            switch await AppLink.ask(.credential(id: id, services: services)) {
            case .credential(let username, let password):
                let credential = ASPasswordCredential(user: username, password: String(decoding: password.bytes, as: UTF8.self))
                await extensionContext.completeRequest(withSelectedCredential: credential)
            case .refused(let code): refused(code)
            case .candidates: cancel(.failed)
            }
        }
    }

    // MARK: passkeys

    /// The one place passkeys plug in, for assertion and registration alike. Off today: `ProvidesPasskeys` is false in Info.plist, so
    /// the system does not offer Bisel for them. To fill it in: add the request to `AutoFillRequest`, answer it in `AutoFillBroker` (the
    /// app holds the key and signs, as it does for passwords), complete with `completeAssertionRequest` /
    /// `completeRegistrationRequest` here, and set `ProvidesPasskeys` to true (docs/SPEC.md §8, "AutoFill").
    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) { declinePasskey() }

    private func declinePasskey() { cancel(.failed) }

    // MARK: screen

    private func show(_ text: String) {
        status.stringValue = text
        choices.setViews([], in: .top)
    }

    private func showChoices(_ list: [AutoFillCandidate]) {
        show(String(localized: "Choose a login"))
        for (index, candidate) in list.enumerated() {
            let name = candidate.username.isEmpty ? candidate.title : "\(candidate.title) – \(candidate.username)"
            let button = NSButton(title: name, target: self, action: #selector(choiceTapped))
            button.tag = index
            choices.addArrangedSubview(button)
        }
        candidates = list
    }

    private var candidates: [AutoFillCandidate] = []

    @objc private func choiceTapped(_ sender: NSButton) { fetch(candidates[sender.tag].id) }
    @objc private func cancelTapped() { cancel(.userCanceled) }

    private func refused(_ code: AgentCode) {
        switch code {
        case .denied, .timeout: cancel(.userCanceled)
        case .appNotRunning: show(String(localized: "Open Bisel and try again"))
        case .wrongSite, .notFound, .noSuchField: cancel(.credentialIdentityNotFound)
        default: cancel(.failed)
        }
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }
}

/// The app's end of the socket, started when it is not running yet.
enum AppLink {
    static let launchWait: Duration = .seconds(10)

    private static var path: String? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AutoFillSocket.appGroup).map {
            #if DEBUG
            AutoFillSocket.path(container: $0, debug: true)
            #else
            AutoFillSocket.path(container: $0, debug: false)
            #endif
        }
    }

    /// `…/Bisel.app/Contents/PlugIns/BiselAutoFill.appex`: only ever the app this extension shipped in.
    private static var hostApp: URL? {
        let app = Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return app.pathExtension == "app" ? app : nil
    }

    static func ask(_ request: AutoFillRequest) async -> AutoFillResult {
        guard let path else { return .refused(.failed) }
        let first = await send(request, path)
        guard case .refused(.appNotRunning) = first, let hostApp else { return first }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        _ = try? await NSWorkspace.shared.openApplication(at: hostApp, configuration: configuration)
        let deadline = ContinuousClock.now + launchWait
        while ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(250))
            let next = await send(request, path)
            if case .refused(.appNotRunning) = next { continue }
            return next
        }
        return first
    }

    /// Blocking socket work, off the main actor. The peer must be the signed app: an impostor here could hand back a password of its own.
    @concurrent
    private static func send(_ request: AutoFillRequest, _ path: String) async -> AutoFillResult {
        do { return try AgentSocket.exchange(request, path: path, serverRequirement: AgentPeer.appRequirement) }
        catch { return .refused(error.code) }
    }
}
