import AppKit
import AuthenticationServices
import BiselAgent

/// The system AutoFill provider (docs/SPEC.md §8, "AutoFill"). It holds no keys and opens no store: it asks the running app over the
/// App Group socket, and the app does Touch ID and answers with one password or one passkey signature. The screen is the plainest one the system needs.
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
        if let request = credentialRequest as? ASPasskeyCredentialRequest {
            guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else { cancel(.credentialIdentityNotFound); return }
            sign(rpID: identity.relyingPartyIdentifier, credentialID: identity.credentialID, clientDataHash: request.clientDataHash)
            return
        }
        guard let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity, let id = identity.recordIdentifier else {
            cancel(.credentialIdentityNotFound)
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
            case .candidates(let list):
                offer(String(localized: "Choose a login"), list.map { $0.username.isEmpty ? $0.title : "\($0.title) – \($0.username)" }) { [self] in
                    fetch(list[$0].id)
                }
            case .refused(let code): refused(code)
            default: cancel(.failed)
            }
        }
    }

    /// Passkeys first; a site's page can ask for either, so with none here it falls back to its passwords.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        let rpID = requestParameters.relyingPartyIdentifier, hash = requestParameters.clientDataHash
        show(String(localized: "Waiting for Touch ID in Bisel"))
        Task {
            switch await AppLink.ask(.passkeys(rpID: rpID, allowList: requestParameters.allowedCredentials)) {
            case .passkeys(let list) where list.isEmpty: prepareCredentialList(for: serviceIdentifiers)
            case .passkeys(let list):
                offer(String(localized: "Choose a passkey"), list.map(\.userName)) { [self] in
                    sign(rpID: rpID, credentialID: list[$0].credentialID, clientDataHash: hash)
                }
            case .refused(let code): refused(code)
            default: cancel(.failed)
            }
        }
    }

    private func fetch(_ id: String) {
        show(String(localized: "Waiting for Touch ID in Bisel"))
        Task {
            switch await AppLink.ask(.credential(id: id, services: services)) {
            case .credential(let username, let password):
                let credential = ASPasswordCredential(user: username, password: String(decoding: password.bytes, as: UTF8.self))
                await extensionContext.completeRequest(withSelectedCredential: credential)
            case .refused(let code): refused(code)
            default: cancel(.failed)
            }
        }
    }

    // MARK: passkeys

    /// The app holds the key and signs; only the signature comes back here (docs/SPEC.md §8, "AutoFill").
    private func sign(rpID: String, credentialID: Data, clientDataHash: Data) {
        show(String(localized: "Waiting for Touch ID in Bisel"))
        Task {
            switch await AppLink.ask(.passkeyAssertion(rpID: rpID, credentialID: credentialID, clientDataHash: clientDataHash)) {
            case .assertion(let id, let userHandle, let authenticatorData, let signature):
                let credential = ASPasskeyAssertionCredential(userHandle: userHandle, relyingParty: rpID, signature: signature,
                                                              clientDataHash: clientDataHash, authenticatorData: authenticatorData, credentialID: id)
                _ = await extensionContext.completeAssertionRequest(using: credential)
            case .refused(let code): refused(code)
            default: cancel(.failed)
            }
        }
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else { cancel(.failed); return }
        let rpID = identity.relyingPartyIdentifier, hash = request.clientDataHash
        let registration = AutoFillPasskeyRegistration(rpID: rpID, userHandle: identity.userHandle, userName: identity.userName,
                                                       userDisplayName: identity.userName,
                                                       algorithms: request.supportedAlgorithms.map { $0.rawValue },
                                                       excludedCredentialIDs: (request.excludedCredentials ?? []).map(\.credentialID))
        show(String(localized: "Waiting for Touch ID in Bisel"))
        Task {
            switch await AppLink.ask(.passkeyRegistration(registration)) {
            case .registered(let id, let attestationObject):
                let credential = ASPasskeyRegistrationCredential(relyingParty: rpID, clientDataHash: hash, credentialID: id, attestationObject: attestationObject)
                _ = await extensionContext.completeRegistrationRequest(using: credential)
            case .refused(let code): refused(code)
            default: cancel(.failed)
            }
        }
    }

    // MARK: screen

    private func show(_ text: String) {
        status.stringValue = text
        choices.setViews([], in: .top)
    }

    private func offer(_ heading: String, _ names: [String], pick: @escaping (Int) -> Void) {
        show(heading)
        for (index, name) in names.enumerated() {
            let button = NSButton(title: name, target: self, action: #selector(choiceTapped))
            button.tag = index
            choices.addArrangedSubview(button)
        }
        self.pick = pick
    }

    private var pick: ((Int) -> Void)?

    @objc private func choiceTapped(_ sender: NSButton) { pick?(sender.tag) }
    @objc private func cancelTapped() { cancel(.userCanceled) }

    private func refused(_ code: AgentCode) {
        switch code {
        case .denied, .timeout: cancel(.userCanceled)
        case .appNotRunning: show(String(localized: "Open Bisel and try again"))
        case .wrongSite, .notFound, .noSuchField: cancel(.credentialIdentityNotFound)
        case .excludedCredential: cancel(.matchedExcludedCredential)
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
