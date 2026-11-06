import Foundation

/// What travels between the AutoFill extension and the app (docs/SPEC.md §8, "AutoFill"). The extension links only this module: it
/// holds no keys and opens no store. It gets one password or one passkey signature at a time, after Touch ID in the app; a passkey's
/// private key never crosses this socket.

public enum AutoFillSocket {
    /// macOS-style, so it needs no entry on the developer website; the Mac provisioning profiles authorise `<team>.*`.
    public static let appGroup = "ZVGTVNUPVA.app.bisel"

    /// Inside the App Group container, the one place a sandboxed extension may reach a socket. Debug builds have their own, so a
    /// dev build and the installed app can run side by side.
    public static func path(container: URL, debug: Bool) -> String {
        container.appendingPathComponent("autofill/\(debug ? "s-dev" : "s").sock").path
    }
}

public enum AutoFillRequest: Codable, Sendable {
    /// The logins for these sites, after one Touch ID. `services` are what the system asked for: domains or URLs.
    case list(services: [String])
    /// One login's password. Answers after Touch ID, unless the same login just came from a `.list`, which already asked.
    case credential(id: String, services: [String])
    /// The passkeys for this RP ID, after one Touch ID. An empty `allowList` means any of them.
    case passkeys(rpID: String, allowList: [Data])
    /// One signature. Answers after Touch ID, unless the same passkey just came from a `.passkeys`, which already asked.
    case passkeyAssertion(rpID: String, credentialID: Data, clientDataHash: Data)
    /// Makes a passkey in the box, after Touch ID.
    case passkeyRegistration(AutoFillPasskeyRegistration)
}

public struct AutoFillPasskeyRegistration: Codable, Sendable {
    public var rpID: String
    public var userHandle: Data
    public var userName: String
    public var userDisplayName: String
    public var algorithms: [Int]
    public var excludedCredentialIDs: [Data]
    public init(rpID: String, userHandle: Data, userName: String, userDisplayName: String, algorithms: [Int], excludedCredentialIDs: [Data]) {
        self.rpID = rpID; self.userHandle = userHandle; self.userName = userName; self.userDisplayName = userDisplayName
        self.algorithms = algorithms; self.excludedCredentialIDs = excludedCredentialIDs
    }
}

/// No secret: what the extension shows so the person can choose.
public struct AutoFillPasskey: Codable, Sendable, Equatable {
    public var credentialID: Data
    public var userName: String
    public init(credentialID: Data, userName: String) { self.credentialID = credentialID; self.userName = userName }
}

/// No secret: what the extension shows so the person can choose.
public struct AutoFillCandidate: Codable, Sendable, Equatable {
    public var id: String
    public var title: String
    public var username: String
    public init(id: String, title: String, username: String) { self.id = id; self.title = title; self.username = username }
}

public enum AutoFillResult: Codable, Sendable {
    case candidates([AutoFillCandidate])
    case credential(username: String, password: AgentSecret)
    case passkeys([AutoFillPasskey])
    case assertion(credentialID: Data, userHandle: Data, authenticatorData: Data, signature: Data)
    case registered(credentialID: Data, attestationObject: Data)
    case refused(AgentCode)
}
