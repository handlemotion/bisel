import Foundation

/// What travels between the `bisel` tool and the app (docs/AGENT-CLI.md). The tool links only this module: it holds no keys.

/// A secret on its way through the socket. Its textual and reflected forms show nothing, so printing a request or a result cannot
/// leak one.
public struct AgentSecret: Codable, Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public let bytes: Data
    public init(_ bytes: Data) { self.bytes = bytes }
    public init(_ text: String) { bytes = Data(text.utf8) }
    public var description: String { "[hidden]" }
    public var debugDescription: String { "[hidden]" }
    public var customMirror: Mirror { Mirror(self, children: []) }
}

public enum AgentField: Codable, Sendable, Equatable {
    case password, username, totp
    case custom(String)
}

/// `<id>`, `<id>:username`, `<id>:totp` or `<id>:field:<label>`. Item ids are base64url, so they never hold a colon.
public struct AgentSecretRef: Codable, Sendable, Equatable {
    public var item: String
    public var field: AgentField

    public init(item: String, field: AgentField = .password) { self.item = item; self.field = field }

    public init?(parsing text: String) {
        let parts = text.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false).map(String.init)
        guard let id = parts.first, !id.isEmpty else { return nil }
        switch parts.count {
        case 1: self.init(item: id)
        case 2 where parts[1] == "password": self.init(item: id)
        case 2 where parts[1] == "username": self.init(item: id, field: .username)
        case 2 where parts[1] == "totp": self.init(item: id, field: .totp)
        case 3 where parts[1] == "field" && !parts[2].isEmpty: self.init(item: id, field: .custom(parts[2]))
        default: return nil
        }
    }
}

public struct AgentItemFields: Codable, Sendable, Equatable {
    public var title: String?
    public var url: String?
    public var username: String?
    public init(title: String? = nil, url: String? = nil, username: String? = nil) {
        self.title = title; self.url = url; self.username = username
    }
    public var isEmpty: Bool { title == nil && url == nil && username == nil }
}

public enum AgentRequest: Codable, Sendable {
    case status
    case search(String)
    /// `command[0]` is the full path the tool will run, exactly as the approval prompt shows it.
    case run(refs: [AgentSecretRef], command: [String])
    case fill(id: String, login: Bool, submit: Bool)
    case add(AgentItemFields, password: AgentSecret?)
    case edit(id: String, AgentItemFields)
    case trash(id: String)
}

public struct AgentStatus: Codable, Sendable, Equatable {
    public var unlocked: Bool
    public var agentsAllowed: Bool
    public init(unlocked: Bool, agentsAllowed: Bool) { self.unlocked = unlocked; self.agentsAllowed = agentsAllowed }
}

/// Metadata only: never a password, username, note or code.
public struct AgentItem: Codable, Sendable, Equatable {
    public var id: String
    public var title: String
    public var domain: String?
    public var has: [String]
    public var fields: [String]
    public init(id: String, title: String, domain: String?, has: [String], fields: [String]) {
        self.id = id; self.title = title; self.domain = domain; self.has = has; self.fields = fields
    }
}

public enum AgentResult: Codable, Sendable {
    case status(AgentStatus)
    case items([AgentItem])
    case saved(id: String)
    case done
    /// Only ever an answer to `.run`, in the order of its refs. The tool hands these to the child and never prints them.
    case secrets([AgentSecret])
    case refused(AgentCode)
}

/// Every failure is one of these codes. The hint is fixed text, so an error can never carry a value.
public enum AgentCode: String, Codable, Sendable, CaseIterable {
    case appNotRunning = "app_not_running"
    case untrustedApp = "untrusted_app"
    case agentsOff = "agents_off"
    case locked
    case denied
    case timeout
    case busy
    case notFound = "not_found"
    case noSuchField = "no_such_field"
    case wrongSite = "wrong_site"
    case notPasswordField = "not_password_field"
    case noAccessibility = "no_accessibility"
    case fillFailed = "fill_failed"
    case commandRefused = "command_refused"
    case conflict
    case badRequest = "bad_request"
    case failed

    public var hint: String {
        switch self {
        case .appNotRunning: "Ask the person to open Bisel."
        case .untrustedApp: "The process answering is not the signed Bisel app. Stop and tell the person."
        case .agentsOff: "Ask the person to turn on Allow agents in Bisel's Security settings."
        case .locked: "Ask the person to unlock Bisel."
        case .denied: "The person declined, or Touch ID is unavailable. Do not retry without asking them."
        case .timeout: "Nobody answered the Touch ID prompt."
        case .busy: "Another request is waiting. Try again when it finishes."
        case .notFound: "No item has that id. Use bl search."
        case .noSuchField: "That item has no such field. bl search lists what it has."
        case .wrongSite: "Fill works only in a browser, on a page matching the item's URL."
        case .notPasswordField: "Focus the password or code field. With --login, focus the username field."
        case .noAccessibility: "Ask the person to turn on Accessibility for Bisel."
        case .fillFailed: "Typing stopped: focus moved, or the next field is not a password field."
        case .commandRefused: "Use a command with no control characters, short enough to show in full."
        case .conflict: "The item changed on another device. Search again and retry."
        case .badRequest: "Run bl --help."
        case .failed: "Bisel could not do that."
        }
    }
}

public struct AgentError: Error, Sendable, Equatable {
    public let code: AgentCode
    public init(_ code: AgentCode) { self.code = code }
}
