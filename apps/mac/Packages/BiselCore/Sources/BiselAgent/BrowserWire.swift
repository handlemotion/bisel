import Foundation

/// What travels between the Chrome extension, its native host and the app (docs/SPEC.md §8, "Chrome extension"). The host links only
/// this module: it holds no keys and opens no store. The link is write-only: no answer carries anything from the box, and the only
/// thing it tells about a stored login is the one word that picks Save or Update.

public enum BrowserLink {
    /// The native host's name: Chrome finds its manifest by this, and the extension calls it by this.
    public static let hostName = "app.bisel.browser"
    /// Fixed by the `key` in apps/chrome/public/manifest.json.
    public static let extensionID = "hchnaceebnafpeijdmglkmfccfmlcelj"
    public static var extensionOrigin: String { "chrome-extension://\(extensionID)/" }
    public static let version = 1
    /// A login is far smaller. Chrome would send up to 64 MiB.
    public static let maxMessage = 64 * 1024

    /// Debug builds have their own socket, so a dev build and the installed app can run side by side.
    public static func socketPath(debug: Bool) -> String {
        AgentSocket.path(name: debug ? "browser-dev" : "browser")
    }

    /// Chrome's native messaging manifest for the host at `hostPath`. `allowed_origins` takes no wildcards.
    public static func manifest(hostPath: String) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "name": hostName, "description": "Bisel", "path": hostPath, "type": "stdio", "allowed_origins": [extensionOrigin],
        ] as [String: Any], options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }
}

/// A login as a page offered it. `site` is the page's origin, taken by the extension from Chrome, never from the page.
public struct BrowserLogin: Codable, Sendable, Equatable {
    public var site: String
    public var username: String
    public init(site: String, username: String) { self.site = site; self.username = username }
}

/// The type name on the wire says what is asked, so a later `fill.*` adds types and leaves these alone.
public enum BrowserRequest: Sendable, Equatable {
    /// Would this login be new, or an update? Sent before the person has answered, so the password itself stays out of it: only
    /// SHA-256(salt + password), with a fresh random salt.
    case saveCheck(BrowserLogin, salt: Data, digest: Data)
    /// Sent once the person accepted. `replace` is the person's choice of Update: without it no stored password changes.
    case save(BrowserLogin, password: AgentSecret, replace: Bool)
}

public enum BrowserAnswer: Sendable, Equatable {
    /// To `.saveCheck`. `unknown`: the box is locked or the check allowance is spent, so the extension offers Save and the app
    /// decides after Touch ID.
    case new, differs, same, unknown
    /// To `.save`. `exists`: the box holds this login with another password and `replace` was not set, so nothing was written.
    case saved, unchanged, exists
    case refused(AgentCode)
}

/// One request on the wire, in the same shape from Chrome to the host and from the host to the app:
/// `{"v":1,"id":"…","type":"save.check","site":"…","username":"…","salt":"…","digest":"…"}`. Anything else does not decode.
public struct BrowserEnvelope: Codable, Sendable, Equatable {
    public var id: String
    public var request: BrowserRequest
    public init(id: String, request: BrowserRequest) { self.id = id; self.request = request }

    private enum Key: String, CodingKey { case v, id, type, site, username, salt, digest, password, replace }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        guard try c.decode(Int.self, forKey: .v) == BrowserLink.version else {
            throw DecodingError.dataCorruptedError(forKey: .v, in: c, debugDescription: "version")
        }
        id = try c.decode(String.self, forKey: .id)
        let login = BrowserLogin(site: try c.decode(String.self, forKey: .site), username: try c.decode(String.self, forKey: .username))
        switch try c.decode(String.self, forKey: .type) {
        case "save.check":
            request = .saveCheck(login, salt: try c.decode(Data.self, forKey: .salt), digest: try c.decode(Data.self, forKey: .digest))
        case "save":
            request = .save(login, password: AgentSecret(try c.decode(String.self, forKey: .password)), replace: try c.decode(Bool.self, forKey: .replace))
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: c, debugDescription: "type")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        try c.encode(BrowserLink.version, forKey: .v)
        try c.encode(id, forKey: .id)
        switch request {
        case .saveCheck(let login, let salt, let digest):
            try c.encode("save.check", forKey: .type)
            try c.encode(login.site, forKey: .site); try c.encode(login.username, forKey: .username)
            try c.encode(salt, forKey: .salt); try c.encode(digest, forKey: .digest)
        case .save(let login, let password, let replace):
            try c.encode("save", forKey: .type)
            try c.encode(login.site, forKey: .site); try c.encode(login.username, forKey: .username)
            try c.encode(String(decoding: password.bytes, as: UTF8.self), forKey: .password)
            try c.encode(replace, forKey: .replace)
        }
    }
}

/// `{"v":1,"id":"…","result":"saved"}` or `{"v":1,"id":"…","error":"denied"}`.
public struct BrowserReply: Codable, Sendable, Equatable {
    public var id: String
    public var answer: BrowserAnswer
    public init(id: String, answer: BrowserAnswer) { self.id = id; self.answer = answer }

    private enum Key: String, CodingKey { case v, id, result, error }

    private static let results: [(String, BrowserAnswer)] = [
        ("new", .new), ("differs", .differs), ("same", .same), ("unknown", .unknown), ("saved", .saved), ("unchanged", .unchanged), ("exists", .exists),
    ]

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        id = try c.decode(String.self, forKey: .id)
        if let code = try c.decodeIfPresent(AgentCode.self, forKey: .error) { answer = .refused(code); return }
        let name = try c.decode(String.self, forKey: .result)
        guard let found = Self.results.first(where: { $0.0 == name }) else {
            throw DecodingError.dataCorruptedError(forKey: .result, in: c, debugDescription: "result")
        }
        answer = found.1
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        try c.encode(BrowserLink.version, forKey: .v)
        try c.encode(id, forKey: .id)
        if case .refused(let code) = answer { try c.encode(code, forKey: .error); return }
        try c.encode(Self.results.first { $0.1 == answer }?.0, forKey: .result)
    }
}

#if os(macOS)
/// The native host's whole job: check who called, pass one message to the app, pass the answer back. It reads nothing else.
public enum BrowserRelay {
    /// `callerOrigin` is what Chrome gave the host as its first argument. Bytes in, bytes out, both without Chrome's length prefix.
    public static func answer(_ message: Data, callerOrigin: String?, socketPath: String, serverRequirement: String?) -> Data {
        var id = ""
        let answer: BrowserAnswer
        do {
            guard callerOrigin == BrowserLink.extensionOrigin else { throw AgentError(.wrongSite) }
            guard message.count <= BrowserLink.maxMessage, let envelope = try? JSONDecoder().decode(BrowserEnvelope.self, from: message) else {
                throw AgentError(.badRequest)
            }
            id = envelope.id
            let reply: BrowserReply = try AgentSocket.exchange(envelope, path: socketPath, serverRequirement: serverRequirement)
            answer = reply.answer
        } catch {
            answer = .refused((error as? AgentError)?.code ?? .failed)
        }
        return (try? JSONEncoder().encode(BrowserReply(id: id, answer: answer))) ?? Data()
    }
}
#endif
