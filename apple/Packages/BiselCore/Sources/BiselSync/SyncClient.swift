import Foundation
import BiselCrypto
import BiselVault

public enum SyncError: Error, Sendable, Equatable {
    /// The uniform bare 404: revoked device, bad signature, clock skew, wrong server, or a bootstrapped/unknown route.
    case notAuthorized
    case conflict(current: StoredRecord?)
    case exists
    case tooLarge
    case notFound
    case server(status: Int, code: String?)
    case network(String)
    case malformedResponse
}

public enum PutOutcome: Sendable, Equatable {
    case accepted(StoredRecord)
    case conflict(current: StoredRecord?)
}

public struct SyncPage: Sendable {
    public let records: [StoredRecord]
    public let hasMore: Bool
    public let nextSince: Int
    public let headSeq: Int
    public let devices: [DeviceInfo]
    public let recovery: RecoveryMaterial?
}

/// Signed HTTP client for SPEC §6. Stateless apart from the URLSession.
public struct SyncClient: Sendable {
    public let baseURL: URL
    let signer: RequestSigner?
    let session: URLSession

    public init(baseURL: URL, signer: RequestSigner?, session: URLSession? = nil) {
        self.baseURL = baseURL
        self.signer = signer
        if let session { self.session = session } else {
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 20
            config.urlCache = nil
            config.httpCookieStorage = nil
            self.session = URLSession(configuration: config)
        }
    }

    // MARK: endpoints

    public static func bootstrap(baseURL: URL, token: String, device: WireDevice, recoveryPublicKey: Data,
                                 recoveryEnvelope: Data) async throws {
        let client = SyncClient(baseURL: baseURL, signer: nil)
        let body = try JSONCoding.encoder.encode(BootstrapRequest(device: device, recoveryPubkey: recoveryPublicKey.base64URLEncoded(),
                                                                 recoveryEnvelope: recoveryEnvelope.base64URLEncoded()))
        _ = try await client.send("POST", "/v1/bootstrap", body: body, headers: ["X-Bisel-Bootstrap": token])
    }

    public func pull(since: Int, limit: Int = 200) async throws -> SyncPage {
        let (data, _) = try await send("GET", "/v1/sync", query: [("since", String(since)), ("limit", String(limit))])
        let page = try decode(SyncPageWire.self, data)
        let records = page.items.compactMap(\.record)
        guard records.count == page.items.count else { throw SyncError.malformedResponse }
        return SyncPage(records: records, hasMore: page.hasMore, nextSince: page.nextSince, headSeq: page.headSeq,
                        devices: page.devices, recovery: page.recovery)
    }

    public func put(id: String, baseRev: Int, blob: Data) async throws -> PutOutcome {
        let body = try JSONCoding.encoder.encode(PutRequest(baseRev: baseRev, blob: blob.base64URLEncoded()))
        return try await mutate("PUT", "/v1/items/\(id)", body: body)
    }

    public func delete(id: String, baseRev: Int) async throws -> PutOutcome {
        try await mutate("DELETE", "/v1/items/\(id)", query: [("base_rev", String(baseRev))])
    }

    public func devices() async throws -> [DeviceInfo] {
        let (data, _) = try await send("GET", "/v1/devices")
        return try decode(DevicesResponse.self, data).devices
    }

    public func addDevice(_ device: WireDevice) async throws {
        _ = try await send("POST", "/v1/devices", body: try JSONCoding.encoder.encode(device))
    }

    public func revokeDevice(id: String) async throws {
        _ = try await send("DELETE", "/v1/devices/\(id)")
    }

    public func envelope() async throws -> Data {
        let (data, _) = try await send("GET", "/v1/envelope")
        guard let env = Data(base64URLEncoded: try decode(EnvelopeResponse.self, data).envelope) else { throw SyncError.malformedResponse }
        return env
    }

    public func rotateRecovery(publicKey: Data, envelope: Data) async throws {
        let body = try JSONCoding.encoder.encode(RotateRequest(recoveryPubkey: publicKey.base64URLEncoded(),
                                                              recoveryEnvelope: envelope.base64URLEncoded()))
        _ = try await send("POST", "/v1/recovery/rotate", body: body)
    }

    /// Step 1 of recovery: empty body, returns the recovery envelope. Client must be signed with `RecoverySigner`.
    public func recoveryEnvelope() async throws -> Data {
        let (data, _) = try await send("POST", "/v1/recovery/session")
        guard let env = Data(base64URLEncoded: try decode(RecoverySessionResponse.self, data).recoveryEnvelope) else { throw SyncError.malformedResponse }
        return env
    }

    /// Step 3 of recovery: registers the replacement device.
    public func recoveryRegister(device: WireDevice) async throws {
        _ = try await send("POST", "/v1/recovery/session", body: try JSONCoding.encoder.encode(RecoverySessionRequest(device: device)))
    }

    // MARK: plumbing

    private func mutate(_ method: String, _ path: String, query: [(String, String)] = [], body: Data = Data()) async throws -> PutOutcome {
        do {
            let (data, _) = try await send(method, path, query: query, body: body)
            guard let rec = try decode(ItemResponse.self, data).item.record else { throw SyncError.malformedResponse }
            return .accepted(rec)
        } catch SyncError.conflict(let current) {
            return .conflict(current: current)
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try JSONCoding.decoder.decode(type, from: data) } catch { throw SyncError.malformedResponse }
    }

    private func send(_ method: String, _ path: String, query: [(String, String)] = [], body: Data = Data(),
                      headers: [String: String] = [:]) async throws -> (Data, HTTPURLResponse) {
        var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
        let basePath = components.path.hasSuffix("/") ? String(components.path.dropLast()) : components.path
        let fullPath = basePath + path
        components.percentEncodedPath = fullPath
        let canonicalQuery = Canonical.sortedQuery(query)
        components.percentEncodedQuery = canonicalQuery.isEmpty ? nil : canonicalQuery
        guard let url = components.url else { throw SyncError.malformedResponse }

        var request = URLRequest(url: url)
        request.httpMethod = method
        if !body.isEmpty {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
        if let signer {
            let ts = String(Int(Date().timeIntervalSince1970))
            let nonce = BiselRandom.nonce()
            let canonical = Canonical.string(method: method, path: fullPath, query: canonicalQuery, body: body, ts: ts, nonce: nonce)
            request.setValue(signer.deviceHeader, forHTTPHeaderField: "X-Bisel-Device")
            request.setValue(ts, forHTTPHeaderField: "X-Bisel-Ts")
            request.setValue(nonce, forHTTPHeaderField: "X-Bisel-Nonce")
            request.setValue(try signer.sign(Data(canonical.utf8)).base64URLEncoded(), forHTTPHeaderField: "X-Bisel-Sig")
        }

        let data: Data, response: URLResponse
        do { (data, response) = try await session.data(for: request) }
        catch { throw SyncError.network(error.localizedDescription) }
        guard let http = response as? HTTPURLResponse else { throw SyncError.malformedResponse }

        switch http.statusCode {
        case 200..<300: return (data, http)
        case 404 where data.isEmpty: throw SyncError.notAuthorized
        case 404: throw SyncError.notFound
        case 409:
            let body = try? JSONCoding.decoder.decode(ConflictResponse.self, from: data)
            if body?.error == "exists" { throw SyncError.exists }
            throw SyncError.conflict(current: body?.current?.record)
        case 413: throw SyncError.tooLarge
        default:
            let code = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw SyncError.server(status: http.statusCode, code: code)
        }
    }
}

enum JSONCoding {
    static let encoder: JSONEncoder = { let e = JSONEncoder(); e.keyEncodingStrategy = .convertToSnakeCase; return e }()
    static let decoder: JSONDecoder = { let d = JSONDecoder(); d.keyDecodingStrategy = .convertFromSnakeCase; return d }()
}
