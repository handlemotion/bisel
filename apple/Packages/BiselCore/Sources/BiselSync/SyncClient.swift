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
    /// The vault key was rotated since this device last synced; its blob is wrapped under the old one.
    case staleEpoch(serverEpoch: Int)
}

/// Vault-key rotation (SPEC §4/§6/§7). A separate type, not more cases on `SyncError`, so existing exhaustive switches keep compiling.
public enum RotationError: Error, Sendable, Equatable, LocalizedError {
    /// A request carried key material built for an older epoch: the vault key was rotated elsewhere.
    case staleEpoch(serverEpoch: Int)
    /// This device found out the vault key was rotated. It locked itself: unlock (Touch ID) to continue.
    case vaultKeyRotated
    /// Others kept editing for the whole retry budget. Nothing was changed; try again.
    case tooManyConflicts
    /// Local edits that have not reached the server yet. They must be pushed (sync) before the key can rotate.
    case pendingChanges(Int)
    /// Items that do not decrypt under the current key (tampered, or from a failed import). Delete them first.
    case undecryptableItems([String])
    /// Recovery material from before rotation existed: run `rotateRecovery()` once to upgrade it.
    case recoveryNeedsUpgrade
    /// Use another device to revoke this one.
    case cannotRevokeThisDevice
    case deviceNotFound(String)
    case inProgress

    public var errorDescription: String? {
        switch self {
        case .staleEpoch: return "The vault key was changed on another device. Sync, unlock and try again."
        case .vaultKeyRotated: return "The vault key was changed on another device. Unlock to continue."
        case .tooManyConflicts: return "The vault kept changing while the key was being rotated. Nothing was changed; try again."
        case .pendingChanges(let n): return "\(n) local change(s) are not synced yet. Sync first."
        case .undecryptableItems(let ids): return "\(ids.count) item(s) cannot be decrypted and block the rotation. Delete them first."
        case .recoveryNeedsUpgrade: return "Create a new recovery phrase first (this vault predates key rotation)."
        case .cannotRevokeThisDevice: return "A device cannot revoke itself. Revoke it from another device."
        case .deviceNotFound: return "That device is not in this vault."
        case .inProgress: return "A key rotation is already in progress."
        }
    }
}

public enum RotateOutcome: Sendable, Equatable {
    case rotated(epoch: Int, headSeq: Int)
    /// Something changed since the snapshot (an edit, a device, another rotation). Sync and retry.
    case conflict(epoch: Int?, headSeq: Int?)
}

public struct SyncPage: Sendable {
    public let records: [StoredRecord]
    public let hasMore: Bool
    public let nextSince: Int
    public let headSeq: Int
    /// Epoch of the vault key currently in force.
    public let epoch: Int
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
                                 recoveryEncryptionPublicKey: Data, recoveryEnvelope: Data) async throws {
        let client = SyncClient(baseURL: baseURL, signer: nil)
        let body = try JSONCoding.encoder.encode(BootstrapRequest(device: device, recoveryPubkey: recoveryPublicKey.base64URLEncoded(),
                                                                 recoveryEncPubkey: recoveryEncryptionPublicKey.base64URLEncoded(),
                                                                 recoveryEnvelope: recoveryEnvelope.base64URLEncoded()))
        _ = try await client.send("POST", "/v1/bootstrap", body: body, headers: ["X-Bisel-Bootstrap": token])
    }

    public func pull(since: Int, limit: Int = 200) async throws -> SyncPage {
        let (data, _) = try await send("GET", "/v1/sync", query: [("since", String(since)), ("limit", String(limit))])
        let page = try decode(SyncPageWire.self, data)
        let records = page.items.compactMap(\.record)
        guard records.count == page.items.count else { throw SyncError.malformedResponse }
        return SyncPage(records: records, hasMore: page.hasMore, nextSince: page.nextSince, headSeq: page.headSeq,
                        epoch: page.epoch, devices: page.devices, recovery: page.recovery)
    }

    /// `epoch` is the epoch of the vault key the blob's item key is wrapped under.
    public func put(id: String, baseRev: Int, blob: Data, epoch: Int) async throws -> PutOutcome {
        let body = try JSONCoding.encoder.encode(PutRequest(baseRev: baseRev, epoch: epoch, blob: blob.base64URLEncoded()))
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

    /// This device's own envelope and the epoch of the vault key inside it.
    public func envelope() async throws -> (envelope: Data, epoch: Int) {
        let (data, _) = try await send("GET", "/v1/envelope")
        let r = try decode(EnvelopeResponse.self, data)
        guard let env = Data(base64URLEncoded: r.envelope), !env.isEmpty else { throw SyncError.malformedResponse }
        return (env, r.epoch)
    }

    /// Replaces the recovery key (new phrase). `epoch` is the epoch of the VK the new envelope was sealed from.
    public func rotateRecovery(publicKey: Data, encryptionPublicKey: Data, envelope: Data, epoch: Int) async throws {
        let body = try JSONCoding.encoder.encode(RecoveryRotateRequest(recoveryPubkey: publicKey.base64URLEncoded(),
                                                                      recoveryEncPubkey: encryptionPublicKey.base64URLEncoded(),
                                                                      recoveryEnvelope: envelope.base64URLEncoded(), epoch: epoch))
        _ = try await send("POST", "/v1/recovery/rotate", body: body)
    }

    /// Step 1 of recovery: empty body, returns the recovery envelope and the epoch it belongs to. Client must be signed with `RecoverySigner`.
    public func recoveryEnvelope() async throws -> (envelope: Data, epoch: Int) {
        let (data, _) = try await send("POST", "/v1/recovery/session")
        let r = try decode(RecoverySessionResponse.self, data)
        guard let env = Data(base64URLEncoded: r.recoveryEnvelope) else { throw SyncError.malformedResponse }
        return (env, r.epoch)
    }

    /// Step 3 of recovery: registers the replacement device. `epoch` is the one step 1 returned.
    public func recoveryRegister(device: WireDevice, epoch: Int) async throws {
        _ = try await send("POST", "/v1/recovery/session", body: try JSONCoding.encoder.encode(RecoverySessionRequest(device: device, epoch: epoch)))
    }

    /// Vault-key rotation, atomically (`POST /v1/rotate`): new wrapped key for each live item, new envelope for each
    /// remaining device, new recovery envelope, optionally revoking one device. The server applies all of it or none.
    public func rotate(baseEpoch: Int, baseSeq: Int, revoke: String?, items: [(id: String, rev: Int, wrappedKey: Data)],
                       devices: [(id: String, envelope: Data)], recoveryEnvelope: Data) async throws -> RotateOutcome {
        let body = try JSONCoding.encoder.encode(RotateRequest(
            baseEpoch: baseEpoch, baseSeq: baseSeq, revoke: revoke,
            items: items.map { RotateItemWire(id: $0.id, rev: $0.rev, key: $0.wrappedKey.base64URLEncoded()) },
            devices: devices.map { RotateDeviceWire(id: $0.id, envelope: $0.envelope.base64URLEncoded()) },
            recoveryEnvelope: recoveryEnvelope.base64URLEncoded()))
        let (data, http) = try await perform("POST", "/v1/rotate", body: body)
        if http.statusCode == 409, let c = try? JSONCoding.decoder.decode(ConflictResponse.self, from: data), c.error == "conflict" {
            return .conflict(epoch: c.epoch, headSeq: c.headSeq)
        }
        try check(data, http)
        let r = try decode(RotateResponse.self, data)
        return .rotated(epoch: r.epoch, headSeq: r.headSeq)
    }

    // MARK: plumbing

    private func mutate(_ method: String, _ path: String, query: [(String, String)] = [], body: Data = Data()) async throws -> PutOutcome {
        do {
            let (data, _) = try await send(method, path, query: query, body: body)
            guard let rec = try decode(ItemResponse.self, data).item.record else { throw SyncError.malformedResponse }
            return .accepted(rec)
        } catch SyncError.conflict(let current) {
            return .conflict(current: current)
        } catch RotationError.staleEpoch(let serverEpoch) {
            return .staleEpoch(serverEpoch: serverEpoch)
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try JSONCoding.decoder.decode(type, from: data) } catch { throw SyncError.malformedResponse }
    }

    private func send(_ method: String, _ path: String, query: [(String, String)] = [], body: Data = Data(),
                      headers: [String: String] = [:]) async throws -> (Data, HTTPURLResponse) {
        let (data, http) = try await perform(method, path, query: query, body: body, headers: headers)
        try check(data, http)
        return (data, http)
    }

    /// Builds, signs and sends the request; returns whatever the server answered, whatever the status.
    private func perform(_ method: String, _ path: String, query: [(String, String)] = [], body: Data = Data(),
                         headers: [String: String] = [:]) async throws -> (Data, HTTPURLResponse) {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else { throw SyncError.malformedResponse }
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
        return (data, http)
    }

    /// Maps a non-2xx answer to a typed error. Never includes response bodies in the error text.
    private func check(_ data: Data, _ http: HTTPURLResponse) throws {
        switch http.statusCode {
        case 200..<300: return
        case 404 where data.isEmpty: throw SyncError.notAuthorized
        case 404: throw SyncError.notFound
        case 409:
            let body = try? JSONCoding.decoder.decode(ConflictResponse.self, from: data)
            if body?.error == "exists" { throw SyncError.exists }
            if body?.error == "stale_epoch" { throw RotationError.staleEpoch(serverEpoch: body?.epoch ?? 0) }
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
