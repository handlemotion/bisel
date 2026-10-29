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

/// Device-code connect failures that are not the bare 404.
public enum ConnectError: Error, Sendable, Equatable, LocalizedError {
    /// The approving account already owns a box (409 `box_exists`): a second Mac joins it by enrollment or recovery.
    case accountHasBox
    /// The box already belongs to an account (409 `already_linked`).
    case alreadyLinked
    /// The person denied the request, or the code ran out.
    case denied
    case expired

    public var errorDescription: String? {
        switch self {
        case .accountHasBox: return "This account already has a box. Add this Mac from a device that is already connected, or restore with your recovery phrase."
        case .alreadyLinked: return "This box is already linked to an account."
        case .denied: return "The request was denied."
        case .expired: return "The code expired. Start again."
        }
    }
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
        case .staleEpoch: return "The box key was changed on another device. Sync, unlock and try again."
        case .vaultKeyRotated: return "The box key was changed on another device. Unlock to continue."
        case .tooManyConflicts: return "The box kept changing while the key was being rotated. Nothing was changed; try again."
        case .pendingChanges(let n): return "\(n) local change(s) are not synced yet. Sync first."
        case .undecryptableItems(let ids): return "\(ids.count) item(s) cannot be decrypted and block the rotation. Delete them first."
        case .recoveryNeedsUpgrade: return "Create a new recovery phrase first (this box predates key rotation)."
        case .cannotRevokeThisDevice: return "A device cannot revoke itself. Revoke it from another device."
        case .deviceNotFound: return "That device is not in this box."
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
    public let events: [ServerEvent]
    public let recovery: RecoveryMaterial?
}

/// A previous state of an item, as the server retained it (30 days).
public struct HistoryEntry: Sendable, Equatable {
    public enum Kind: String, Sendable { case overwrite, delete, rotate }
    public let serverID: Int
    public let itemID: String
    public let rev: Int
    public let kind: Kind
    public let blob: Data
    public let epoch: Int
    public let replacedAt: Date
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
            config.waitsForConnectivity = false
            // Never follow a redirect: the signed headers must not travel to another origin, and the real server does not redirect.
            self.session = URLSession(configuration: config, delegate: RefuseRedirects(), delegateQueue: nil)
        }
    }

    /// https only; plain http is accepted solely for a server on this machine (development).
    static func isAcceptable(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased() else { return false }
        if scheme == "https" { return true }
        return scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1" || host.hasSuffix(".localhost"))
    }

    /// No response bigger than this is read (a page of 200 items of 256 KiB is the worst legitimate answer).
    static let maxResponseBytes = 64 * 1024 * 1024

    // MARK: endpoints

    /// What proves the right to create a box: the operator's token (dev servers, scripts) or a device code the person approved
    /// on the dashboard (`Vault.pollConnect` returned `.approved`). A device code is single-use.
    public enum BootstrapCredential: Sendable, Equatable {
        case token(String)
        case connect(deviceCode: String)
    }

    public struct BootstrapResult: Sendable, Equatable {
        public let deviceID: String
        /// nil only from a server that predates accounts.
        public let boxID: String?
        public let headSeq: Int
        public let epoch: Int
    }

    /// `POST /v1/bootstrap`. Unsigned: the credential is the authorization.
    @discardableResult
    public static func bootstrap(baseURL: URL, credential: BootstrapCredential, device: WireDevice, recoveryPublicKey: Data,
                                 recoveryEncryptionPublicKey: Data, recoveryEnvelope: Data, adminPublicKey: Data) async throws -> BootstrapResult {
        let client = SyncClient(baseURL: baseURL, signer: nil)
        let body = try JSONCoding.encoder.encode(BootstrapRequest(device: device, recoveryPubkey: recoveryPublicKey.base64URLEncoded(),
                                                                 recoveryEncPubkey: recoveryEncryptionPublicKey.base64URLEncoded(),
                                                                 recoveryEnvelope: recoveryEnvelope.base64URLEncoded(),
                                                                 adminPubkey: adminPublicKey.base64URLEncoded()))
        let header: [String: String]
        switch credential {
        case .token(let token): header = ["X-Bisel-Bootstrap": token]
        case .connect(let deviceCode): header = ["X-Bisel-Connect": deviceCode]
        }
        do {
            let (data, _) = try await client.send("POST", "/v1/bootstrap", body: body, headers: header)
            let r = try client.decode(BootstrapResponse.self, data)
            return BootstrapResult(deviceID: r.deviceId, boxID: r.boxId, headSeq: r.headSeq ?? 0, epoch: r.epoch ?? 1)
        } catch SyncError.conflict {
            // `409 {"error":"box_exists"}`: the account that approved this code already owns a box.
            if case .connect = credential { throw ConnectError.accountHasBox }
            throw SyncError.conflict(current: nil)
        }
    }

    @discardableResult
    public static func bootstrap(baseURL: URL, token: String, device: WireDevice, recoveryPublicKey: Data,
                                 recoveryEncryptionPublicKey: Data, recoveryEnvelope: Data, adminPublicKey: Data) async throws -> BootstrapResult {
        try await bootstrap(baseURL: baseURL, credential: .token(token), device: device, recoveryPublicKey: recoveryPublicKey,
                            recoveryEncryptionPublicKey: recoveryEncryptionPublicKey, recoveryEnvelope: recoveryEnvelope,
                            adminPublicKey: adminPublicKey)
    }

    // MARK: device-code connect (no token typed)

    /// A pending connect request. Show `userCode`, open `verificationURL` in the browser, then poll with `deviceCode`
    /// (a secret: never show it, never put it in a URL).
    public struct ConnectCode: Sendable, Equatable {
        public let deviceCode: String
        public let userCode: String
        public let verificationURL: URL
        /// Seconds until the code stops working.
        public let expiresIn: Int
        /// Seconds between polls.
        public let interval: Int
    }

    public enum ConnectStatus: Sendable, Equatable {
        case pending
        /// The person approved. `accountHasBox == true`: the account already owns a box, so this Mac cannot create one.
        case approved(accountHasBox: Bool)
        /// Redeemed: the box was created (create) or linked to the account (claim). `boxID` only when the server says.
        case consumed(boxID: String?)
        case denied
        case expired
    }

    /// `POST /v1/connect {device_name}`. Unsigned: the Mac has no identity yet.
    public static func connectStart(baseURL: URL, deviceName: String) async throws -> ConnectCode {
        let client = SyncClient(baseURL: baseURL, signer: nil)
        let (data, _) = try await client.send("POST", "/v1/connect", body: try JSONCoding.encoder.encode(ConnectStartRequest(deviceName: deviceName)))
        return try client.connectCode(data)
    }

    /// `POST /v1/connect/poll {device_code}`. An unknown code answers `.expired` (the server cannot tell a guess from a timeout).
    public static func connectPoll(baseURL: URL, deviceCode: String) async throws -> ConnectStatus {
        let client = SyncClient(baseURL: baseURL, signer: nil)
        let (data, _) = try await client.send("POST", "/v1/connect/poll", body: try JSONCoding.encoder.encode(ConnectPollRequest(deviceCode: deviceCode)))
        let r = try client.decode(ConnectPollResponse.self, data)
        switch r.status {
        case "pending": return .pending
        case "approved": return .approved(accountHasBox: r.accountHasBox ?? false)
        case "consumed": return .consumed(boxID: r.boxId)
        case "denied": return .denied
        case "expired": return .expired
        default: throw SyncError.malformedResponse
        }
    }

    /// `POST /v1/box/claim`: link this device's existing, unowned box to an account. Signed by the device and the vault-admin
    /// key. Poll the result with `connectPoll` (`.consumed` = linked, `.denied` = the account already owns a box).
    /// `409 already_linked` throws `ConnectError.alreadyLinked`.
    public func boxClaim(admin: AdminSigner) async throws -> ConnectCode {
        do {
            let (data, _) = try await send("POST", "/v1/box/claim", admin: admin)
            return try connectCode(data)
        } catch SyncError.conflict {
            throw ConnectError.alreadyLinked
        }
    }

    private func connectCode(_ data: Data) throws -> ConnectCode {
        let r = try decode(ConnectCodeResponse.self, data)
        guard let url = URL(string: r.verificationUri), let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http" else {
            throw SyncError.malformedResponse
        }
        return ConnectCode(deviceCode: r.deviceCode, userCode: r.userCode, verificationURL: url, expiresIn: r.expiresIn, interval: r.interval)
    }

    public func pull(since: Int, limit: Int = 200, eventsSince: Int? = nil) async throws -> SyncPage {
        var query = [("since", String(since)), ("limit", String(limit))]
        if let eventsSince { query.append(("events_since", String(eventsSince))) }
        let (data, _) = try await send("GET", "/v1/sync", query: query)
        let page = try decode(SyncPageWire.self, data)
        let records = page.items.compactMap(\.record)
        guard records.count == page.items.count else { throw SyncError.malformedResponse }
        return SyncPage(records: records, hasMore: page.hasMore, nextSince: page.nextSince, headSeq: page.headSeq,
                        epoch: page.epoch, devices: page.devices, events: page.events ?? [], recovery: page.recovery)
    }

    /// `epoch` is the epoch of the vault key the blob's item key is wrapped under.
    /// Writes to the vault manifest need `admin` (the server refuses them with `admin_signature_required` otherwise).
    public func put(id: String, baseRev: Int, blob: Data, epoch: Int, admin: AdminSigner? = nil) async throws -> PutOutcome {
        let body = try JSONCoding.encoder.encode(PutRequest(baseRev: baseRev, epoch: epoch, blob: blob.base64URLEncoded()))
        return try await mutate("PUT", "/v1/items/\(id)", body: body, admin: admin)
    }

    /// `marker` is the sealed tombstone marker (`ItemSealer.sealTombstone`), stored as the tombstone's blob.
    public func delete(id: String, baseRev: Int, marker: Data, epoch: Int, admin: AdminSigner? = nil) async throws -> PutOutcome {
        let body = try JSONCoding.encoder.encode(DeleteItemRequest(epoch: epoch, marker: marker.base64URLEncoded()))
        return try await mutate("DELETE", "/v1/items/\(id)", query: [("base_rev", String(baseRev))], body: body, admin: admin)
    }

    /// Previous states of items (overwritten, deleted, re-keyed) the server still holds.
    public func history(itemID: String? = nil, after: Int = 0, limit: Int = 100) async throws -> [HistoryEntry] {
        var query = [("after", String(after)), ("limit", String(limit))]
        if let itemID { query.append(("id", itemID)) }
        let (data, _) = try await send("GET", "/v1/history", query: query)
        return try decode(HistoryResponse.self, data).entries.compactMap { e in
            guard let kind = HistoryEntry.Kind(rawValue: e.kind), let blob = Data(base64URLEncoded: e.blob) else { return nil }
            return HistoryEntry(serverID: e.id, itemID: e.itemId, rev: e.rev, kind: kind, blob: blob, epoch: e.epoch,
                                replacedAt: Date(timeIntervalSince1970: TimeInterval(e.replacedAt)))
        }
    }

    public func devices() async throws -> [DeviceInfo] {
        let (data, _) = try await send("GET", "/v1/devices")
        return try decode(DevicesResponse.self, data).devices
    }

    /// Needs the vault-admin signature (unlocked vault).
    public func addDevice(_ device: WireDevice, admin: AdminSigner) async throws {
        _ = try await send("POST", "/v1/devices", body: try JSONCoding.encoder.encode(device), admin: admin)
    }

    /// Revoke without rotating (emergency). Needs the vault-admin signature.
    public func revokeDevice(id: String, admin: AdminSigner) async throws {
        _ = try await send("DELETE", "/v1/devices/\(id)", admin: admin)
    }

    /// This device's own envelope and the epoch of the vault key inside it.
    public func envelope() async throws -> (envelope: Data, epoch: Int) {
        let (data, _) = try await send("GET", "/v1/envelope")
        let r = try decode(EnvelopeResponse.self, data)
        guard let env = Data(base64URLEncoded: r.envelope), !env.isEmpty else { throw SyncError.malformedResponse }
        return (env, r.epoch)
    }

    /// Replaces the recovery key (new phrase). `epoch` is the epoch of the VK the new envelope was sealed from.
    public func rotateRecovery(publicKey: Data, encryptionPublicKey: Data, envelope: Data, epoch: Int, admin: AdminSigner) async throws {
        let body = try JSONCoding.encoder.encode(RecoveryRotateRequest(recoveryPubkey: publicKey.base64URLEncoded(),
                                                                      recoveryEncPubkey: encryptionPublicKey.base64URLEncoded(),
                                                                      recoveryEnvelope: envelope.base64URLEncoded(), epoch: epoch))
        _ = try await send("POST", "/v1/recovery/rotate", body: body, admin: admin)
    }

    /// Step 1 of recovery: empty body, returns the recovery envelope and the epoch it belongs to. Client must be signed with `RecoverySigner`.
    public func recoveryEnvelope() async throws -> (envelope: Data, epoch: Int) {
        let (data, _) = try await send("POST", "/v1/recovery/session")
        let r = try decode(RecoverySessionResponse.self, data)
        guard let env = Data(base64URLEncoded: r.recoveryEnvelope) else { throw SyncError.malformedResponse }
        return (env, r.epoch)
    }

    /// Step 3 of recovery: registers the replacement device. `epoch` is the one step 1 returned.
    /// Returns when the server will let the new device sign requests (nil = immediately).
    @discardableResult
    public func recoveryRegister(device: WireDevice, epoch: Int) async throws -> Date? {
        let (data, _) = try await send("POST", "/v1/recovery/session", body: try JSONCoding.encoder.encode(RecoverySessionRequest(device: device, epoch: epoch)))
        return (try? JSONCoding.decoder.decode(RecoverySessionResponse.self, from: data))?.device?.activatesAt
            .map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// Vault-key rotation, atomically (`POST /v1/rotate`): new wrapped key for each live item, new envelope for each
    /// remaining device, new recovery envelope, optionally revoking one device. The server applies all of it or none.
    public func rotate(baseEpoch: Int, baseSeq: Int, revoke: String?, newAdminPublicKey: Data,
                       items: [(id: String, rev: Int, wrappedKey: Data)], tombstones: [(id: String, rev: Int, marker: Data)],
                       devices: [(id: String, envelope: Data)], recoveryEnvelope: Data,
                       admin: AdminSigner) async throws -> RotateOutcome {
        let body = try JSONCoding.encoder.encode(RotateRequest(
            baseEpoch: baseEpoch, baseSeq: baseSeq, revoke: revoke, newAdminPubkey: newAdminPublicKey.base64URLEncoded(),
            tombstones: tombstones.map { RotateTombstoneWire(id: $0.id, rev: $0.rev, marker: $0.marker.base64URLEncoded()) },
            items: items.map { RotateItemWire(id: $0.id, rev: $0.rev, key: $0.wrappedKey.base64URLEncoded()) },
            devices: devices.map { RotateDeviceWire(id: $0.id, envelope: $0.envelope.base64URLEncoded()) },
            recoveryEnvelope: recoveryEnvelope.base64URLEncoded()))
        let (data, http) = try await perform("POST", "/v1/rotate", body: body, admin: admin)
        if http.statusCode == 409, let c = try? JSONCoding.decoder.decode(ConflictResponse.self, from: data), c.error == "conflict" {
            return .conflict(epoch: c.epoch, headSeq: c.headSeq)
        }
        try check(data, http)
        let r = try decode(RotateResponse.self, data)
        return .rotated(epoch: r.epoch, headSeq: r.headSeq)
    }

    // MARK: plumbing

    private func mutate(_ method: String, _ path: String, query: [(String, String)] = [], body: Data = Data(),
                        admin: AdminSigner? = nil) async throws -> PutOutcome {
        do {
            let (data, _) = try await send(method, path, query: query, body: body, admin: admin)
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
                      headers: [String: String] = [:], admin: AdminSigner? = nil) async throws -> (Data, HTTPURLResponse) {
        let (data, http) = try await perform(method, path, query: query, body: body, headers: headers, admin: admin)
        try check(data, http)
        return (data, http)
    }

    /// `performOnce`, waiting out the server's per-address flood limit (an empty 429 with `Retry-After`): a bulk push or
    /// import runs at the limiter's pace instead of aborting the sync. Every attempt is signed afresh (new nonce, new
    /// timestamp). After `maxRateLimitWaits` waits the 429 is returned as it is and `check` reports it.
    private func perform(_ method: String, _ path: String, query: [(String, String)] = [], body: Data = Data(),
                         headers: [String: String] = [:], admin: AdminSigner? = nil) async throws -> (Data, HTTPURLResponse) {
        var waits = 0
        while true {
            let (data, http) = try await performOnce(method, path, query: query, body: body, headers: headers, admin: admin)
            guard http.statusCode == 429, waits < Self.maxRateLimitWaits else { return (data, http) }
            waits += 1
            let advised = http.value(forHTTPHeaderField: "Retry-After").flatMap(Double.init) ?? 10
            try await Task.sleep(for: .seconds(min(max(advised, 1), 30)))
        }
    }

    private static let maxRateLimitWaits = 6

    /// Builds, signs and sends the request; returns whatever the server answered, whatever the status.
    private func performOnce(_ method: String, _ path: String, query: [(String, String)] = [], body: Data = Data(),
                             headers: [String: String] = [:], admin: AdminSigner? = nil) async throws -> (Data, HTTPURLResponse) {
        guard Self.isAcceptable(baseURL) else { throw SyncError.network("the server address must be https") }
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
            for (k, v) in signer.extraHeaders { request.setValue(v, forHTTPHeaderField: k) }
            let ts = String(Int(Date().timeIntervalSince1970))
            let nonce = BiselRandom.nonce()
            let canonical = Canonical.string(method: method, path: fullPath, query: canonicalQuery, body: body, ts: ts, nonce: nonce)
            request.setValue(signer.deviceHeader, forHTTPHeaderField: "X-Bisel-Device")
            request.setValue(ts, forHTTPHeaderField: "X-Bisel-Ts")
            request.setValue(nonce, forHTTPHeaderField: "X-Bisel-Nonce")
            request.setValue(try signer.sign(Data(canonical.utf8)).base64URLEncoded(), forHTTPHeaderField: "X-Bisel-Sig")
            if let admin {
                request.setValue(try admin.signature(device: signer.deviceHeader, canonicalRequest: canonical).base64URLEncoded(),
                                 forHTTPHeaderField: "X-Bisel-Admin")
            }
        }

        var data = Data()
        let response: URLResponse
        do {
            let (bytes, r) = try await session.bytes(for: request)
            response = r
            for try await byte in bytes {
                data.append(byte)
                if data.count > Self.maxResponseBytes { throw SyncError.malformedResponse }
            }
        } catch let e as SyncError { throw e }
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
        case 403 where (try? JSONCoding.decoder.decode(ConflictResponse.self, from: data))?.error == "admin_signature_required":
            throw SyncError.server(status: 403, code: "admin_signature_required")
        case 409:
            let body = try? JSONCoding.decoder.decode(ConflictResponse.self, from: data)
            if body?.error == "exists" { throw SyncError.exists }
            if body?.error == "stale_epoch" { throw RotationError.staleEpoch(serverEpoch: body?.epoch ?? 0) }
            // The box is at its size limit: not a conflict (retrying the same write can only fail the same way).
            if body?.error == "box_full" { throw SyncError.server(status: 409, code: "box_full") }
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

/// Answers every redirect with "no": the response is then the 3xx itself, which `check` reports as a server error.
private final class RefuseRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
