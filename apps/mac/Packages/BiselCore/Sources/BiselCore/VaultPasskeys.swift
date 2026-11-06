@_exported import BiselPasskey
import Foundation

/// A site asking for a new passkey.
public struct PasskeyRegistrationRequest: Sendable, Equatable {
    public var rpID: String
    public var userHandle: Data
    public var userName: String
    public var userDisplayName: String
    /// COSE algorithms the site accepts; ES256 must be one of them.
    public var algorithms: [Int]
    public var excludedCredentialIDs: [Data]

    public init(rpID: String, userHandle: Data, userName: String, userDisplayName: String,
                algorithms: [Int] = [PasskeyAuthenticator.es256], excludedCredentialIDs: [Data] = []) {
        self.rpID = rpID; self.userHandle = userHandle; self.userName = userName; self.userDisplayName = userDisplayName
        self.algorithms = algorithms; self.excludedCredentialIDs = excludedCredentialIDs
    }
}

/// What the credential provider calls. Registering and signing each take one fresh check of `gate`, which is what sets the
/// user-verified flag; `gate` replaces the configured check for the call, it is never skipped. Keys stay in here: the caller
/// gets attestation objects and signatures. A passkey is never written on sign-in (`PasskeyCredential.signCount`).
public extension Vault {
    /// Passkeys for exactly `rpID`, newest first. An empty `allowList` means any of them (a discoverable sign-in).
    func passkeys(rpID: String, allowList: [Data] = []) throws -> [PasskeyMatch] {
        PasskeyLookup.credentials(in: try items().items, rpID: rpID, allowList: allowList)
            .map { PasskeyMatch(itemID: $0.item.id, credential: $0.credential) }
    }

    /// Items holding a passkey blob Bisel cannot sign with, such as an import's.
    func unusablePasskeys() throws -> [UnusablePasskey] {
        try items().items.compactMap { item in
            guard case .unusable(let reason)? = item.passkeyState else { return nil }
            return UnusablePasskey(itemID: item.id, title: item.title, reason: reason)
        }
    }

    /// Makes a passkey and saves it to the box; `sync()` pushes it. The same account on the same site registering again replaces
    /// its passkey in place (WebAuthn §6.3.2), and the old one stays in the item's history.
    /// Throws `PasskeyError`, `VaultError.locked`, or the gate's error.
    func registerPasskey(_ request: PasskeyRegistrationRequest, gate: (any BiometricGate)? = nil) async throws -> PasskeyRegistration {
        guard request.algorithms.contains(PasskeyAuthenticator.es256) else { throw PasskeyError.unsupportedAlgorithm }
        _ = try requireKey()
        let rp = PasskeyAuthenticator.normalized(rpID: request.rpID)
        try await (gate ?? config.gate).authenticate(reason: "Create a passkey for \(rp)")
        // After the check, and with no suspension until the write: the box may have changed during the prompt.
        let k = try requireKey()
        let held = PasskeyLookup.credentials(in: try items().items, rpID: rp)
        guard !held.contains(where: { request.excludedCredentialIDs.contains($0.credential.credentialID) }) else {
            throw PasskeyError.excludedCredential
        }
        let now = Self.storedNow()
        let registration = try PasskeyAuthenticator.register(rpID: rp, userHandle: request.userHandle, userName: request.userName,
                                                             userDisplayName: request.userDisplayName, userVerified: true,
                                                             backedUp: try syncsSomewhere(), createdAt: now)
        var item: Item
        if let same = held.first(where: { $0.credential.userHandle == request.userHandle }) {
            item = registration.credential.replacing(in: same.item)
        } else {
            item = registration.credential.item()
            item.id = BiselRandom.identifier()
            item.createdAt = now
        }
        item.updatedAt = now
        try writeItem(try checked(item), key: k, keepPrevious: keepsLocalHistory())
        return registration
    }

    /// Signs `clientDataHash` with the passkey `credentialID` for exactly `rpID`.
    /// Throws `PasskeyError.noCredential` for any other RP ID, `VaultError.locked`, or the gate's error.
    func assertPasskey(rpID: String, credentialID: Data, clientDataHash: Data, gate: (any BiometricGate)? = nil) async throws -> PasskeyAssertion {
        _ = try requireKey()
        let rp = PasskeyAuthenticator.normalized(rpID: rpID)
        try await (gate ?? config.gate).authenticate(reason: "Sign in to \(rp)")
        guard let match = PasskeyLookup.credentials(in: try items().items, rpID: rp, allowList: [credentialID]).first else {
            throw PasskeyError.noCredential
        }
        return try PasskeyAuthenticator.assert(match.credential, clientDataHash: clientDataHash, userVerified: true, backedUp: try syncsSomewhere())
    }

    /// The backup-state flag: a box on this Mac only has no second copy of the key.
    private func syncsSomewhere() throws -> Bool { try laneStatus() != .thisDeviceOnly }
}
