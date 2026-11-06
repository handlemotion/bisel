import Foundation
import CryptoKit
import BiselVault

/// A WebAuthn credential Bisel can sign with. It lives in the `passkey` slot of a `.passkey` item, so its private key is sealed
/// with the item and travels only inside the box, through sync and backups like any other item (SPEC §5).
///
/// `privateKey` is deliberately not public: only `PasskeyAuthenticator` touches it, in memory, to sign.
public struct PasskeyCredential: Sendable, Equatable {
    public let credentialID: Data
    public let rpID: String
    public let userHandle: Data
    public let userName: String
    public let userDisplayName: String
    /// Stays 0: the key is shared by every device of the box, so a counter could only go backwards or fork. 0 tells the site
    /// that this authenticator keeps none (WebAuthn §6.1.1), and signing never has to write to the box.
    public let signCount: UInt32
    public let createdAt: Date
    /// The raw 32-byte P-256 scalar.
    let privateKey: Data

    private static let format = "bisel-passkey"
    private static let version = 1

    init(credentialID: Data, rpID: String, userHandle: Data, userName: String, userDisplayName: String,
         signCount: UInt32, createdAt: Date, privateKey: Data) {
        self.credentialID = credentialID; self.rpID = rpID; self.userHandle = userHandle; self.userName = userName
        self.userDisplayName = userDisplayName; self.signCount = signCount; self.createdAt = createdAt; self.privateKey = privateKey
    }

    /// What goes in `Item.passkey`.
    var slot: JSONValue {
        .object([
            "format": .string(Self.format),
            "version": .number(Double(Self.version)),
            "algorithm": .number(Double(PasskeyAuthenticator.es256)),
            "credentialId": .string(credentialID.base64URLEncoded()),
            "rpId": .string(rpID),
            "userHandle": .string(userHandle.base64URLEncoded()),
            "userName": .string(userName),
            "userDisplayName": .string(userDisplayName),
            "privateKey": .string(privateKey.base64URLEncoded()),
            "signCount": .number(Double(signCount)),
            "createdAt": .string(createdAt.formatted(.iso8601)),
        ])
    }

    /// Reads a slot without ever changing it: a blob this build cannot use stays in the item byte for byte.
    static func state(of slot: JSONValue, type: ItemType) -> PasskeyState {
        guard case .object(let o) = slot, o["format"] == .string(format) else { return .unusable(.imported) }
        guard case .number(let version)? = o["version"] else { return .unusable(.damaged) }
        guard version == Double(Self.version) else { return .unusable(version > Double(Self.version) ? .newerFormat : .damaged) }
        func text(_ key: String) -> String? { if case .string(let s)? = o[key] { s } else { nil } }
        func bytes(_ key: String) -> Data? { text(key).flatMap { Data(base64URLEncoded: $0) } }
        guard type == .passkey,
              o["algorithm"] == .number(Double(PasskeyAuthenticator.es256)),
              let credentialID = bytes("credentialId"), PasskeyAuthenticator.credentialIDLengths.contains(credentialID.count),
              let rpID = text("rpId"), !rpID.isEmpty,
              let userHandle = bytes("userHandle"), PasskeyAuthenticator.userHandleLengths.contains(userHandle.count),
              let userName = text("userName"), let userDisplayName = text("userDisplayName"),
              case .number(let count)? = o["signCount"], let signCount = UInt32(exactly: count),
              let created = text("createdAt"), let createdAt = try? Date(created, strategy: .iso8601),
              let privateKey = bytes("privateKey"), (try? P256.Signing.PrivateKey(rawRepresentation: privateKey)) != nil
        else { return .unusable(.damaged) }
        return .usable(PasskeyCredential(credentialID: credentialID, rpID: rpID, userHandle: userHandle, userName: userName,
                                         userDisplayName: userDisplayName, signCount: signCount, createdAt: createdAt,
                                         privateKey: privateKey))
    }

    /// The new item that holds this credential.
    public func item() -> Item {
        Item(type: .passkey, title: rpID, urls: ["https://\(rpID)"], username: userName, passkey: slot)
    }

    /// `item` with this credential in place of the one it had (the same account registered again).
    public func replacing(in item: Item) -> Item {
        var item = item
        item.username = userName
        item.passkey = slot
        return item
    }
}

// The private key must not reach a log through string interpolation or a dump.
extension PasskeyCredential: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "PasskeyCredential(rpID: \(rpID), contents redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }
}

public enum PasskeyState: Sendable, Equatable {
    case usable(PasskeyCredential)
    case unusable(PasskeyUnusableReason)
}

public enum PasskeyUnusableReason: Sendable, Equatable {
    /// A blob stored whole by an import, in a shape Bisel does not sign with.
    case imported
    /// Written by a later version of Bisel.
    case newerFormat
    /// Bisel's format, but something in it cannot be used.
    case damaged
}

public extension Item {
    /// What the `passkey` slot holds; nil when it is empty.
    var passkeyState: PasskeyState? { passkey.map { PasskeyCredential.state(of: $0, type: type) } }
}

/// A passkey to offer for a site. Holds no key material.
public struct PasskeyMatch: Sendable, Equatable, Identifiable {
    public let itemID: String
    public let credentialID: Data
    public let rpID: String
    public let userHandle: Data
    public let userName: String
    public let userDisplayName: String
    public let createdAt: Date
    public var id: Data { credentialID }

    public init(itemID: String, credential c: PasskeyCredential) {
        self.itemID = itemID; credentialID = c.credentialID; rpID = c.rpID; userHandle = c.userHandle
        userName = c.userName; userDisplayName = c.userDisplayName; createdAt = c.createdAt
    }
}

/// An item whose `passkey` slot cannot sign. It is reported, never changed.
public struct UnusablePasskey: Sendable, Equatable, Identifiable {
    public let itemID: String
    public let title: String
    public let reason: PasskeyUnusableReason
    public var id: String { itemID }
    public init(itemID: String, title: String, reason: PasskeyUnusableReason) {
        self.itemID = itemID; self.title = title; self.reason = reason
    }
}

public enum PasskeyLookup {
    /// Every credential that can sign, newest first. A "(conflict)" copy holds the same credential as its original: one entry
    /// per credential ID, the most recently updated.
    public static func credentials(in items: [Item]) -> [(item: Item, credential: PasskeyCredential)] {
        var seen = Set<Data>()
        return items.sorted { $0.updatedAt > $1.updatedAt }.compactMap { item in
            guard case .usable(let c)? = item.passkeyState, seen.insert(c.credentialID).inserted else { return nil }
            return (item, c)
        }
    }

    /// The credentials scoped to exactly `rpID`, and when `allowList` is not empty, only those it names. No subdomain or
    /// `SiteMatch` rule applies here: the browser has already checked the page against the RP ID, and a credential belongs to
    /// the one RP ID it was made for.
    public static func credentials(in items: [Item], rpID: String, allowList: [Data] = []) -> [(item: Item, credential: PasskeyCredential)] {
        let rp = PasskeyAuthenticator.normalized(rpID: rpID)
        return credentials(in: items).filter { $0.credential.rpID == rp && (allowList.isEmpty || allowList.contains($0.credential.credentialID)) }
    }
}
