import Foundation
import CryptoKit
import LocalAuthentication
import Security
import BiselCrypto

/// Secure Enclave implementation of `DeviceKeyStore`.
///
/// Requires a signed app with a `keychain-access-groups` / `application-identifier` entitlement for
/// persistent keys. With `persistent: false` keys live only in this object (used by `bisel-dev se-probe`
/// to exercise the Enclave from an unsigned tool).
public final class SecureEnclaveDeviceKeyStore: DeviceKeyStore, @unchecked Sendable {
    public let implementation = "secure-enclave"

    private let accessGroup: String?
    private let tagPrefix: String
    private let persistent: Bool
    private let lock = NSLock()
    private var cache: [String: SecKey] = [:]      // only used when !persistent

    public init(accessGroup: String?, tagPrefix: String = "app.bisel.device", persistent: Bool = true) {
        self.accessGroup = accessGroup
        self.tagPrefix = tagPrefix
        self.persistent = persistent
    }

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    private enum Role: String { case enc, sig }
    private func tag(_ role: Role) -> Data { Data("\(tagPrefix).dk-\(role.rawValue)".utf8) }

    // MARK: DeviceKeyStore

    public func createKeys() throws -> DevicePublicKeys {
        try deleteKeys()
        let enc = try makeKey(.enc, flags: [.biometryAny, .privateKeyUsage],
                              accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        let sig = try makeKey(.sig, flags: [.privateKeyUsage],
                              accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        return DevicePublicKeys(sig: try publicBytes(sig), enc: try publicBytes(enc))
    }

    public func publicKeys() throws -> DevicePublicKeys? {
        guard let enc = try loadKey(.enc, context: nil), let sig = try loadKey(.sig, context: nil) else { return nil }
        return DevicePublicKeys(sig: try publicBytes(sig), enc: try publicBytes(enc))
    }

    public func sign(_ message: Data) throws -> Data {
        // DK-sig has no biometric requirement; the context makes that explicit: if the system ever wanted to
        // prompt, the call fails instead of putting a Touch ID sheet in front of a background sync.
        let context = LAContext()
        context.interactionNotAllowed = true
        guard let key = try loadKey(.sig, context: context) else { throw KeyStoreError.noKeys }
        var err: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &err) else {
            throw Self.map(err?.takeRetainedValue(), fallback: "sign failed")
        }
        return try P256.Signing.ECDSASignature(derRepresentation: der as Data).rawRepresentation
    }

    public func openEnvelope(_ envelope: Data, reason: String) async throws -> Data {
        guard let first = try await openEnvelopes([envelope], reason: reason).first else { throw KeyStoreError.failed("no result") }
        return first
    }

    public func openEnvelopes(_ envelopes: [Data], reason: String) async throws -> [Data] {
        // The key operation blocks while the biometric sheet is up: keep it off the caller's executor.
        try await Task.detached(priority: .userInitiated) { [self] in
            let context = LAContext()                 // one context: the first decrypt authenticates, the rest reuse it
            context.localizedReason = reason
            context.localizedFallbackTitle = ""
            guard let key = try loadKey(.enc, context: context) else { throw KeyStoreError.noKeys }
            return try envelopes.map { envelope in
                var err: Unmanaged<CFError>?
                guard let out = SecKeyCreateDecryptedData(key, DeviceEnvelope.algorithm, envelope as CFData, &err) else {
                    throw Self.map(err?.takeRetainedValue(), fallback: "decrypt failed")
                }
                return out as Data
            }
        }.value
    }

    /// Typed mapping of Security / LocalAuthentication failures. Messages carry codes, never key material.
    static func map(_ error: CFError?, fallback: String) -> KeyStoreError {
        guard let error else { return .failed(fallback) }
        let ns = error as Error as NSError
        switch (ns.domain, ns.code) {
        case (LAError.errorDomain, LAError.userCancel.rawValue), (LAError.errorDomain, LAError.appCancel.rawValue),
             (LAError.errorDomain, LAError.systemCancel.rawValue), (NSOSStatusErrorDomain, Int(errSecUserCanceled)):
            return .userCancelled
        case (LAError.errorDomain, LAError.biometryLockout.rawValue):
            return .unavailable("Touch ID is locked out; unlock the Mac with its password first")
        case (LAError.errorDomain, LAError.biometryNotEnrolled.rawValue), (LAError.errorDomain, LAError.biometryNotAvailable.rawValue):
            return .unavailable("Touch ID is not available or not enrolled")
        case (LAError.errorDomain, LAError.authenticationFailed.rawValue), (NSOSStatusErrorDomain, Int(errSecAuthFailed)):
            return .failed("authentication failed")
        default:
            return .failed("\(fallback) (\(ns.domain) \(ns.code))")
        }
    }

    public func deleteKeys() throws {
        lock.withLock { cache.removeAll() }
        guard persistent else { return }
        for role in [Role.enc, .sig] {
            let status = SecItemDelete(query(role, context: nil) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeyStoreError.failed("SecItemDelete \(status)")
            }
        }
    }

    // MARK: Keychain plumbing

    private func makeKey(_ role: Role, flags: SecAccessControlCreateFlags, accessible: CFString) throws -> SecKey {
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, accessible, flags, &err) else {
            throw KeyStoreError.failed("access control: \(err.map { ($0.takeRetainedValue() as Error as NSError).code } ?? 0)")
        }
        var priv: [CFString: Any] = [
            kSecAttrIsPermanent: persistent,
            kSecAttrApplicationTag: tag(role),
            kSecAttrAccessControl: access,
        ]
        if let accessGroup { priv[kSecAttrAccessGroup] = accessGroup }
        var attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: priv,
        ]
        #if os(macOS)
        if persistent { attrs[kSecUseDataProtectionKeychain] = true }
        #endif
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            let e = err?.takeRetainedValue()
            throw KeyStoreError.unavailable("SecKeyCreateRandomKey: \(e?.localizedDescription ?? "?") (\((e as Error?).map { ($0 as NSError).code } ?? 0))")
        }
        if !persistent { lock.withLock { cache[role.rawValue] = key } }
        return key
    }

    private func query(_ role: Role, context: LAContext?) -> [CFString: Any] {
        var q: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: tag(role),
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        if let accessGroup { q[kSecAttrAccessGroup] = accessGroup }
        #if os(macOS)
        q[kSecUseDataProtectionKeychain] = true
        #endif
        if let context { q[kSecUseAuthenticationContext] = context }
        return q
    }

    private func loadKey(_ role: Role, context: LAContext?) throws -> SecKey? {
        if !persistent { return lock.withLock { cache[role.rawValue] } }
        var q = query(role, context: context)
        q[kSecReturnRef] = true
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else { throw KeyStoreError.failed("keychain returned an unexpected item") }
            return (item as! SecKey)   // type checked above
        case errSecItemNotFound: return nil
        default: throw KeyStoreError.failed("SecItemCopyMatching \(status)")
        }
    }

    private func publicBytes(_ priv: SecKey) throws -> Data {
        guard let pub = SecKeyCopyPublicKey(priv) else { throw KeyStoreError.failed("no public key") }
        var err: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(pub, &err) else {
            throw KeyStoreError.failed(err?.takeRetainedValue().localizedDescription ?? "export")
        }
        return raw as Data
    }
}
