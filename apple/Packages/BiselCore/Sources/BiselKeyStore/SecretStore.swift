import Foundation
import Security

/// Small secrets that must not sit in the plaintext SQLite file (for example the server's address, which SPEC §6 treats as
/// a secret). The Keychain implementation is the production one.
public protocol SecretStore: Sendable {
    func get(_ key: String) throws -> Data?
    func set(_ key: String, _ value: Data) throws
    func delete(_ key: String) throws
}

/// Generic-password Keychain items, readable after first unlock, this device only (never in backups or iCloud).
public struct KeychainSecretStore: SecretStore {
    let service: String
    let accessGroup: String?

    public init(service: String = "app.bisel.secrets", accessGroup: String?) {
        self.service = service; self.accessGroup = accessGroup
    }

    private func query(_ key: String) -> [CFString: Any] {
        var q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: key]
        if let accessGroup { q[kSecAttrAccessGroup] = accessGroup }
        #if os(macOS)
        q[kSecUseDataProtectionKeychain] = true
        #endif
        return q
    }

    public func get(_ key: String) throws -> Data? {
        var q = query(key)
        q[kSecReturnData] = true
        var item: CFTypeRef?
        switch SecItemCopyMatching(q as CFDictionary, &item) {
        case errSecSuccess: return item as? Data
        case errSecItemNotFound: return nil
        case let status: throw KeyStoreError.failed("keychain read \(status)")
        }
    }

    public func set(_ key: String, _ value: Data) throws {
        let status = SecItemUpdate(query(key) as CFDictionary, [kSecValueData: value] as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw KeyStoreError.failed("keychain update \(status)") }
        var add = query(key)
        add[kSecValueData] = value
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = SecItemAdd(add as CFDictionary, nil)
        guard added == errSecSuccess else { throw KeyStoreError.failed("keychain add \(added)") }
    }

    public func delete(_ key: String) throws {
        let status = SecItemDelete(query(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeyStoreError.failed("keychain delete \(status)") }
    }
}

#if BISEL_SOFTWARE_KEYS
/// TEST ONLY: secrets in 0600 files next to the software keys.
public struct FileSecretStore: SecretStore {
    let directory: URL
    public init(directory: URL) { self.directory = directory }
    private func url(_ key: String) -> URL { directory.appendingPathComponent("secret-\(key.replacingOccurrences(of: "/", with: "_"))") }
    public func get(_ key: String) throws -> Data? { try? Data(contentsOf: url(key)) }
    public func set(_ key: String, _ value: Data) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try value.write(to: url(key), options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url(key).path)
    }
    public func delete(_ key: String) throws { try? FileManager.default.removeItem(at: url(key)) }
}
#endif
