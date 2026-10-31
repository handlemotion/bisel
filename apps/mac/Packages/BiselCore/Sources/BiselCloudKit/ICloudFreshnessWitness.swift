import Foundation
import BiselLane

/// The freshness witness in iCloud key-value storage (docs/SYNC-LANES.md §8, D5): a separate iCloud service from the CloudKit
/// zone, so a snapshot restored there, or a fork written there, shows against it. One small value per box.
///
/// Needs the signed app's `com.apple.developer.ubiquity-kvstore-identifier` entitlement; without it, or signed out of iCloud,
/// every call throws `FreshnessError.unavailable` and the box syncs with the lane's own checks only. Key-value storage is
/// eventually consistent (a value written on one Mac can take a while to reach another), holds 1 MB in all, and the owner can
/// clear it from iCloud settings: the verifier reads a missing or stale value as such, never as an attack.
public struct ICloudFreshnessWitness: FreshnessWitness {
    /// Far above what a statement needs (an admin-key chain of a few hundred rotations); KVS takes at most 1 MB per app.
    static let maxValue = 64 * 1024

    public init() {}

    public func read(_ key: String) async throws -> SignedFreshness? {
        let store = try available()
        guard let data = store.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(SignedFreshness.self, from: data)
    }

    public func write(_ value: SignedFreshness, key: String) async throws {
        let store = try available()
        let data = try JSONEncoder().encode(value)
        guard data.count <= Self.maxValue else { throw FreshnessError.unavailable }
        store.set(data, forKey: key)
        guard store.synchronize() else { throw FreshnessError.unavailable }
    }

    /// `synchronize` returns false when the app lacks the entitlement; no ubiquity token means no iCloud account.
    private func available() throws -> NSUbiquitousKeyValueStore {
        let store = NSUbiquitousKeyValueStore.default
        guard FileManager.default.ubiquityIdentityToken != nil, store.synchronize() else { throw FreshnessError.unavailable }
        return store
    }
}
