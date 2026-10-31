import Foundation
import BiselLane

/// The freshness witness for flow tests, standing in for iCloud key-value storage: one value per key, last writer wins, and
/// anyone on the account can write or clear it. It can also be switched off (signed out of iCloud, no entitlement).
public final class FakeFreshnessWitness: FreshnessWitness, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: SignedFreshness] = [:]
    private var reachable = true

    public init() {}

    public func read(_ key: String) async throws -> SignedFreshness? {
        try lock.withLock {
            guard reachable else { throw FreshnessError.unavailable }
            return values[key]
        }
    }

    public func write(_ value: SignedFreshness, key: String) async throws {
        try lock.withLock {
            guard reachable else { throw FreshnessError.unavailable }
            values[key] = value
        }
    }

    public func setReachable(_ on: Bool) { lock.withLock { reachable = on } }

    /// Every value it holds, by key: what a writer on the account can see and overwrite.
    public var all: [String: SignedFreshness] { lock.withLock { values } }

    /// Someone on the account overwrites a value.
    public func plant(_ value: SignedFreshness, key: String) { lock.withLock { values[key] = value } }
}
