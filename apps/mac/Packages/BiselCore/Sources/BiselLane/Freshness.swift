import Foundation
import CryptoKit
import BiselCrypto

// The second freshness witness (docs/SYNC-LANES.md §8, decision D5): somewhere other than the lane that remembers how far the
// box got, so a device that recovers fresh, and has seen nothing of the box, can tell a lane rolled back to an older snapshot
// or forked by a revoked device from the real one. On the signed app it is iCloud key-value storage (`ICloudFreshnessWitness`,
// BiselCloudKit); the flow tests use `FakeFreshnessWitness`. It holds no secret and nothing about items: the admin-key chain,
// the head's hash and a counter, signed by the admin key of the newest epoch.

/// A small store outside the lane. Anyone who can write the lane can usually write it too (same Apple ID), so nothing read from
/// it is trusted until `LaneVerifier.freshness` has checked it against the box's own chain.
public protocol FreshnessWitness: Sendable {
    /// What the witness holds under `key`; nil when it holds nothing (never written, cleared, unreadable). Throws
    /// `FreshnessError.unavailable` when the witness cannot be reached at all.
    func read(_ key: String) async throws -> SignedFreshness?
    func write(_ value: SignedFreshness, key: String) async throws
}

/// How far the box got, as the device that wrote it had verified.
public struct FreshnessStatement: Codable, Sendable, Equatable {
    public var v = 1
    public var epoch: Int
    /// The admin-key chain up to `epoch`, as the box's head holds it.
    public var aks: [ControlRecords.AKLink]
    /// SHA-256 (hex) of the head record's blob for that chain.
    public var head: String
    /// `LaneWitness.freshnessCounter`: grows with every log entry and every member's sync.
    public var counter: Int
    public var writer: String
    public var ts: Int

    public init(epoch: Int, aks: [ControlRecords.AKLink], counter: Int, writer: String, ts: Int) {
        self.epoch = epoch; self.aks = aks; self.counter = counter; self.writer = writer; self.ts = ts
        head = Self.headHash(epoch: epoch, aks: aks)
    }

    /// Where a box's statement lives: one key per box, named after the first admin key of its chain (public, on the lane anyway).
    public static func key(root: Data) -> String { "bisel.fresh." + root.sha256Hex().prefix(32) }

    public static func headHash(epoch: Int, aks: [ControlRecords.AKLink]) -> String {
        ((try? ControlRecords.encode(ControlRecords.Head(epoch: epoch, aks: aks))) ?? Data()).sha256Hex()
    }

    /// What the admin key signs.
    public static func message(_ statement: Data) -> Data { Data("bisel/v1/freshness|".utf8) + statement }
}

/// A statement as stored: its bytes and the signature of the last admin key of its chain over them.
public struct SignedFreshness: Codable, Sendable, Equatable {
    public var statement: Data
    public var sig: Data
    public init(statement: Data, sig: Data) { self.statement = statement; self.sig = sig }
}

/// What the witness says about the lane, for the person: shown in the box's sync status (`SyncReport.freshness`).
public enum FreshnessState: String, Sendable, Codable, Equatable {
    /// No witness on this device (the server lane, BiselDev, iCloud key-value storage off) or it could not be reached: only the
    /// lane's own checks ran, as before the witness existed.
    case unavailable
    /// The witness holds nothing this device can verify for this box (not written yet, cleared, or written by someone without
    /// the box's admin key). An unlocked device writes it on its next sync.
    case unwitnessed
    /// The lane is at least as far as the witness.
    case current
    /// The witness has seen the box further than the lane shows: the lane is catching up, or it was restored to an older state.
    /// Another device of the box puts it right; nothing is lost.
    case laneBehind
    /// The witness and the lane hold two different chains of the same box: a device that was removed is still writing to the
    /// storage, or someone tampered with it.
    case forked
}

public enum FreshnessError: Error, Equatable {
    /// The witness cannot be reached.
    case unavailable
    /// Recovering: the lane's head and the witness's are two different chains of the box. The phrase would open a key someone
    /// else chose.
    case forked
    /// Recovering: the lane holds an older epoch than the witness saw, so its recovery envelope holds a key that was rotated
    /// away (and that a removed device knows).
    case laneBehind
}

public struct FreshnessVerdict: Sendable, Equatable {
    public var state: FreshnessState
    /// This device knows more than the witness (or the witness is unusable): an unlocked device at the box's current epoch
    /// writes its own statement.
    public var rewrite: Bool
}

extension LaneVerifier {
    /// Compares what the witness holds with the lane as this device verified it: `chain` is the admin-key chain (the pinned one,
    /// or the anchored head a recovering device read), `counter` the lane's `freshnessCounter` (nil when not known yet).
    ///
    /// Only the chain and the counter decide. A revoked device holds the admin key of the epoch it was cut off in, so it can
    /// sign a statement for that epoch (a prefix of the real chain: read as the witness lagging) or for a chain of its own
    /// (a fork); it cannot sign one for the real current epoch.
    public func freshness(_ signed: SignedFreshness?, chain: [ControlRecords.AKLink], counter: Int?) -> FreshnessVerdict {
        guard let root = chain.first?.ak else { return .init(state: .unwitnessed, rewrite: false) }
        guard let s = Self.statement(signed, root: root) else { return .init(state: .unwitnessed, rewrite: true) }
        if Self.forks(s.aks, chain) { return .init(state: .forked, rewrite: true) }
        if s.aks.count > chain.count { return .init(state: .laneBehind, rewrite: false) }
        if s.aks.count < chain.count { return .init(state: .current, rewrite: true) }
        guard let counter else { return .init(state: .current, rewrite: false) }
        if s.counter > counter { return .init(state: .laneBehind, rewrite: false) }
        return .init(state: .current, rewrite: s.counter < counter)
    }

    /// The statement in `signed` if it holds together for the box whose chain starts at `root`: a well-formed chain from that
    /// root, signed by its own last key. Says nothing yet about whether it agrees with the lane.
    public static func statement(_ signed: SignedFreshness?, root: Data) -> FreshnessStatement? {
        guard let signed, let s = ControlRecords.decode(FreshnessStatement.self, signed.statement), s.v == 1,
              ControlRecords.chainValid(s.aks, epoch: s.epoch), s.aks.first?.ak == root, let last = s.aks.last,
              let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: last.ak),
              pub.isValidSignature(signed.sig, for: FreshnessStatement.message(signed.statement)),
              s.head == FreshnessStatement.headHash(epoch: s.epoch, aks: s.aks) else { return nil }
        return s
    }

    /// Whether two admin-key chains part ways: neither is a prefix of the other.
    static func forks(_ a: [ControlRecords.AKLink], _ b: [ControlRecords.AKLink]) -> Bool {
        zip(a, b).prefix { $0.epoch == $1.epoch && $0.ak == $1.ak }.count < min(a.count, b.count)
    }
}

extension LaneWitness {
    /// The lane's progress as any device that read all of it computes it: the log length plus the counter of every member that
    /// was not revoked. A revoked device's own counter is left out, as a fresh device never sees the one it showed before.
    public var freshnessCounter: Int {
        let revoked = Set(members.filter(\.isRevoked).map(\.id))
        return logN + counters.filter { !revoked.contains($0.key) }.values.reduce(0, +)
    }
}
