import Foundation
import BiselVault

/// Why a record was dropped from the apply path. Nothing is ever deleted because of a verdict: rejected records are kept
/// aside (`LocalStore.quarantine`) for diagnostics.
public enum LaneQuarantineReason: String, Sendable, Codable {
    case malformed          // kind, id, rev or size do not fit the record layout
    case rolledBackRecord   // an older revision of a record this device already holds, replayed by the lane
    case badSignature       // a control record not signed by the pinned admin key
    case unpinnedSigner     // signed by a key outside the pinned chain
    case staleEpoch         // written for a vault-key epoch older than the box's current one
    case chainBroken        // a log or head record that does not extend the chain this device has seen
}

public struct LaneQuarantined: Sendable, Equatable {
    public var record: LaneRecord
    public var reason: LaneQuarantineReason
}

/// Something a lane did that is not a legitimate update: surfaced to the person, never applied silently.
public enum LaneIncident: Sendable, Equatable {
    /// The lane reports a hard delete of a record that is never hard-deleted. The local replica heals it.
    case removed(LaneRecordRef)
    /// The lane's position went backwards: restored from an older snapshot, or rolled back.
    case rolledBack(known: Int, reported: Int)
    /// A roster peer attested a record set this device cannot reproduce although it has seen everything (withholding).
    case splitView(peer: String)
    /// A device keeps writing records the box rejects.
    case noisyWriter(String)
}

public struct LaneVerdict: Sendable {
    public var accepted: [LaneRecord]
    public var quarantined: [LaneQuarantined]
    public var incidents: [LaneIncident]
}

/// The checks of docs/SYNC-LANES.md §2, run on every `LaneChanges` before `applyRemote`. A lane may additionally enforce
/// (the server lane does); nothing here depends on it.
public struct LaneVerifier: Sendable {
    /// Largest item blob: 256 KiB of payload plus the wrapped key, nonce and tag (`ItemSealer`).
    static let maxBlob = 256 * 1024 + 256

    public init() {}

    /// Throws `IntegrityError.serverRolledBack` when the lane reports a position lower than one this device already saw, and
    /// `.invalidCursor` when its answer contradicts itself: records or a cursor beyond its own head, a cursor that went
    /// backwards, or no progress on a page that says there is more.
    public func verify(_ changes: LaneChanges, since: LaneCursor?, knownHead: Int) throws -> LaneVerdict {
        if let meta = changes.meta {
            if meta.headSeq < knownHead { throw IntegrityError.serverRolledBack(known: knownHead, reported: meta.headSeq) }
            let from = since.flatMap { Int($0.rawValue) } ?? 0
            // Positions are numbers on lanes that have a head; a cursor that is not one (CloudKit's token) is only compared for equality.
            if let next = Int(changes.cursor.rawValue), next < from || next > meta.headSeq { throw IntegrityError.invalidCursor }
            if changes.hasMore, changes.cursor == since || (since == nil && Int(changes.cursor.rawValue) == 0) { throw IntegrityError.invalidCursor }
            if changes.upserts.contains(where: { $0.order > meta.headSeq || ($0.order <= from && Int(changes.cursor.rawValue) != nil) }) {
                throw IntegrityError.invalidCursor
            }
        }
        var verdict = LaneVerdict(accepted: [], quarantined: [], incidents: [])
        for record in changes.upserts {
            if let reason = structuralFault(record) { verdict.quarantined.append(.init(record: record, reason: reason)) }
            else { verdict.accepted.append(record) }
        }
        for ref in changes.removed where ref.kind != .enroll { verdict.incidents.append(.removed(ref)) }
        return verdict
    }

    private func structuralFault(_ r: LaneRecord) -> LaneQuarantineReason? {
        guard r.blob.count <= Self.maxBlob, !r.id.isEmpty else { return .malformed }
        switch r.kind {
        case .item, .tombstone, .manifest:
            guard r.rev >= 1, (r.kind == .manifest) == (r.id == ReservedRecord.manifestID) else { return .malformed }
        default: break
        }
        return nil
    }
}
