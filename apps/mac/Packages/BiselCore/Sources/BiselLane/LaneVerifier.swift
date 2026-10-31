import Foundation
import BiselCrypto
import BiselVault

/// Why a record was dropped from the apply path. Nothing is ever deleted because of a verdict: rejected records are kept
/// aside (`LocalStore.quarantine`) for diagnostics.
public enum LaneQuarantineReason: String, Sendable, Codable {
    case malformed          // kind, id, rev or size do not fit the record layout
    case rolledBackRecord   // an older version of a control record this device already holds, replayed by the lane
    case badSignature       // a control record not signed by the admin key of its epoch
    case unpinnedSigner     // signed by a key outside the chain this device pinned
    case staleEpoch         // written for a vault-key epoch older than the box's current one
    case chainBroken        // a log entry that does not extend the chain this device has seen
}

public struct LaneQuarantined: Sendable, Equatable {
    public var record: LaneRecord
    public var reason: LaneQuarantineReason
}

/// Something a lane did that is not a legitimate update: surfaced to the person, never applied silently.
public enum LaneIncident: Sendable, Equatable {
    /// The lane reports a hard delete of a record that is never hard-deleted. The local replica heals it.
    case removed(LaneRecordRef)
    /// A full read of the lane lacks records this device acknowledged earlier. The local replica heals them.
    case lost(count: Int)
}

public struct LaneVerdict: Sendable {
    public var accepted: [LaneRecord]
    public var quarantined: [LaneQuarantined]
    public var incidents: [LaneIncident]
    /// For lanes that do not say it themselves: the box as the verified control records describe it.
    public var meta: LaneMeta?
}

/// The checks of docs/SYNC-LANES.md §2, §7 and §8, run on every `LaneChanges` before `applyRemote`. A lane may additionally
/// enforce (the server lane does); nothing here depends on it.
public struct LaneVerifier: Sendable {
    /// Largest item blob: 256 KiB of payload plus the wrapped key, nonce and tag (`ItemSealer`).
    static let maxBlob = 256 * 1024 + 256

    public init() {}

    /// - `witness`: what this device already verified; updated in place (the caller persists it only if this returns).
    /// - `adminKey`: the admin public key derived from the vault key this device holds, nil while locked. It anchors a
    ///   device that has no pin yet.
    ///
    /// Throws `IntegrityError.serverRolledBack` when the lane reports a position (or a writer's counter) lower than one this
    /// device already saw, and `.invalidCursor` when its answer contradicts itself: records or a cursor beyond its own head, a
    /// cursor that went backwards, or no progress on a page that says there is more.
    public func verify(_ changes: LaneChanges, since: LaneCursor?, knownHead: Int, witness: inout LaneWitness, adminKey: Data?) throws -> LaneVerdict {
        var verdict = LaneVerdict(accepted: [], quarantined: [], incidents: [], meta: nil)
        if let meta = changes.meta {
            try checkPosition(changes, meta: meta, since: since, knownHead: knownHead)
        } else {
            var control = changes.upserts.filter { !$0.isItemLike }
            control += witness.held.values.map(\.record).filter { held in !control.contains { $0.kind == held.kind && $0.id == held.id } }
            witness.held = [:]
            try verifyControl(control, witness: &witness, adminKey: adminKey, into: &verdict)
            let meta = LaneMeta(epoch: max(witness.epoch, 1), headSeq: witness.position, members: witness.members, events: witness.events,
                                recovery: witness.recovery)
            if meta.headSeq < knownHead { throw IntegrityError.serverRolledBack(known: knownHead, reported: meta.headSeq) }
            verdict.meta = meta
        }
        for record in changes.upserts where record.isItemLike {
            if let reason = fault(record, currentEpoch: witness.epoch) { verdict.quarantined.append(.init(record: record, reason: reason)) }
            else { verdict.accepted.append(record) }
        }
        for ref in changes.removed where ref.kind != .enroll { verdict.incidents.append(.removed(ref)) }
        return verdict
    }

    // MARK: lanes that report a position

    private func checkPosition(_ changes: LaneChanges, meta: LaneMeta, since: LaneCursor?, knownHead: Int) throws {
        if meta.headSeq < knownHead { throw IntegrityError.serverRolledBack(known: knownHead, reported: meta.headSeq) }
        let from = since.flatMap { Int($0.rawValue) } ?? 0
        // Positions are numbers on lanes that have a head; a cursor that is not one (CloudKit's token) is only compared for equality.
        if let next = Int(changes.cursor.rawValue), next < from || next > meta.headSeq { throw IntegrityError.invalidCursor }
        if changes.hasMore, changes.cursor == since || (since == nil && Int(changes.cursor.rawValue) == 0) { throw IntegrityError.invalidCursor }
        if changes.upserts.contains(where: { $0.order > meta.headSeq || ($0.order <= from && Int(changes.cursor.rawValue) != nil) }) {
            throw IntegrityError.invalidCursor
        }
    }

    private func fault(_ r: LaneRecord, currentEpoch: Int) -> LaneQuarantineReason? {
        guard r.blob.count <= Self.maxBlob, !r.id.isEmpty else { return .malformed }
        guard r.rev >= 1, (r.kind == .manifest) == (r.id == ReservedRecord.manifestID) else { return .malformed }
        // A write built for a vault-key epoch the box has left: it cannot open under the current key (0: the lane does not say).
        if r.epoch != 0, currentEpoch > 0, r.epoch < currentEpoch { return .staleEpoch }
        return nil
    }

    // MARK: control records

    private func verifyControl(_ records: [LaneRecord], witness w: inout LaneWitness, adminKey: Data?, into verdict: inout LaneVerdict) throws {
        func quarantine(_ r: LaneRecord, _ why: LaneQuarantineReason) { verdict.quarantined.append(.init(record: r, reason: why)) }

        // 1. The head pins the chain of admin keys.
        for r in records where r.kind == .head && r.id == ControlRecords.headID {
            guard let head = ControlRecords.decode(ControlRecords.Head.self, r.blob), ControlRecords.chainValid(head.aks, epoch: head.epoch),
                  let last = head.aks.last, ControlRecords.adminSignatureValid(r, key: last.ak) else { quarantine(r, .badSignature); continue }
            if head.epoch < w.epoch { quarantine(r, .rolledBackRecord); continue }
            if let pinned = w.aks.last {
                // The chain must still contain the key this device pinned.
                guard head.aks.contains(where: { $0.epoch == pinned.epoch && $0.ak == pinned.ak }) else { quarantine(r, .unpinnedSigner); continue }
            } else if let adminKey {
                guard head.aks.contains(where: { $0.ak == adminKey }) else { quarantine(r, .unpinnedSigner); continue }
            } else {
                w.held[heldKey(r)] = HeldRecord(r)    // locked and unpinned: nothing to check it against yet
                continue
            }
            w.aks = head.aks
            w.epoch = head.epoch
        }

        let rest = records.filter { !($0.kind == .head && $0.id == ControlRecords.headID) }
        guard !w.aks.isEmpty else {
            for r in rest { w.held[heldKey(r)] = HeldRecord(r) }
            return
        }

        // 2. The membership log, in order whatever order it arrived in.
        let logs = rest.filter { $0.kind == .log }.sorted { (ControlRecords.logNumber($0.id) ?? 0) < (ControlRecords.logNumber($1.id) ?? 0) }
        for r in logs {
            guard let n = ControlRecords.logNumber(r.id), let e = ControlRecords.decode(ControlRecords.LogEntry.self, r.blob), e.n == n else { quarantine(r, .malformed); continue }
            guard let key = ControlRecords.key(at: e.epoch, in: w.aks), ControlRecords.adminSignatureValid(r, key: key) else { quarantine(r, .badSignature); continue }
            if n <= w.logN {
                if n == w.logN, ControlRecords.logHash(r.blob) != w.logHash { quarantine(r, .chainBroken) }
                continue
            }
            if n > w.logN + 1 { w.held[heldKey(r)] = HeldRecord(r); continue }
            guard e.prev == w.logHash, e.epoch >= w.logEpoch else { quarantine(r, .chainBroken); continue }
            apply(e, blob: r.blob, to: &w)
        }
        // Entries that were waiting for their predecessors may fit now.
        while let next = w.held["log/\(ControlRecords.logID(w.logN + 1))"]?.record,
              let e = ControlRecords.decode(ControlRecords.LogEntry.self, next.blob), e.prev == w.logHash, e.epoch >= w.logEpoch {
            w.held["log/\(next.id)"] = nil
            apply(e, blob: next.blob, to: &w)
        }

        // 3. Envelopes, the recovery record and the writers' heads.
        for r in rest where r.kind != .log {
            switch r.kind {
            case .envelope:
                guard let parts = ControlRecords.envelopeParts(r.id), let key = ControlRecords.key(at: parts.epoch, in: w.aks),
                      ControlRecords.adminSignatureValid(r, key: key) else { quarantine(r, .badSignature); continue }
            case .recovery:
                guard let rec = ControlRecords.decode(ControlRecords.Recovery.self, r.blob), let key = ControlRecords.key(at: rec.epoch, in: w.aks),
                      ControlRecords.adminSignatureValid(r, key: key) else { quarantine(r, .badSignature); continue }
                guard rec.seq >= w.recoverySeq else { quarantine(r, .rolledBackRecord); continue }
                w.recoverySeq = rec.seq
                w.recovery = RecoveryMaterial(pubkey: rec.pubkey, encPubkey: rec.encPubkey, envelope: rec.envelope)
            case .head:
                guard let device = ControlRecords.deviceOfHead(r.id), let head = ControlRecords.decode(ControlRecords.DeviceHead.self, r.blob),
                      head.device == device else { quarantine(r, .malformed); continue }
                guard let member = w.members.first(where: { $0.id == device }) else { w.held[heldKey(r)] = HeldRecord(r); continue }
                guard let pub = Data(base64URLEncoded: member.sigPubkey), ControlRecords.deviceSignatureValid(r, sigPubkey: pub) else {
                    quarantine(r, .badSignature); continue
                }
                if let known = w.counters[device], head.counter < known {
                    throw IntegrityError.serverRolledBack(known: known, reported: head.counter)
                }
                w.counters[device] = head.counter
            default:
                break
            }
        }
    }

    private func heldKey(_ r: LaneRecord) -> String { "\(r.kind.rawValue)/\(r.id)" }

    private func apply(_ e: ControlRecords.LogEntry, blob: Data, to w: inout LaneWitness) {
        w.logN = e.n
        w.logHash = ControlRecords.logHash(blob)
        w.logEpoch = e.epoch
        switch e.type {
        case "bootstrap", "approve", "recovery":
            if let m = e.member, !w.members.contains(where: { $0.id == m.id }) { w.members.append(m) }
        case "revoke", "rotate":
            if let subject = e.subject, let i = w.members.firstIndex(where: { $0.id == subject }), w.members[i].revokedAt == nil {
                w.members[i].revokedAt = e.ts
            }
        default: break
        }
        w.events.append(ServerEvent(id: e.n, ts: e.ts, deviceId: e.by, type: e.type, subjectId: e.subject))
    }
}
