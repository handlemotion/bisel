import Foundation
import CryptoKit
import BiselCrypto

// Control records: the authority of a box on a lane that enforces nothing (docs/SYNC-LANES.md §2, §4, §8).
//
//   head              the box's epoch and the chain of vault-admin keys (AK) up to the current one; signed by the current AK
//   log.<n>           membership log, hash-chained, signed by the AK of its epoch
//   <epoch>.<device>  a device envelope (kind .envelope), signed by the AK of its epoch
//   recovery          the recovery public keys and envelope, signed by the AK of its epoch
//   head.<device>     freshness: a strictly increasing counter per writer, signed by that device's DK-sig
//
// AK is derived from the vault key, so any device holding VK can sign; a device that does not is never trusted for these.

public enum ControlRecords {
    public static let headID = "head"
    public static let recoveryID = "recovery"
    public static func logID(_ n: Int) -> String { "log.\(n)" }
    public static func envelopeID(epoch: Int, device: String) -> String { "\(epoch).\(device)" }
    public static func deviceHeadID(_ device: String) -> String { "head.\(device)" }
    public static func logNumber(_ id: String) -> Int? { id.hasPrefix("log.") ? Int(id.dropFirst(4)) : nil }
    public static func deviceOfHead(_ id: String) -> String? { id.hasPrefix("head.") ? String(id.dropFirst(5)) : nil }
    /// `(epoch, device)` of an envelope id.
    public static func envelopeParts(_ id: String) -> (epoch: Int, device: String)? {
        guard let dot = id.firstIndex(of: "."), let epoch = Int(id[..<dot]) else { return nil }
        return (epoch, String(id[id.index(after: dot)...]))
    }

    /// One key of the admin-key chain. Link `i` is signed by link `i - 1`; the first has no signature.
    public struct AKLink: Codable, Sendable, Equatable {
        public var epoch: Int
        public var ak: Data
        public var sig: Data?
        public init(epoch: Int, ak: Data, sig: Data?) { self.epoch = epoch; self.ak = ak; self.sig = sig }
    }

    public struct Head: Codable, Sendable, Equatable {
        public var v = 1
        public var epoch: Int
        public var aks: [AKLink]
        public init(epoch: Int, aks: [AKLink]) { self.epoch = epoch; self.aks = aks }
    }

    public struct LogEntry: Codable, Sendable, Equatable {
        public var n: Int
        /// SHA-256 (hex) of the previous entry's blob; empty for the first.
        public var prev: String
        /// `bootstrap`, `approve`, `revoke`, `rotate`, `recovery`, `recovery_rotate`.
        public var type: String
        public var by: String?
        public var subject: String?
        public var epoch: Int
        public var ts: Int
        /// The device a `bootstrap`, `approve` or `recovery` entry adds.
        public var member: DeviceInfo?
        public init(n: Int, prev: String, type: String, by: String?, subject: String?, epoch: Int, ts: Int, member: DeviceInfo? = nil) {
            self.n = n; self.prev = prev; self.type = type; self.by = by; self.subject = subject; self.epoch = epoch; self.ts = ts; self.member = member
        }
    }

    public struct Recovery: Codable, Sendable, Equatable {
        public var seq: Int
        public var epoch: Int
        public var pubkey: String
        public var encPubkey: String
        public var envelope: String
        /// RK-sig's signature over the first admin key of the chain (`anchorMessage`): what a device recovering with the phrase,
        /// which has seen nothing of the box yet, checks the head against. The envelope is sealed to a public key, so without it
        /// anyone who can write to the storage could build a box of their own around an envelope the phrase opens.
        public var anchor: String?
        public init(seq: Int, epoch: Int, pubkey: String, encPubkey: String, envelope: String, anchor: String? = nil) {
            self.seq = seq; self.epoch = epoch; self.pubkey = pubkey; self.encPubkey = encPubkey; self.envelope = envelope; self.anchor = anchor
        }
    }

    public struct DeviceHead: Codable, Sendable, Equatable {
        public var device: String
        public var counter: Int
        public var epoch: Int
        public init(device: String, counter: Int, epoch: Int) { self.device = device; self.counter = counter; self.epoch = epoch }
    }

    // MARK: enrollment over the lane (§4)
    //
    //   enroll.<device>           the new device's request, signed by its own DK-sig (the key inside it)
    //   enroll.<device>.approved  the approver's pairing MAC over the envelope it sealed, signed by the AK of the head's epoch
    //
    // Both are deleted by the new device once it took its envelope; the verifier passes them through untouched.

    public static func enrollID(_ device: String) -> String { "enroll.\(device)" }
    public static func enrollApprovedID(_ device: String) -> String { "enroll.\(device).approved" }
    /// The device of a request id (`enroll.<device>`); nil for an approval or anything else.
    public static func deviceOfEnrollRequest(_ id: String) -> String? {
        guard id.hasPrefix("enroll."), !id.hasSuffix(".approved") else { return nil }
        let device = String(id.dropFirst(7))
        return device.isEmpty || device.contains(".") ? nil : device
    }

    public struct EnrollRequest: Codable, Sendable, Equatable {
        public var v = 1
        public var deviceID: String
        public var name: String
        public var kind: String
        public var sigPubkey: String
        public var encPubkey: String
        /// Unix seconds on the new device's clock. Bound into the proof; never used for expiry (the approver's clock is).
        public var createdAt: Int
        /// `PairingSecret.proof` over the device id, both keys and `createdAt`.
        public var proof: String
        public init(deviceID: String, name: String, kind: String, sigPubkey: String, encPubkey: String, createdAt: Int, proof: String) {
            self.deviceID = deviceID; self.name = name; self.kind = kind; self.sigPubkey = sigPubkey; self.encPubkey = encPubkey
            self.createdAt = createdAt; self.proof = proof
        }
    }

    public struct EnrollApproval: Codable, Sendable, Equatable {
        public var deviceID: String
        public var epoch: Int
        /// SHA-256 (hex) of the envelope blob the approver sealed.
        public var envelopeHash: String
        /// `PairingSecret.approval` over the device id, `envelopeHash`, the root admin key and `epoch`.
        public var mac: String
        public init(deviceID: String, epoch: Int, envelopeHash: String, mac: String) {
            self.deviceID = deviceID; self.epoch = epoch; self.envelopeHash = envelopeHash; self.mac = mac
        }
    }

    /// The request in `record` if it holds together: an `enroll.<device>` record naming that device, signed by the signing key it
    /// carries. That proves only that whoever wrote it holds that key; whether the key is the new device's is the proof's job.
    public static func verifiedEnrollRequest(_ record: LaneRecord) -> EnrollRequest? {
        guard record.kind == .enroll, let device = deviceOfEnrollRequest(record.id), let request = decode(EnrollRequest.self, record.blob),
              request.deviceID == device, let sig = Data(base64URLEncoded: request.sigPubkey), Data(base64URLEncoded: request.encPubkey) != nil,
              Data(base64URLEncoded: request.proof) != nil, deviceSignatureValid(record, sigPubkey: sig) else { return nil }
        return request
    }

    // MARK: staged rotation (docs/SYNC-LANES.md §5)
    //
    //   stage                 the journal of a rotation from `from` to `to`, signed by the admin key of `from`
    //   stage.<to>.<n>        the re-wrapped item keys, signed by the new admin key (the one the committed head ends in)
    //
    // A lane whose atomic commit is smaller than the box cannot switch keys in one write. The rotator stages the new wraps next to
    // the items (which stay readable under the old key), commits head, recovery and log entry atomically, then folds the staged
    // keys into the items. Any device holding the new key can finish the fold.

    public static let stageID = "stage"
    public static func stageChunkID(epoch: Int, n: Int) -> String { "stage.\(epoch).\(n)" }
    /// A journal older than this belongs to a rotator that gave up or died: another device may take over (or clean up after it).
    public static let stageTTL = 15 * 60

    public struct StageJournal: Codable, Sendable, Equatable {
        public var from: Int
        public var to: Int
        /// Ties the chunks to this attempt: a chunk left behind by an earlier one is never folded.
        public var nonce: String
        public var rotator: String?
        /// The admin key of `to` (base64url), the one the chunks are signed with.
        public var newAK: String
        public var startedAt: Int
        public var chunks: Int
        public init(from: Int, to: Int, nonce: String, rotator: String?, newAK: String, startedAt: Int, chunks: Int) {
            self.from = from; self.to = to; self.nonce = nonce; self.rotator = rotator; self.newAK = newAK; self.startedAt = startedAt; self.chunks = chunks
        }
        /// Read off the rotator's clock: one far in the future counts as stale too, so a wrong clock cannot block a box for long.
        public func isFresh(now: Int) -> Bool { abs(now - startedAt) < ControlRecords.stageTTL }
    }

    public struct StageChunk: Codable, Sendable, Equatable {
        public var epoch: Int
        public var nonce: String
        public var items: [StagedKey]
        public init(epoch: Int, nonce: String, items: [StagedKey]) { self.epoch = epoch; self.nonce = nonce; self.items = items }
    }

    /// One item's new wrap: the 60-byte wrapped item key, or for a tombstone the whole new marker (base64url). `rev` is the
    /// revision it was built for; the fold leaves an item that moved on alone.
    public struct StagedKey: Codable, Sendable, Equatable {
        public var id: String
        public var rev: Int
        public var key: String
        public var tomb: Bool
        public init(id: String, rev: Int, key: String, tomb: Bool) { self.id = id; self.rev = rev; self.key = key; self.tomb = tomb }
    }

    /// The journal in `record` if it is one and is signed by the admin key in force at its `from` in `chain`. A revoked device
    /// keeps the admin key of the epoch it was cut off in, so it can sign journals for old epochs: callers compare `from`/`to`
    /// with the verified head, and the chunks must verify under the head's own last key.
    public static func verifiedJournal(_ record: LaneRecord?, chain: [AKLink]) -> StageJournal? {
        guard let record, record.kind == .stage, record.id == stageID, let j = decode(StageJournal.self, record.blob),
              j.to == j.from + 1, record.epoch == j.from, j.chunks >= 0,
              let key = key(at: j.from, in: chain), adminSignatureValid(record, key: key) else { return nil }
        return j
    }

    static let encoder: JSONEncoder = { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; return e }()
    public static func encode<T: Encodable>(_ value: T) throws -> Data { try encoder.encode(value) }
    public static func decode<T: Decodable>(_ type: T.Type, _ blob: Data) -> T? { try? JSONDecoder().decode(type, from: blob) }

    /// What the previous key signs to hand over to the next one.
    public static func chainMessage(newKey: Data) -> Data { Data("bisel/v1/ak-chain|".utf8) + newKey }

    public static func logHash(_ blob: Data) -> String { blob.sha256Hex() }

    /// What the recovery signing key signs to vouch for a box: the first admin key of its chain.
    public static func anchorMessage(root: Data) -> Data { Data("bisel/v1/recovery-anchor|".utf8) + root }

    public static func adminSignatureValid(_ record: LaneRecord, key: Data) -> Bool {
        guard let sig = record.sig, let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: key) else { return false }
        return pub.isValidSignature(sig, for: record.canonical)
    }

    public static func deviceSignatureValid(_ record: LaneRecord, sigPubkey: Data) -> Bool {
        guard let sig = record.sig, let pub = try? P256.Signing.PublicKey(x963Representation: sigPubkey),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: sig) else { return false }
        return pub.isValidSignature(signature, for: record.canonical)
    }

    /// Whether `links` is a well-formed chain (each link signed by the one before) ending at `epoch`.
    public static func chainValid(_ links: [AKLink], epoch: Int) -> Bool {
        guard let last = links.last, last.epoch == epoch, links[0].sig == nil else { return false }
        for (i, link) in links.enumerated().dropFirst() {
            guard link.epoch > links[i - 1].epoch, let sig = link.sig,
                  let prev = try? Curve25519.Signing.PublicKey(rawRepresentation: links[i - 1].ak),
                  prev.isValidSignature(sig, for: chainMessage(newKey: link.ak)) else { return false }
        }
        return true
    }

    /// The admin key in force at `epoch`: the last link at or before it.
    public static func key(at epoch: Int, in links: [AKLink]) -> Data? { links.last { $0.epoch <= epoch }?.ak }

    /// The head in `record` if it holds together: a well-formed chain, the record signed by its last key, and (when this device
    /// pinned a chain before) still containing the key it pinned. Anyone who can write to the storage can write a head, so a read
    /// that decides anything (the epoch to write for, which envelope to take) goes through this.
    public static func verifiedHead(_ record: LaneRecord, pinned: [AKLink]) -> Head? {
        guard record.kind == .head, record.id == headID, let head = decode(Head.self, record.blob), chainValid(head.aks, epoch: head.epoch),
              let last = head.aks.last, adminSignatureValid(record, key: last.ak) else { return nil }
        if let pin = pinned.last {
            guard head.epoch >= pin.epoch, head.aks.contains(where: { $0.epoch == pin.epoch && $0.ak == pin.ak }) else { return nil }
        }
        return head
    }
}

/// Everything a device has verified about a lane's control records so far. Persisted per lane (`lane_state.witness`); what
/// an incremental fetch cannot show again is kept here.
public struct LaneWitness: Codable, Sendable, Equatable {
    public var epoch = 0
    public var aks: [ControlRecords.AKLink] = []
    public var logN = 0
    public var logHash = ""
    /// Epoch of the last log entry applied; later entries may not go back.
    public var logEpoch = 0
    public var members: [DeviceInfo] = []
    public var events: [ServerEvent] = []
    public var recovery: RecoveryMaterial?
    public var recoverySeq = 0
    /// Highest counter seen from each writer.
    public var counters: [String: Int] = [:]
    /// Control records that arrived before what is needed to verify them (a log entry before its predecessor, anything before
    /// the head), by `"<kind>/<id>"`.
    public var held: [String: HeldRecord] = [:]
    public init() {}

    /// A position that only grows: the log length plus every writer's counter.
    public var position: Int { logN + counters.values.reduce(0, +) }
}

/// An enrollment request this device saw on the lane, and when (its own clock: the request's `createdAt` is the requester's
/// word and could be anything). Kept by `LaneEngine.pull` until the device joins, the lane drops the request, or newer ones
/// push it out.
public struct ReceivedEnrollment: Codable, Sendable, Equatable {
    public var request: ControlRecords.EnrollRequest
    public var receivedAt: Int
    public init(request: ControlRecords.EnrollRequest, receivedAt: Int) { self.request = request; self.receivedAt = receivedAt }
}

/// A control record kept aside until it can be verified.
public struct HeldRecord: Codable, Sendable, Equatable {
    public var kind: LaneKind
    public var id: String
    public var epoch: Int
    public var blob: Data
    public var sig: Data?
    public var writer: String?
    public init(_ r: LaneRecord) { kind = r.kind; id = r.id; epoch = r.epoch; blob = r.blob; sig = r.sig; writer = r.writer }
    public var record: LaneRecord { LaneRecord(kind: kind, id: id, rev: 0, epoch: epoch, blob: blob, writer: writer, sig: sig) }
    public var key: String { "\(kind.rawValue)/\(id)" }
}
