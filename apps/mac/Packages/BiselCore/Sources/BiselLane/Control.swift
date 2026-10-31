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
        public init(seq: Int, epoch: Int, pubkey: String, encPubkey: String, envelope: String) {
            self.seq = seq; self.epoch = epoch; self.pubkey = pubkey; self.encPubkey = encPubkey; self.envelope = envelope
        }
    }

    public struct DeviceHead: Codable, Sendable, Equatable {
        public var device: String
        public var counter: Int
        public var epoch: Int
        public init(device: String, counter: Int, epoch: Int) { self.device = device; self.counter = counter; self.epoch = epoch }
    }

    static let encoder: JSONEncoder = { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; return e }()
    public static func encode<T: Encodable>(_ value: T) throws -> Data { try encoder.encode(value) }
    public static func decode<T: Decodable>(_ type: T.Type, _ blob: Data) -> T? { try? JSONDecoder().decode(type, from: blob) }

    /// What the previous key signs to hand over to the next one.
    public static func chainMessage(newKey: Data) -> Data { Data("bisel/v1/ak-chain|".utf8) + newKey }

    public static func logHash(_ blob: Data) -> String { blob.sha256Hex() }

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
