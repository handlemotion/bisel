import Foundation
import BiselVault

// A lane is dumb, replaceable storage for a box's ciphertext (docs/SYNC-LANES.md §1). It never decides anything the client
// cannot re-check: `LaneVerifier` runs on everything a lane returns, whichever lane it came from.

public struct LaneID: Hashable, Sendable, Codable {
    /// `server:<host>:<boxID>`, `cloudkit:<container>:<zone>`.
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
}

public enum LaneKind: String, Sendable, Codable {
    case item, tombstone                  // id = item id
    case manifest                         // the reserved item, sealed under VK
    case envelope                         // id = "<epoch>.<deviceID>"; VK sealed to the device's DK-enc
    case recovery                         // RK public keys and the HPKE envelope
    case head                             // signed epoch / admin-key chain / counters
    case log                              // membership log entry
    case enroll                           // enrollment request / pairing proof
    case stage                            // a staged key rotation: the journal (`stage`) and its re-wrapped keys (`stage.<epoch>.<n>`)
}

/// The lane's own concurrency token. Opaque to the engine, which only stores and returns it.
public struct LaneTag: Hashable, Sendable, Codable {
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
}

public struct LaneCursor: Hashable, Sendable, Codable {
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
}

public struct LaneRecord: Sendable, Equatable {
    public var kind: LaneKind
    public var id: String
    /// Item revision; 0 for control records that use a counter.
    public var rev: Int
    /// Vault-key epoch the material was built for.
    public var epoch: Int
    /// Opaque; the `item` layout is unchanged (`wrapped IK (60) || nonce || ciphertext`).
    public var blob: Data
    /// Device id, advisory.
    public var writer: String?
    /// DK-sig / admin-key signature over `canonical`, on control records.
    public var sig: Data?
    public var tag: LaneTag?
    /// A lane-supplied, per-lane monotonic ordering hint (server `seq`, CloudKit modification time). Lets the hub tell a
    /// re-wrapped copy of the same revision from a stale one. Never compared across lanes.
    public var order: Int
    /// Unix seconds, as the lane reports it (display and trash ordering only).
    public var updatedAt: Int

    public init(kind: LaneKind, id: String, rev: Int, epoch: Int = 1, blob: Data, writer: String? = nil, sig: Data? = nil,
                tag: LaneTag? = nil, order: Int = 0, updatedAt: Int = 0) {
        self.kind = kind; self.id = id; self.rev = rev; self.epoch = epoch; self.blob = blob; self.writer = writer; self.sig = sig
        self.tag = tag; self.order = order; self.updatedAt = updatedAt
    }

    public var isItemLike: Bool { kind == .item || kind == .tombstone || kind == .manifest }

    /// The bytes a signature covers: everything but the tag, order and time, which belong to the lane.
    public var canonical: Data {
        var out = Data("bisel/v1/lane|\(kind.rawValue)|\(id)|\(rev)|\(epoch)|\(writer ?? "")|".utf8)
        out.append(blob)
        return out
    }
}

public struct LaneRecordRef: Sendable, Hashable {
    public var kind: LaneKind
    public var id: String
    public init(kind: LaneKind, id: String) { self.kind = kind; self.id = id }
}

public enum LaneExpect: Sendable, Equatable { case absent, tag(LaneTag), any }
public struct LaneWrite: Sendable {
    public var record: LaneRecord
    public var expect: LaneExpect
    public init(record: LaneRecord, expect: LaneExpect) { self.record = record; self.expect = expect }
}

public enum LaneRejection: Sendable, Equatable {
    case staleEpoch(serverEpoch: Int)
    case tooLarge
    case quota
    case forbidden
    /// Another device is part-way through a key rotation on this lane: try again after it committed or gave up.
    case rotationInProgress
}

public enum LaneWriteResult: Sendable, Equatable {
    /// Carries the new tag.
    case accepted(LaneRecord)
    /// `nil`: the lane has no such record (it lost state).
    case conflict(current: LaneRecord?)
    case rejected(LaneRejection)
}

public enum LaneReset: Sendable, Equatable {
    case cursorExpired, containerReplaced, accountChanged
}

/// What the lane says about the box besides its records. A lane that cannot say (a CloudKit zone) leaves it to the verifier,
/// which derives it from signed control records.
public struct LaneMeta: Sendable {
    public var epoch: Int
    /// Highest position the lane has ever reported (the server's `head_seq`). Never decreases.
    public var headSeq: Int
    public var members: [DeviceInfo]
    public var events: [ServerEvent]
    public var recovery: RecoveryMaterial?
    public init(epoch: Int, headSeq: Int, members: [DeviceInfo] = [], events: [ServerEvent] = [], recovery: RecoveryMaterial? = nil) {
        self.epoch = epoch; self.headSeq = headSeq; self.members = members; self.events = events; self.recovery = recovery
    }
}

public struct LaneChanges: Sendable {
    public var upserts: [LaneRecord]
    /// Hard deletes the lane reports (CloudKit only; the server never hard-deletes). Never honoured: see `LaneVerifier`.
    public var removed: [LaneRecordRef]
    public var cursor: LaneCursor
    public var hasMore: Bool
    public var reset: LaneReset?
    public var meta: LaneMeta?
    public init(upserts: [LaneRecord], removed: [LaneRecordRef] = [], cursor: LaneCursor, hasMore: Bool = false,
                reset: LaneReset? = nil, meta: LaneMeta? = nil) {
        self.upserts = upserts; self.removed = removed; self.cursor = cursor; self.hasMore = hasMore; self.reset = reset; self.meta = meta
    }
}

public struct LaneCapabilities: Sendable, Equatable {
    /// Largest all-or-nothing batch `commit` takes; 0 = none.
    public var atomicBatch: Int
    public var enforcesExpect: Bool
    public var pushNotifications: Bool
    public var history: Bool
    public var perDeviceAuth: Bool
    /// The lane's position is a number that only grows and is also the cursor (the server's `head_seq`). Lanes without one
    /// get their freshness from signed per-writer counters.
    public var headIsCursor: Bool
    /// A record can be written at any revision above the one the lane holds, so a lane that lost or replayed state is repaired
    /// by uploading the local copy. The server numbers revisions itself and cannot be repaired this way.
    public var repairs: Bool
    public init(atomicBatch: Int = 0, enforcesExpect: Bool = false, pushNotifications: Bool = false, history: Bool = false,
                perDeviceAuth: Bool = false, headIsCursor: Bool = false, repairs: Bool = false) {
        self.atomicBatch = atomicBatch; self.enforcesExpect = enforcesExpect; self.pushNotifications = pushNotifications
        self.history = history; self.perDeviceAuth = perDeviceAuth; self.headIsCursor = headIsCursor; self.repairs = repairs
    }
}

/// Who owns this storage (server: the box id; CloudKit: the hashed user record id). Pinned when the lane is enabled.
public struct LaneIdentity: Hashable, Sendable, Codable {
    public let rawValue: String
    public init(_ rawValue: String) { self.rawValue = rawValue }
}

/// A hint that something may have changed. Never carries data.
public enum LaneSignal: Sendable { case maybeChanged }

public struct LaneEraseToken: Sendable {
    public init() {}
}

public enum LaneError: Error, Sendable, Equatable {
    case unsupported
    /// The storage's account cannot be used right now (CloudKit: signed out, restricted, not determined). Nothing is lost;
    /// the lane pauses and edits stay pending.
    case accountUnavailable(String)
    /// The storage now belongs to a different account than the one pinned when the lane was enabled. Never upload to it.
    case accountChanged
    /// The storage the lane names is gone (CloudKit: the zone was deleted). The replica can re-seed it.
    case storeMissing
}

public protocol SyncLane: Sendable {
    var id: LaneID { get }
    var capabilities: LaneCapabilities { get }
    func identity() async throws -> LaneIdentity
    /// A page of records after `since` (nil: from the start), with the lane's view of the box in `meta`.
    func fetch(since: LaneCursor?, limit: Int) async throws -> LaneChanges
    /// The current copies of these records, nil where the lane has none.
    func read(_ refs: [LaneRecordRef]) async throws -> [LaneRecord?]
    /// Per record; not atomic.
    func write(_ batch: [LaneWrite]) async throws -> [LaneWriteResult]
    /// All or nothing; only if `capabilities.atomicBatch >= atomic.count`.
    func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult]
    func changes() -> AsyncStream<LaneSignal>
    /// Destructive and explicit (migration, detach).
    func erase(confirmed: LaneEraseToken) async throws
    /// Makes the storage exist (CloudKit: creates the box's zone). Only creating or re-seeding a box calls it: a store that
    /// vanished must stay missing (`LaneError.storeMissing`) until the person chose to upload the replica again.
    func prepare() async throws
    /// Hard-deletes records that are meant to go away (`enroll`, `stage`). Never items or control state: those are only
    /// ever overwritten, and the verifier treats a hard delete of them as an incident.
    func remove(_ refs: [LaneRecordRef]) async throws
}

public extension SyncLane {
    func read(_ refs: [LaneRecordRef]) async throws -> [LaneRecord?] { throw LaneError.unsupported }
    func commit(_ atomic: [LaneWrite]) async throws -> [LaneWriteResult] { throw LaneError.unsupported }
    func changes() -> AsyncStream<LaneSignal> { AsyncStream { $0.finish() } }
    func erase(confirmed: LaneEraseToken) async throws { throw LaneError.unsupported }
    func prepare() async throws {}
    func remove(_ refs: [LaneRecordRef]) async throws { throw LaneError.unsupported }
}
