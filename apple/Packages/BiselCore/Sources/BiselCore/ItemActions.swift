import Foundation

// The operations the command panel's add / edit / delete screens call. Everything here is local (encrypt and commit to the store);
// the caller runs `sync()` afterwards, exactly as after `save`.

public enum ItemActionError: Error, Sendable, Equatable {
    /// `updateItem` needs a draft made with `ItemDraft(editing:)`.
    case draftIsNew
    /// `createItem` needs a draft made with `ItemDraft(type:)` or `ItemDraft(copying:)`.
    case draftIsEdit
    /// The deleted version is no longer in the local trash (30 days passed) or the receipt is not from this vault.
    case undoUnavailable
}

/// An edit that could not be saved as it stands. Nothing was written. Show `fields` (or "deleted on another device"),
/// let the owner choose, and call `updateItem` again with the same draft and `ConflictResolution(choice, for: conflict)`.
public struct ItemConflict: Error, Sendable, Equatable {
    public let itemID: String
    /// The item as it is now. Nil when it was deleted on another device (or is gone).
    public let current: Item?
    /// What the draft would have produced: the version the form was opened on with the owner's changes applied.
    public let mine: Item
    /// Fields both sides changed to different values. Empty when `current` is nil.
    public let fields: [ItemFieldID]

    /// Appended to the title of the copy `keepBoth` creates (the sync engine uses the same suffix).
    public static let copySuffix = " (conflict)"
    public var itemWasDeleted: Bool { current == nil }
}

public struct ConflictResolution: Sendable, Equatable {
    public enum Choice: Sendable, Equatable {
        /// The conflicting fields take the owner's values; the other device's non-conflicting changes stay.
        /// For an item deleted elsewhere: bring it back with the owner's version.
        case useMine
        /// The conflicting fields keep the other device's values; the owner's non-conflicting changes are still applied.
        /// For an item deleted elsewhere: drop the draft.
        case useTheirs
        /// The item stays as it is and the owner's version becomes a new item titled "<title> (conflict)".
        /// For an item deleted elsewhere this is the same as `useMine`.
        case keepBoth
    }
    public let choice: Choice
    public let conflict: ItemConflict
    public init(_ choice: Choice, for conflict: ItemConflict) { self.choice = choice; self.conflict = conflict }
}

public enum UpdateOutcome: Sendable, Equatable {
    /// The draft changes nothing. Nothing was written and no biometric check ran.
    case unchanged(Item)
    /// Saved. `mergedRemoteChanges`: the item had changed elsewhere since the form was opened; those changes were kept.
    case saved(Item, mergedRemoteChanges: Bool)
    /// `keepBoth`: the original is untouched; this is the new copy.
    case savedAsCopy(Item)
    /// `useTheirs` (or an item deleted elsewhere): the owner's changes were dropped; this is what stays (nil: nothing).
    case discarded(Item?)
}

/// Proof that this vault moved an item to the trash, good for `undoTrash`.
public struct TrashReceipt: Sendable, Equatable, Identifiable {
    public let itemID: String
    public let title: String
    public let type: ItemType
    public let deletedAt: Date
    let trashKey: Int
    public var id: String { "\(itemID)#\(trashKey)" }

    /// Seconds after `deletedAt` during which `undoTrash` needs no biometric check. After that it asks like any restore.
    public static let undoWindow: TimeInterval = 10
    /// How long the local trash keeps a deleted item.
    public static let retention: TimeInterval = 30 * 24 * 3600
    public var isInUndoWindow: Bool { Date().timeIntervalSince(deletedAt) <= Self.undoWindow }
}

extension Vault {
    // MARK: create

    /// Validates the draft and stores it as a new item. Idempotent per draft: if an item with the draft's id is already there
    /// (the form was submitted twice) the stored one is returned and nothing is written. No biometric check.
    /// Throws `ItemValidationError`, `ItemActionError.draftIsEdit`, `VaultError.locked`.
    @discardableResult
    public func createItem(_ draft: ItemDraft) async throws -> Item {
        guard draft.base == nil else { throw ItemActionError.draftIsEdit }
        var item = try ItemValidator.item(from: draft)
        let k = try requireKey()
        if let rec = try store.record(item.id), !rec.deleted { return try decrypt(rec, k) }
        let now = Self.storedNow()
        item.createdAt = now; item.updatedAt = now
        try writeItem(item, key: k, keepPrevious: false)
        return item
    }

    // MARK: edit

    /// Saves an edit made on top of `draft.base`. Fields the owner did not touch are never rewritten, and fields changed on
    /// another device in the meantime are kept, so a stale form cannot overwrite newer data. When both sides changed the same
    /// field differently (or the item was deleted elsewhere) nothing is written and `ItemConflict` is thrown; call again with
    /// `resolution`. A write needs a fresh biometric check (not for `unchanged` or `keepBoth`).
    /// Throws `ItemValidationError`, `ItemConflict`, `ItemActionError.draftIsNew`, `VaultError.locked`.
    @discardableResult
    public func updateItem(_ draft: ItemDraft, resolution: ConflictResolution? = nil) async throws -> UpdateOutcome {
        guard let base = draft.base else { throw ItemActionError.draftIsNew }
        let content = try ItemValidator.validated(draft)
        var authenticated = false
        while true {
            let k = try requireKey()
            let current = try store.record(draft.id).flatMap { $0.deleted ? nil : try decrypt($0, k) }
            switch ItemMerge.plan(draft: draft, content: content, base: base, current: current, resolution: resolution) {
            case .unchanged(let item): return .unchanged(item)
            case .discard(let item): return .discarded(item)
            case .conflict(let conflict): throw conflict
            case .copy(let copy):
                try writeItem(try checked(copy), key: k, keepPrevious: false)
                return .savedAsCopy(copy)
            case .write(var item, let remote, let keepPrevious):
                // The check is a suspension point: the store may change meanwhile, so decide again afterwards and commit
                // without another suspension.
                if !authenticated { try await config.gate.authenticate(reason: "Edit \(base.title)"); authenticated = true; continue }
                item.updatedAt = Self.storedNow()
                try writeItem(try checked(item), key: k, keepPrevious: keepPrevious || keepsLocalHistory())
                return .saved(item, mergedRemoteChanges: remote)
            }
        }
    }

    // MARK: delete / undo

    /// Moves an item to the trash (kept 30 days, encrypted) after a fresh biometric check. Sync carries the delete to the
    /// server. Offer `undoTrash(receipt)` for `TrashReceipt.undoWindow` seconds.
    /// Throws `VaultError.notFound`, `VaultError.locked`, or the biometric gate's error (cancel).
    public func trashItem(id: String) async throws -> TrashReceipt {
        let first = try requireKey()
        guard let rec = try store.record(id), !rec.deleted else { throw VaultError.notFound(id) }
        let title = (try? decrypt(rec, first))?.title ?? ""
        try await config.gate.authenticate(reason: "Delete item")
        let k = try requireKey()
        guard let rec = try store.record(id), !rec.deleted else { throw VaultError.notFound(id) }
        let item = try? decrypt(rec, k)
        if rec.pending == .put && rec.baseRev == 0 {
            try store.forget(id, keepInTrash: true)   // never reached the server: no tombstone needed
        } else {
            try store.commitLocal(id: id, deleted: true, keepPrevious: true) { rev in
                try k.withKey { try ItemSealer.sealTombstone(id: id, rev: rev, vaultKey: $0) }
            }
        }
        guard let entry = try store.trashedRecords(id: id).first(where: { $0.reason == "local-delete" }) else {
            throw ItemActionError.undoUnavailable
        }
        return TrashReceipt(itemID: id, title: item?.title ?? title, type: item?.type ?? .login, deletedAt: entry.replacedAt, trashKey: entry.key)
    }

    /// Puts a trashed item back as its newest revision. No biometric check inside `TrashReceipt.undoWindow`, one after it.
    /// If the item is already back (restored elsewhere) it is returned as it is.
    /// Throws `ItemActionError.undoUnavailable`, `VaultError.locked`.
    @discardableResult
    public func undoTrash(_ receipt: TrashReceipt) async throws -> Item {
        _ = try requireKey()
        if !receipt.isInUndoWindow { try await config.gate.authenticate(reason: "Restore \(receipt.title)") }
        let k = try requireKey()
        if let live = try store.record(receipt.itemID), !live.deleted {
            try? store.removeFromTrash(key: receipt.trashKey)
            return try decrypt(live, k)
        }
        guard let entry = try store.trashedRecords(id: receipt.itemID).first(where: { $0.key == receipt.trashKey }),
              var item = try? decrypt(entry.record, k) else { throw ItemActionError.undoUnavailable }
        item.updatedAt = Self.storedNow()
        try writeItem(item, key: k, keepPrevious: false)
        try store.removeFromTrash(key: receipt.trashKey)
        return item
    }

    /// Items moved to the trash on this device in the last 30 days that are not back yet, newest first.
    /// Each receipt works with `undoTrash` (which asks for a biometric check once its undo window is over).
    public func recentlyDeleted() throws -> [TrashReceipt] {
        let k = try requireKey()
        return try store.trashedRecords().compactMap { t in
            guard t.reason == "local-delete", !t.record.deleted, !ReservedRecord.isReserved(t.record.id),
                  let item = try? decrypt(t.record, k) else { return nil }
            if let live = try store.record(t.record.id), !live.deleted { return nil }
            return TrashReceipt(itemID: item.id, title: item.title, type: item.type, deletedAt: t.replacedAt, trashKey: t.key)
        }
    }

    // MARK: helpers

    /// Items are stored with whole-second dates, so what these operations return equals what a later read gives back.
    static func storedNow() -> Date { Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down)) }

    private func checked(_ item: Item) throws -> Item {
        if let issue = ItemValidator.sizeIssue(for: item) { throw ItemValidationError(issues: [issue]) }
        return item
    }

    private func writeItem(_ item: Item, key k: LockedKey, keepPrevious: Bool) throws {
        let payload = try ItemCodec.encode(item)
        let id = item.id
        try store.commitLocal(id: id, deleted: false, now: item.updatedAt, keepPrevious: keepPrevious) { rev in
            try k.withKey { try ItemSealer.seal(payload: payload, id: id, rev: rev, vaultKey: $0) }
        }
    }
}

// MARK: three-way merge

enum MergePlan {
    case unchanged(Item)
    case write(Item, remoteChanges: Bool, keepPrevious: Bool)
    case copy(Item)
    case discard(Item?)
    case conflict(ItemConflict)
}

/// Field-level three-way merge of `base` (what the form was opened on), the draft, and `current` (what is stored now).
enum ItemMerge {
    static func plan(draft: ItemDraft, content n: NormalizedContent, base: Item, current: Item?, resolution: ConflictResolution?) -> MergePlan {
        let was = ItemDraft(editing: base)
        let typeChanged = draft.type != was.type
        func touched(_ f: ItemFieldID) -> Bool {
            if typeChanged { return true }
            return switch f {
            case .title: draft.title != was.title
            case .urls: draft.urls != was.urls
            case .username: draft.username != was.username
            case .password: draft.password != was.password
            case .totp: draft.totp != was.totp
            case .notes: draft.notes != was.notes
            case .fields: draft.fields != was.fields
            case .tags: draft.tags != was.tags
            case .type, .size: false
            }
        }

        // The version the owner meant: the one they opened with their changes on top.
        var mine = base
        mine.type = n.type
        if touched(.title) { mine.title = n.title }
        if touched(.urls) { mine.urls = n.urls }
        if touched(.username) { mine.username = n.username }
        if touched(.password) { mine.password = n.password }
        if touched(.totp) { mine.totp = n.totp }
        if touched(.notes) { mine.notes = n.notes }
        if touched(.fields) { mine.fields = n.fields }
        if touched(.tags) { mine.tags = n.tags }

        guard let current else {
            let conflict = ItemConflict(itemID: draft.id, current: nil, mine: mine, fields: [])
            guard let r = resolution, r.conflict == conflict else { return .conflict(conflict) }
            return r.choice == .useTheirs ? .discard(nil) : .write(mine, remoteChanges: false, keepPrevious: false)
        }

        var result = current
        result.type = mine.type
        var changed: [ItemFieldID] = [], clashes: [ItemFieldID] = []
        var overlays: [(inout Item) -> Void] = []
        func consider<T: Equatable>(_ id: ItemFieldID, _ path: WritableKeyPath<Item, T>) {
            guard touched(id) else { return }
            let value = mine[keyPath: path]
            guard value != current[keyPath: path] else { return }
            if base[keyPath: path] != current[keyPath: path] {   // changed on both sides, differently
                clashes.append(id); overlays.append { $0[keyPath: path] = value }
            } else {
                result[keyPath: path] = value; changed.append(id)
            }
        }
        consider(.title, \.title); consider(.urls, \.urls); consider(.username, \.username); consider(.password, \.password)
        consider(.totp, \.totp); consider(.notes, \.notes); consider(.fields, \.fields); consider(.tags, \.tags)
        if mine.type != current.type { changed.append(.type) }
        let remote = current.differsInContent(from: base)

        if clashes.isEmpty { return changed.isEmpty ? .unchanged(current) : .write(result, remoteChanges: remote, keepPrevious: false) }

        let conflict = ItemConflict(itemID: draft.id, current: current, mine: mine, fields: clashes)
        guard let r = resolution, r.conflict == conflict else { return .conflict(conflict) }
        switch r.choice {
        case .useMine:
            for o in overlays { o(&result) }
            return .write(result, remoteChanges: remote, keepPrevious: true)
        case .useTheirs:
            return changed.isEmpty ? .discard(current) : .write(result, remoteChanges: remote, keepPrevious: false)
        case .keepBoth:
            var copy = mine
            copy.id = BiselRandom.identifier()
            copy.title += ItemConflict.copySuffix
            copy.createdAt = Vault.storedNow(); copy.updatedAt = copy.createdAt
            return .copy(copy)
        }
    }
}

private extension Item {
    /// True when anything but the timestamps differs.
    func differsInContent(from other: Item) -> Bool {
        var a = self
        a.createdAt = other.createdAt; a.updatedAt = other.updatedAt
        return a != other
    }
}
