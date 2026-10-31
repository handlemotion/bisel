import Foundation

/// Where a box's data lives besides the backup file (D4, docs/SYNC-LANES.md §8).
public enum BoxCopies: String, Sendable, Equatable, Codable {
    /// Only this Mac holds the box: losing it loses everything a backup does not have.
    case thisDeviceOnly
    /// The box syncs through a storage-only lane (CloudKit): losing the Apple ID and every device loses the box, and the
    /// 24 words alone cannot bring it back.
    case cloudKitOnly
    /// A Bisel server holds a second copy the phrase can recover from.
    case server
}

/// What this device remembers about its last backup. Kept per device in the local store.
public struct BackupState: Codable, Sendable, Equatable {
    public var lastBackupAt: Date
    public var fileName: String?
    /// Version marker of every record (tombstones included) when the backup was written: what counts as unchanged since.
    public var versions: [String: String]

    public init(lastBackupAt: Date, fileName: String?, versions: [String: String]) {
        self.lastBackupAt = lastBackupAt; self.fileName = fileName; self.versions = versions
    }

    /// Items created, edited or deleted since the backup (each counted once however often it changed).
    public func changes(since now: [String: String]) -> Int {
        let edited = now.filter { versions[$0.key] != $0.value }.count
        let gone = versions.keys.filter { now[$0] == nil }.count
        return edited + gone
    }
}

/// Whether the app must ask for a backup now.
public enum BackupReminder: Sendable, Equatable {
    case none
    /// The box has never been backed up from this device.
    case noBackupYet
    /// The last backup is older than the policy allows.
    case stale(lastBackupAt: Date)
    /// Too many items changed since the last backup.
    case manyChanges(Int, lastBackupAt: Date)

    public var isDue: Bool { self != .none }
}

/// When a box with no second copy must be reminded to export a `.bisel-backup` (D4). Pure: the caller supplies the state.
public struct BackupReminderPolicy: Sendable, Equatable {
    /// A backup older than this is stale.
    public var maxAge: TimeInterval
    /// More changed items than this since the last backup make it stale too.
    public var maxChanges: Int
    /// Boxes a server also holds are reminded only when this is true.
    public var remindWithServer: Bool

    public init(maxAge: TimeInterval = 30 * 86_400, maxChanges: Int = 25, remindWithServer: Bool = false) {
        self.maxAge = maxAge; self.maxChanges = maxChanges; self.remindWithServer = remindWithServer
    }

    public static let standard = BackupReminderPolicy()

    public func evaluate(copies: BoxCopies, state: BackupState?, changes: Int, now: Date = Date()) -> BackupReminder {
        if copies == .server, !remindWithServer { return .none }
        guard let state else { return .noBackupYet }
        if now.timeIntervalSince(state.lastBackupAt) > maxAge { return .stale(lastBackupAt: state.lastBackupAt) }
        if changes > maxChanges { return .manyChanges(changes, lastBackupAt: state.lastBackupAt) }
        return .none
    }
}

/// Everything the UI needs to decide whether to nag and what to say.
public struct BackupStatus: Sendable, Equatable {
    public var copies: BoxCopies
    public var lastBackupAt: Date?
    public var lastFileName: String?
    public var changesSinceBackup: Int
    public var reminder: BackupReminder

    public init(copies: BoxCopies, lastBackupAt: Date?, lastFileName: String?, changesSinceBackup: Int, reminder: BackupReminder) {
        self.copies = copies; self.lastBackupAt = lastBackupAt; self.lastFileName = lastFileName
        self.changesSinceBackup = changesSinceBackup; self.reminder = reminder
    }
}
