import Foundation

/// Where a new box lives by default: the person's iCloud (docs/SYNC-LANES.md §3, D1, D2). What first run asks of it, and nothing
/// more: can a box go there now, which boxes does it already hold, and the lane at one of its addresses. The signed app's is
/// `ICloudHome` (BiselCloudKit); flow tests use `FakeHome`; BiselDev has none (`BoxSetup` reads that as `.notInThisBuild`).
public protocol BoxHome: Sendable {
    /// Whether a box can be put there right now. Never throws: every reason it cannot is a `HomeUnavailable`.
    func availability() async -> HomeAvailability
    /// The boxes this account already holds (their addresses), oldest first. Same Apple ID only (D2): another account's boxes
    /// are never visible here.
    func boxes() async throws -> [URL]
    /// A fresh address nobody has used, for a new box.
    func newAddress() -> URL
    /// The storage at one of this home's addresses; nil for an address that is not one of its own.
    func lane(_ address: URL) -> (any SyncLane)?
    /// What a failure from this home's storage means for the person, when it is one of the reasons it cannot be used (offline,
    /// quota full, signed out…). nil for everything else, which the caller reports as it is.
    func classify(_ error: any Error) -> HomeUnavailable?
}

public enum HomeAvailability: Sendable, Equatable {
    case available
    case unavailable(HomeUnavailable)
}

/// Why the person's iCloud cannot take a box right now. Nothing is lost in any of them; each has one thing the person can do.
public enum HomeUnavailable: Error, Sendable, Equatable {
    /// No Apple Account signed in to iCloud on this Mac.
    case notSignedIn
    /// Signed in, but iCloud is turned off for Bisel (or this build cannot use it).
    case turnedOffForApp
    /// iCloud is restricted on this Mac (Screen Time, a managed Mac).
    case restricted
    /// No network.
    case offline
    /// The person's iCloud storage is full.
    case quotaFull
    /// iCloud cannot say right now (account being set up, Apple's service busy). Try again in a moment.
    case temporarilyUnavailable
    /// This build has no iCloud at all (BiselDev, unsigned). Boxes live on this Mac only.
    case notInThisBuild
}

extension HomeUnavailable: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notSignedIn: return "Sign in to iCloud in System Settings to keep your box there."
        case .turnedOffForApp: return "iCloud is turned off for Bisel. Turn it on in System Settings → Apple Account → iCloud."
        case .restricted: return "iCloud is restricted on this Mac."
        case .offline: return "You're offline. Connect to the internet and try again."
        case .quotaFull: return "Your iCloud storage is full. Free some space and try again."
        case .temporarilyUnavailable: return "iCloud isn't available right now. Try again in a moment."
        case .notInThisBuild: return "This build of Bisel has no iCloud. Your box stays on this Mac."
        }
    }
}
