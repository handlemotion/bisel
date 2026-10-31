import CloudKit
import Foundation
import BiselCrypto
import BiselLane

/// The person's iCloud as the home of new boxes (`BoxHome`): the private database of `iCloud.app.bisel`, one zone per box, each
/// box at `cloudkit://<container>/<zone>`. Needs the signed app's iCloud entitlement, like `CloudKitLane`.
public final class ICloudHome: BoxHome, @unchecked Sendable {
    public static let scheme = "cloudkit"

    public let containerIdentifier: String
    private let container: CKContainer
    private let makeLane: @Sendable (_ zone: String) -> CloudKitLane

    /// `lane`: the lane for a zone. The app passes its cache, so the lane first run talks to is the one later syncs use.
    public init(container identifier: String = CloudKitLane.defaultContainer,
                lane: @escaping @Sendable (_ zone: String) -> CloudKitLane) {
        containerIdentifier = identifier
        container = CKContainer(identifier: identifier)
        makeLane = lane
    }

    public func address(zone: String) -> URL { URL(string: "\(Self.scheme)://\(containerIdentifier)/\(zone)")! }

    public func zone(of url: URL) -> String? {
        guard url.scheme == Self.scheme, url.host == containerIdentifier, !url.lastPathComponent.isEmpty, url.lastPathComponent != "/" else { return nil }
        return url.lastPathComponent
    }

    public func newAddress() -> URL { address(zone: CloudKitLane.zoneName(box: BiselRandom.identifier())) }

    public func lane(_ address: URL) -> (any SyncLane)? { zone(of: address).map(makeLane) }

    public func availability() async -> HomeAvailability {
        do {
            switch try await container.accountStatus() {
            case .available: break
            case .noAccount: return .unavailable(.notSignedIn)
            case .restricted: return .unavailable(.restricted)
            case .couldNotDetermine, .temporarilyUnavailable: return .unavailable(.temporarilyUnavailable)
            @unknown default: return .unavailable(.temporarilyUnavailable)
            }
            // Signed in is not enough: iCloud can be off for this app, which only a real request shows.
            _ = try await container.userRecordID()
            return .available
        } catch {
            return .unavailable(classify(error) ?? .temporarilyUnavailable)
        }
    }

    public func boxes() async throws -> [URL] {
        let zones = try await container.privateCloudDatabase.allRecordZones()
        return zones.map(\.zoneID.zoneName).filter { $0.hasPrefix("box-") }.sorted().map(address(zone:))
    }

    public func classify(_ error: any Error) -> HomeUnavailable? {
        if case LaneError.accountUnavailable(let reason) = error {
            // `CloudKitLane.describe` made the reason from the account status.
            switch reason {
            case CloudKitLane.describe(.noAccount): return .notSignedIn
            case CloudKitLane.describe(.restricted): return .restricted
            default: return .temporarilyUnavailable
            }
        }
        guard let ck = error as? CKError else { return nil }
        switch ck.code {
        case .networkUnavailable, .networkFailure: return .offline
        case .quotaExceeded: return .quotaFull
        case .notAuthenticated: return .notSignedIn
        case .managedAccountRestricted: return .restricted
        case .missingEntitlement, .badContainer, .permissionFailure: return .turnedOffForApp
        case .accountTemporarilyUnavailable, .serviceUnavailable, .requestRateLimited, .zoneBusy: return .temporarilyUnavailable
        case .partialFailure:
            // A batch fails as a whole for the first item's reason.
            return ck.partialErrorsByItemID?.values.lazy.compactMap { self.classify($0) }.first
        default: return nil
        }
    }
}
