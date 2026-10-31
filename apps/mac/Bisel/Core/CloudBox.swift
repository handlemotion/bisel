#if BISEL_CLOUDKIT
import CloudKit
import Foundation
import BiselCloudKit
import BiselCore

/// The box in the person's iCloud (docs/SYNC-LANES.md §3): where the signed build creates every new box. BiselDev (unsigned, no
/// iCloud entitlement) does not define BISEL_CLOUDKIT, so dev runs compile none of this and never touch real CloudKit.
///
/// A box's address (`LocalIdentity.serverURL`) is `cloudkit://<container>/<zone>`, one zone per box (`box-<random id>`).
enum CloudBox {
    static let scheme = "cloudkit"
    static var container: String { CloudKitLane.defaultContainer }

    static func address(zone: String) -> URL { URL(string: "\(scheme)://\(container)/\(zone)")! }

    /// A new box's address: a fresh zone nobody has used.
    static func newAddress() -> URL { address(zone: CloudKitLane.zoneName(box: BiselRandom.identifier())) }

    static func zone(of url: URL) -> String? {
        guard url.scheme == scheme, !url.lastPathComponent.isEmpty, url.lastPathComponent != "/" else { return nil }
        return url.lastPathComponent
    }

    /// One lane per zone for the life of the process: CloudKit's change tags, cached by the lane, then survive from one sync to
    /// the next instead of being fetched again.
    private static let cache = LaneCache()

    /// The lane provider the vault is built with: iCloud addresses go to CloudKit, everything else to the Bisel server.
    static let provider: Vault.LaneProvider = { identity, _ in
        guard let url = identity.serverURL, let zone = zone(of: url) else { return nil }
        return cache.lane(zone: zone)
    }

    static func lane(for url: URL) -> CloudKitLane? { zone(of: url).map { cache.lane(zone: $0) } }

    /// The person's iCloud as first run sees it (`BoxSetup`): whether a box can go there, the boxes it holds, the lane at an
    /// address (from the same cache the vault syncs through).
    static let home = ICloudHome(container: container, lane: { cache.lane(zone: $0) })

    static func isAvailable() async -> Bool { await home.availability() == .available }

    /// The boxes this iCloud account holds (their zones), oldest name first: what "I already have one" and a new Mac look for.
    static func existingBoxes() async throws -> [URL] { try await home.boxes() }

    /// Silent pushes for the private database (best effort: without the push entitlement the subscription saves and no push arrives).
    static func subscribe(_ url: URL) async {
        do { try await lane(for: url)?.subscribe() } catch { Log.app.notice("iCloud subscription not saved: \(error.localizedDescription)") }
    }

    private final class LaneCache: @unchecked Sendable {
        private let lock = NSLock()
        private var lanes: [String: CloudKitLane] = [:]
        func lane(zone: String) -> CloudKitLane {
            lock.withLock {
                if let lane = lanes[zone] { return lane }
                let lane = CloudKitLane(zoneName: zone)
                lanes[zone] = lane
                return lane
            }
        }
    }
}
#endif
