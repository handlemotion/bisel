#if BISEL_LANE_CONTRACT
import AppKit
import CloudKit
import os
import BiselCloudKit
import BiselCore
import BiselLaneContract

/// Opt-in, only in the signed Debug app built from project.contract.yml (docs/SYNC-LANES.md §10, L3): runs the lane contract
/// flows against real CloudKit (Development environment) and quits. Never opens the person's box: it takes over before any
/// SwiftUI scene, `AppModel` or `VaultService` exists, every device is a throwaway store with software keys in a temp
/// directory, and every zone it makes (`bisel-l3-spike-*`) is deleted at the end.
///   BISEL_DEV_LANE_CONTRACT=cloudkit  BISEL_DEV_LANE_CONTRACT_LOG=<file>  BISEL_DEV_LANE_CONTRACT_ONLY=<part of a flow name>
@MainActor
enum LaneContractRun {
    nonisolated static let zonePrefix = "bisel-l3-spike"
    private static var delegate: Delegate?

    static func runIfRequested() {
        let env = ProcessInfo.processInfo.environment
        guard env["BISEL_DEV_LANE_CONTRACT"] == "cloudkit" else { return }
        let app = NSApplication.shared
        let d = Delegate(logPath: env["BISEL_DEV_LANE_CONTRACT_LOG"], only: env["BISEL_DEV_LANE_CONTRACT_ONLY"].flatMap { $0.isEmpty ? nil : $0 })
        delegate = d
        app.delegate = d
        app.setActivationPolicy(.accessory)
        app.run()   // never returns: the run ends in exit()
    }

    final class Delegate: NSObject, NSApplicationDelegate {
        let out: Output
        let only: String?
        let pushes = Counter()

        init(logPath: String?, only: String?) { out = Output(path: logPath); self.only = only }

        func applicationDidFinishLaunching(_ notification: Notification) {
            out.line("lane contract on CloudKit: pid \(ProcessInfo.processInfo.processIdentifier)")
            NSApp.registerForRemoteNotifications()
            Task { @MainActor in
                // Whatever happens, the process ends.
                let out = out, pushes = pushes
                Task.detached { try? await Task.sleep(for: .seconds(1500)); out.line("RESULT: TIMED OUT"); exit(3) }
                let failures = await Runner(out: out, only: only, pushes: { pushes.value }).run()
                out.line(failures == 0 ? "RESULT: ALL PASSED" : "RESULT: \(failures) FAILED")
                exit(failures == 0 ? 0 : 1)
            }
        }

        func application(_ application: NSApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
            out.line("push: registered for remote notifications (token \(deviceToken.count) bytes)")
        }

        func application(_ application: NSApplication, didFailToRegisterForRemoteNotificationsWithError error: any Error) {
            out.line("push: registration failed: \(String(reflecting: error))")
        }

        func application(_ application: NSApplication, didReceiveRemoteNotification userInfo: [String: Any]) {
            let ours = CloudKitLane.handleRemoteNotification(userInfo)
            pushes.add()
            out.line("push: received a remote notification (ours: \(ours))")
        }
    }

    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        var value: Int { lock.withLock { n } }
        func add() { lock.withLock { n += 1 } }
    }

    /// Stdout, the log file and one unified-log line per message (test data only, nothing from a real box).
    final class Output: @unchecked Sendable {
        private let lock = NSLock()
        private let path: String?
        private var text = ""
        private let logger = Logger(subsystem: "app.bisel.mac", category: "lane-contract")
        private let start = Date()
        init(path: String?) { self.path = path }
        func line(_ s: String) {
            let stamped = String(format: "[%7.1fs] ", Date().timeIntervalSince(start)) + s
            print(stamped)
            fflush(stdout)
            logger.notice("\(stamped, privacy: .public)")
            lock.withLock {
                text += stamped + "\n"
                if let path { try? text.write(toFile: path, atomically: true, encoding: .utf8) }
            }
        }
    }

    struct Runner {
        let out: Output
        let only: String?
        let pushes: @Sendable () -> Int

        func run() async -> Int {
            var failures = 0
            let probe = CloudKitLane(zoneName: "\(zonePrefix)-probe")
            do {
                let status = try await probe.container.accountStatus()
                out.line("account status: \(status.rawValue) (\(status == .available ? "available" : "NOT available"))")
                let identity = try await probe.identity()
                out.line("lane identity (hashed user record): \(identity.rawValue.prefix(12))…")
                try await probe.subscribe()
                out.line("subscription \(CloudKitLane.subscriptionID): saved")
            } catch {
                out.line("FAIL  account / subscription: \(String(reflecting: error))")
                failures += 1
            }
            let signals = Task { var n = 0; for await _ in probe.changes() { n += 1 }; return n }

            failures += await laneProbe(probe)

            for (i, flow) in LaneContract.flows.enumerated() where only.map({ flow.name.contains($0) }) ?? true {
                let zone = "\(zonePrefix)-\(i + 1)-\(UUID().uuidString.prefix(6).lowercased())"
                out.line("flow \(i + 1): \(flow.name) [zone \(zone)]")
                let started = Date()
                let found = await LaneContract.run(flow, on: .storage { Self.storage(zone: zone) })
                let took = String(format: "%.1fs", Date().timeIntervalSince(started))
                if found.isEmpty { out.line("PASS  flow \(i + 1) (\(took))") }
                for f in found { out.line("FAIL  flow \(i + 1): \(f)") }
                if !found.isEmpty { failures += 1 }
            }

            // Pushes are best effort and throttled; give a late one a moment before counting.
            try? await Task.sleep(for: .seconds(10))
            signals.cancel()
            out.line("push: \(pushes()) remote notification(s) received during the run")

            failures += await sweep(probe)
            return failures
        }

        static func storage(zone: String) -> StorageUnderTest {
            let lane = CloudKitLane(zoneName: zone)
            return StorageUnderTest(name: zone, lane: lane, lose: { id in
                let record = CKRecord.ID(recordName: CloudKitLane.recordName(id), zoneID: lane.zoneID)
                _ = try await lane.container.privateCloudDatabase.modifyRecords(saving: [], deleting: [record])
            }, close: { try await lane.erase(confirmed: LaneEraseToken()) })
        }

        /// The lane's own CloudKit behaviour, below the box: change tokens, compare-and-set on the change tag, atomic commit,
        /// reported hard deletes.
        private func laneProbe(_ lane: CloudKitLane) async -> Int {
            var failures = 0
            func check(_ ok: Bool, _ what: String) { out.line((ok ? "PASS  " : "FAIL  ") + "probe: " + what); if !ok { failures += 1 } }
            func accepted(_ r: LaneWriteResult) -> LaneRecord? { if case .accepted(let x) = r { return x } else { return nil } }
            func conflict(_ r: LaneWriteResult) -> LaneRecord?? { if case .conflict(let x) = r { return .some(x) } else { return nil } }
            do {
                try await lane.prepare()
                let empty = try await lane.fetch(since: nil, limit: 50)
                check(empty.upserts.isEmpty, "a new zone fetches empty")
                let id = "_" + UUID().uuidString   // ids may start with an underscore, which CloudKit record names may not
                let first = LaneRecord(kind: .item, id: id, rev: 1, epoch: 1, blob: Data(repeating: 1, count: 600), writer: "probe")
                let made = accepted(try await lane.write([LaneWrite(record: first, expect: .absent)])[0])
                check(made?.tag != nil && made?.id == id, "a new record is accepted with a change tag")
                let again = try await lane.write([LaneWrite(record: first, expect: .absent)])[0]
                check(conflict(again)??.id == id, "writing 'absent' over an existing record is a conflict carrying the server copy")
                var second = first; second.rev = 2; second.blob = Data(repeating: 2, count: 600)
                let moved = accepted(try await lane.write([LaneWrite(record: second, expect: .tag(made?.tag ?? LaneTag("?")))])[0])
                check(moved != nil && moved?.tag != made?.tag && (moved?.order ?? 0) >= (made?.order ?? 0), "a write on the expected tag moves the tag on")
                let stale = try await lane.write([LaneWrite(record: first, expect: .tag(made?.tag ?? LaneTag("?")))])[0]
                check(conflict(stale)??.rev == 2, "a write on a stale tag is a conflict with the newer server copy")

                // A second lane (another device) still caches the old change tag: CloudKit itself refuses its save.
                let peer = CloudKitLane(zoneName: lane.zoneID.zoneName)
                _ = try await peer.read([LaneRecordRef(kind: .item, id: id)])
                var third = second; third.rev = 3
                let movedAgain = accepted(try await lane.write([LaneWrite(record: third, expect: .tag(moved?.tag ?? LaneTag("?")))])[0])
                var fourth = second; fourth.rev = 4
                let raced = try await peer.write([LaneWrite(record: fourth, expect: .tag(moved?.tag ?? LaneTag("?")))])[0]
                check(movedAgain != nil && conflict(raced)??.rev == 3, "CloudKit refuses a save on a change tag another device moved on (serverRecordChanged)")

                var fifth = second; fifth.rev = 5
                let latest = accepted(try await lane.write([LaneWrite(record: fifth, expect: .tag(movedAgain?.tag ?? LaneTag("?")))])[0])
                let other = LaneRecord(kind: .item, id: "probe-other", rev: 1, epoch: 1, blob: Data(repeating: 3, count: 100))
                let atomic = try await peer.commit([LaneWrite(record: other, expect: .absent), LaneWrite(record: fourth, expect: .tag(movedAgain?.tag ?? LaneTag("?")))])
                let otherNow = try await lane.read([LaneRecordRef(kind: .item, id: "probe-other")])
                check(latest != nil && atomic.allSatisfy { accepted($0) == nil } && otherNow == [nil],
                      "an atomic commit that CloudKit refuses for one record saves none (\(atomic))")

                let page = try await lane.fetch(since: nil, limit: 50)
                check(page.upserts.map(\.id) == [id] && page.upserts.first?.rev == 5, "fetch from the start returns the record once, newest revision")
                let quiet = try await lane.fetch(since: page.cursor, limit: 50)
                check(quiet.upserts.isEmpty && quiet.removed.isEmpty, "fetch from the returned token sees nothing new")

                _ = try await lane.container.privateCloudDatabase.modifyRecords(saving: [], deleting: [CKRecord.ID(recordName: CloudKitLane.recordName(id), zoneID: lane.zoneID)])
                let gone = try await lane.fetch(since: page.cursor, limit: 50)
                check(gone.removed == [LaneRecordRef(kind: .item, id: id)], "a hard delete comes back as a removed record (\(gone.removed))")
                let paged = try await (1...5).asyncMap { n in
                    accepted(try await lane.write([LaneWrite(record: LaneRecord(kind: .item, id: "page-\(n)", rev: 1, epoch: 1, blob: Data([UInt8(n)])), expect: .absent)])[0])
                }
                var seen: [String] = []
                var cursor = gone.cursor as LaneCursor?
                var pages = 0
                while true {
                    let p = try await lane.fetch(since: cursor, limit: 2)
                    seen += p.upserts.map(\.id); cursor = p.cursor; pages += 1
                    if !p.hasMore || pages > 10 { break }
                }
                check(paged.allSatisfy { $0 != nil } && Set(seen) == Set((1...5).map { "page-\($0)" }) && pages >= 3,
                      "a limit of 2 pages through 5 records (\(pages) pages)")
                try await lane.erase(confirmed: LaneEraseToken())
                do { _ = try await lane.fetch(since: nil, limit: 1); check(false, "a deleted zone must not fetch") }
                catch LaneError.storeMissing { check(true, "a deleted zone fetches as storeMissing") }
            } catch {
                check(false, "unexpected error: \(String(reflecting: error))")
            }
            return failures
        }

        /// Deletes every zone this run (or an earlier one) made and lists what is left.
        private func sweep(_ lane: CloudKitLane) async -> Int {
            let db = lane.container.privateCloudDatabase
            do {
                let ours = try await db.allRecordZones().filter { $0.zoneID.zoneName.hasPrefix(zonePrefix) }.map(\.zoneID)
                if !ours.isEmpty { _ = try await db.modifyRecordZones(saving: [], deleting: ours) }
                let left = try await db.allRecordZones().map(\.zoneID.zoneName)
                out.line("zones: deleted \(ours.count) leftover; the private database now holds \(left)")
                return left.contains { $0.hasPrefix(zonePrefix) } ? 1 : 0
            } catch {
                out.line("FAIL  zone sweep: \(String(reflecting: error))")
                return 1
            }
        }
    }
}

private extension ClosedRange where Bound == Int {
    func asyncMap<T>(_ transform: (Int) async throws -> T) async rethrows -> [T] {
        var out: [T] = []
        for n in self { out.append(try await transform(n)) }
        return out
    }
}
#endif
