#if BISEL_SOFTWARE_KEYS
import Testing
import Foundation
import SQLite3
import CryptoKit
import BiselCore
import BiselTestSupport

// The lane contract (docs/SYNC-LANES.md §10): the flows that must behave the same whichever lane carries the box. Each runs
// against the in-memory `FakeLane` and against the real server (`wrangler dev`, local D1). A lane that passes is a lane the
// engine can trust the way it trusts the server today. Lane-specific behaviour (server endpoints, accounts, device codes) is
// covered by the other flow files.

enum LaneUnderTest: String, CaseIterable, Sendable, CustomTestStringConvertible {
    case fake, server
    var testDescription: String { rawValue }
}

/// One box on one lane, plus what a hostile or failing store can do to it.
final class Rig: @unchecked Sendable {
    let server: TestServer?
    let fake: FakeLane?
    var address: URL { server?.url ?? URL(string: "fake-lane://box")! }

    init(server: TestServer?, fake: FakeLane?) { self.server = server; self.fake = fake }

    static func with<T>(_ lane: LaneUnderTest, _ body: (Rig) async throws -> T) async throws -> T {
        switch lane {
        case .fake: return try await body(Rig(server: nil, fake: FakeLane()))
        case .server: return try await TestServer.with { try await body(Rig(server: $0, fake: nil)) }
        }
    }

    func device(_ name: String) throws -> Device {
        guard let fake else { return try Device(name) }
        return try Device(name, laneProvider: { identity, _ in fake.endpoint(deviceID: identity.deviceID) })
    }

    func bootstrap(_ d: Device) async throws -> RecoveryPhrase {
        if let server { return try await d.bootstrap(server) }
        return try await d.vault.bootstrap(lane: address, deviceName: d.name)
    }

    func enroll(_ d: Device, through approver: Device) async throws { try await d.enroll(through: approver, address: address) }

    func recover(_ d: Device, phrase: RecoveryPhrase) async throws {
        if let server { try await d.vault.recover(server: server.url, phrase: phrase, deviceName: d.name, boxID: try server.onlyBoxID()) }
        else if let fake { try await d.vault.recover(lane: fake.endpoint(deviceID: nil), address: address, phrase: phrase, deviceName: d.name) }
    }

    /// Everything the lane holds, as `d` sees it.
    func records(as d: Device) async throws -> [StoredRecord] {
        if let fake {
            return fake.records().map { StoredRecord(id: $0.id, rev: $0.rev, seq: $0.order, deleted: $0.kind == .tombstone, blob: $0.blob, updatedAt: $0.updatedAt) }
        }
        let id = try #require(try await d.vault.identity()?.deviceID)
        return try await d.signedClientFactory(address, id).pull(since: 0).records
    }

    /// The lane forgets its newest write (a restore from a slightly older point).
    func loseNewestWrite() throws {
        if let fake { fake.loseNewestWrite(); return }
        let server = try #require(server)
        let id = try #require(try server.value("SELECT id FROM items ORDER BY seq DESC LIMIT 1"))
        try server.sql("DELETE FROM items WHERE id = '\(id)'")
        try server.sql("UPDATE boxes SET head_seq = head_seq - 1")
    }

    /// Someone without the vault key deletes `id`: whatever they write as the marker, it cannot be a sealed one.
    func forgeDelete(_ id: String, as d: Device) async throws {
        if let fake { fake.forgeDelete(id: id); return }
        let deviceID = try #require(try await d.vault.identity()?.deviceID)
        let client = d.signedClientFactory(address, deviceID)
        let rev = try #require(try await client.pull(since: 0).records.first { $0.id == id }).rev
        guard case .accepted = try await client.delete(id: id, baseRev: rev, marker: Data(repeating: 1, count: 32), epoch: 1) else {
            Issue.record("the forged delete was refused"); return
        }
    }
}

@Suite("Lane contract: the same flows on every lane", .serialized)
struct LaneContractTests {
    @Test("two devices converge on edits and deletes, and the lane only ever holds ciphertext", arguments: LaneUnderTest.allCases)
    func twoDevicesConverge(_ lane: LaneUnderTest) async throws {
        try await Rig.with(lane) { rig in
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            #expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw")
            var edit = try await b.vault.item(id: bank.id); edit.password = "bank-pw-2"
            _ = try await b.vault.save(edit)
            let mail = try await b.vault.save(login("Mail", password: "mail-pw"))
            try await b.vault.sync()
            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: bank.id) == "bank-pw-2")
            #expect(try await a.vault.revealPassword(id: mail.id) == "mail-pw")

            try await a.vault.delete(id: mail.id)
            try await a.vault.sync()
            try await b.vault.sync()
            #expect(try await b.vault.items().items.map(\.title) == ["Bank"])

            let held = try await rig.records(as: a)
            #expect(!held.contains { $0.blob.range(of: Data("bank-pw".utf8)) != nil })
            #expect(try await a.vault.pendingChanges() == 0)
            #expect(try await b.vault.pendingChanges() == 0)
        }
    }

    @Test("concurrent edits keep the remote version and save the local edit as a '(conflict)' copy", arguments: LaneUnderTest.allCases)
    func conflictKeepsRemoteAndACopy(_ lane: LaneUnderTest) async throws {
        try await Rig.with(lane) { rig in
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            let item = try await a.vault.save(login("Router", user: "admin", password: "orig"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            var editA = try await a.vault.item(id: item.id); editA.password = "from-A"
            var editB = try await b.vault.item(id: item.id); editB.password = "from-B"
            _ = try await a.vault.save(editA)
            _ = try await b.vault.save(editB)

            #expect(try await a.vault.sync().conflicts.isEmpty)
            let conflict = try #require(try await b.vault.sync().conflicts.first)
            #expect(try await b.vault.revealPassword(id: item.id) == "from-A")
            #expect(try await b.vault.item(id: conflict.copyID).title == "Router (conflict)")
            #expect(try await b.vault.revealPassword(id: conflict.copyID) == "from-B")
            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: conflict.copyID) == "from-B")
        }
    }

    @Test("a forged delete is undone and a lane that lost state is noticed and healed from the replica", arguments: LaneUnderTest.allCases)
    func forgedAndRolledBackStateIsDetectedAndHealed(_ lane: LaneUnderTest) async throws {
        try await Rig.with(lane) { rig in
            let a = try rig.device("a"), b = try rig.device("b")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.save(login("Mail", password: "mail-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            // A delete nobody sealed with the vault key is not honoured.
            try await rig.forgeDelete(bank.id, as: a)
            let report = try await b.vault.sync()
            #expect(report.rejectedTombstones == [bank.id])
            #expect(try await b.vault.revealPassword(id: bank.id) == "bank-pw")
            try await b.vault.sync()
            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: bank.id) == "bank-pw")

            // The lane forgets its newest write: refused as a rollback, healed after the owner has looked.
            let newest = try await b.vault.save(login("Newest", password: "newest-pw"))
            try await b.vault.sync()
            try rig.loseNewestWrite()
            do { _ = try await b.vault.sync(); Issue.record("a rolled-back lane must be refused") }
            catch IntegrityError.serverRolledBack {}
            try await b.vault.acknowledgeServerReset()
            #expect(try await b.vault.sync().pushed >= 1)
            #expect(try await b.vault.pendingChanges() == 0)

            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: newest.id) == "newest-pw")
        }
    }

    @Test("revoking a device rotates the key: the revoked device's key opens nothing the lane holds, the others carry on", arguments: LaneUnderTest.allCases)
    func rotationAndRevoke(_ lane: LaneUnderTest) async throws {
        try await Rig.with(lane) { rig in
            let a = try rig.device("a"), b = try rig.device("b"), c = try rig.device("c")
            let phrase = try await rig.bootstrap(a)
            let bank = try await a.vault.save(login("Bank", password: "bank-pw"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)
            try await rig.enroll(c, through: a)

            let bIdentity = try #require(try await b.vault.identity())
            let oldVK = try await b.keyStore.openEnvelope(try #require(bIdentity.envelope), reason: "test")
            func opens(_ r: StoredRecord) -> Bool {
                (try? ItemSealer.open(blob: r.blob, id: r.id, rev: r.rev, vaultKey: SymmetricKey(data: oldVK))) != nil
            }
            let before = try await rig.records(as: a).filter { !$0.deleted }
            #expect(before.allSatisfy(opens), "sanity: the old key opens the lane's ciphertext before the revoke")

            try await a.vault.revoke(deviceID: bIdentity.deviceID)
            #expect(try await a.vault.devices().first { $0.id == bIdentity.deviceID }?.isRevoked == true)
            let after = try await rig.records(as: a).filter { !$0.deleted }
            #expect(after.count == before.count)
            #expect(after.allSatisfy { !opens($0) }, "everything the lane holds is closed to the revoked device's key")

            let report = try await c.vault.sync()
            #expect(report.rotationAdopted)
            try await c.vault.unlock()
            #expect(try await c.vault.revealPassword(id: bank.id) == "bank-pw")
            var edit = try await c.vault.item(id: bank.id); edit.password = "after-rotation"
            _ = try await c.vault.save(edit)
            try await c.vault.sync()
            try await a.vault.sync()
            #expect(try await a.vault.revealPassword(id: bank.id) == "after-rotation")

            // The same 24 words still recover the box after the rotation.
            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: bank.id) == "after-rotation")
        }
    }

    @Test("the 24 words rebuild a box on a fresh device; a stranger's words and a rotated-away phrase do not", arguments: LaneUnderTest.allCases)
    func recoveryFromPhrase(_ lane: LaneUnderTest) async throws {
        try await Rig.with(lane) { rig in
            let a = try rig.device("a")
            let phrase = try await rig.bootstrap(a)
            let item = try await a.vault.save(login("Passport", password: "p-recover"))
            try await a.vault.sync()

            let fresh = try rig.device("fresh")
            try await rig.recover(fresh, phrase: phrase)
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: item.id) == "p-recover")
            #expect(try await a.vault.devices().count == 2)

            let stranger = try rig.device("stranger")
            await #expect(throws: (any Error).self) { try await rig.recover(stranger, phrase: try RecoveryPhrase.generate()) }

            let newPhrase = try await fresh.vault.rotateRecovery()
            let old = try rig.device("old")
            await #expect(throws: (any Error).self) { try await rig.recover(old, phrase: phrase) }
            let again = try rig.device("again")
            try await rig.recover(again, phrase: newPhrase)
            try await again.vault.sync()
            #expect(try await again.vault.revealPassword(id: item.id) == "p-recover")
        }
    }

    @Test("a box synced before lanes existed, with edits still pending, keeps its queue and its position through the migration", arguments: LaneUnderTest.allCases)
    func existingPendingQueueSurvivesTheMigration(_ lane: LaneUnderTest) async throws {
        try await Rig.with(lane) { rig in
            let a = try rig.device("a"), b = try rig.device("b")
            _ = try await rig.bootstrap(a)
            var synced = try await a.vault.save(login("Synced", password: "s1"))
            try await a.vault.sync()
            try await rig.enroll(b, through: a)

            // Offline edits on top of a confirmed revision, and a brand-new item.
            synced.password = "s2"
            _ = try await a.vault.save(synced)
            let created = try await a.vault.save(login("Created offline", password: "c1"))
            #expect(try await a.vault.pendingChanges() == 2)

            try downgradeToBeforeLanes(a.location)
            let reopened = try a.relaunched()
            try await reopened.unlock()
            let report = try await reopened.sync()
            #expect(report.pushed == 2 && report.conflicts.isEmpty, "the pending queue goes up as it was: no re-download, no '(conflict)' copies")
            #expect(try await reopened.pendingChanges() == 0)

            try await b.vault.sync()
            #expect(try await b.vault.revealPassword(id: synced.id) == "s2")
            #expect(try await b.vault.revealPassword(id: created.id) == "c1")
        }
    }

    /// Rewrites the device's database as the app before lanes left it: the sync position in `meta`, no lane tables, the
    /// lane migration not yet applied.
    private func downgradeToBeforeLanes(_ location: StoreLocation) throws {
        var db: OpaquePointer?
        guard sqlite3_open(location.databaseURL.path, &db) == SQLITE_OK else { throw TestServer.Failure.didNotStart("cannot open the database") }
        defer { sqlite3_close(db) }
        let sql = """
            INSERT OR REPLACE INTO meta(key, value) SELECT 'cursor', CAST(cursor AS BLOB) FROM lane_state LIMIT 1;
            INSERT OR REPLACE INTO meta(key, value) SELECT 'head_seq', CAST(known_head AS BLOB) FROM lane_state LIMIT 1;
            INSERT OR REPLACE INTO meta(key, value) SELECT 'event_cursor', CAST(event_cursor AS BLOB) FROM lane_state LIMIT 1;
            DROP TABLE lane_ack;
            DROP TABLE lane_state;
            DELETE FROM grdb_migrations WHERE identifier = 'v3-lanes';
            """
        var message: UnsafeMutablePointer<CChar>?
        guard sqlite3_exec(db, sql, nil, nil, &message) == SQLITE_OK else {
            throw TestServer.Failure.didNotStart("downgrade failed: \(message.map { String(cString: $0) } ?? "?")")
        }
    }
}
#endif
