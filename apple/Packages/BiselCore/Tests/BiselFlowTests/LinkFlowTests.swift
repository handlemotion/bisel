#if BISEL_SOFTWARE_KEYS
import Foundation
import Testing
import BiselCore
import BiselTestSupport

// The browser sign-in flow (`AccountLinker`) against the real local server. The dashboard is played by
// `TestServer.approveConnect` / `denyConnect` / `expireConnect`, which make the same database updates the dashboard's routes do.

private typealias State = AccountLinker.State

/// Records every state the linker publishes, so a test can both wait for one and look back at the ones that went by.
private final class Watch: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [State] = []
    private var task: Task<Void, Never>?

    init(_ linker: AccountLinker) {
        task = Task { [weak self] in
            for await s in await linker.updates() { self?.lock.withLock { self?.seen.append(s) } }
        }
    }
    deinit { task?.cancel() }

    var history: [State] { lock.withLock { seen } }

    @discardableResult
    func wait(since: Int = 0, timeout: TimeInterval = 60, _ what: String = "state", where match: (State) -> Bool) async throws -> State {
        let end = Date().addingTimeInterval(timeout)
        var from = since
        while Date() < end {
            let all = history
            if let hit = all[from...].first(where: match) { return hit }
            from = all.count
            try await Task.sleep(for: .milliseconds(20))
        }
        throw LinkTestError.timedOut("\(what); saw \(history)")
    }

    func pending(since: Int = 0) async throws -> AccountLinker.Pending {
        let s = try await wait(since: since, "waiting for approval") { if case .waitingForApproval = $0 { return true } else { return false } }
        guard case .waitingForApproval(let p) = s else { throw LinkTestError.timedOut("no pending") }
        return p
    }

    func finished() async throws -> State { try await wait("a finished state") { $0.isFinished } }
}

private enum LinkTestError: Error { case timedOut(String) }

/// The live endpoints, with a switch to drop polls (a network that goes away) or to put another box id in the answer.
private final class FlakyTransport: LinkTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var failing = 0
    private var reportedBox: String?
    private var count = 0

    var polls: Int { lock.withLock { count } }
    func failNextPolls(_ n: Int) { lock.withLock { failing = n } }
    func heal() { lock.withLock { failing = 0 } }
    func reportBox(_ id: String?) { lock.withLock { reportedBox = id } }

    func start(server: URL, deviceName: String) async throws -> SyncClient.ConnectCode {
        try await Vault.startConnect(server: server, deviceName: deviceName)
    }

    func poll(server: URL, deviceCode: String) async throws -> SyncClient.ConnectStatus {
        let (down, lie): (Bool, String?) = lock.withLock {
            count += 1
            if failing > 0 { failing -= 1; return (true, nil) }
            return (false, reportedBox)
        }
        if down { throw SyncError.network("the network went away") }
        let status = try await Vault.pollConnect(server: server, deviceCode: deviceCode)
        if let lie, case .consumed = status { return .consumed(boxID: lie) }
        return status
    }
}

private func fast(hardTimeout: TimeInterval? = nil, failures: Int = 6) -> AccountLinker.Timing {
    var t = AccountLinker.Timing()
    t.intervalOverride = 0.05
    t.maxBackoff = 0.2
    t.maxConsecutiveFailures = failures
    t.hardTimeout = hardTimeout
    return t
}

private func boxCount(_ server: TestServer) throws -> String? { try server.value("SELECT COUNT(*) FROM boxes") }

@Suite("Linking to an account in the browser", .serialized)
struct LinkFlowTests {

    @Test("a new box through the account: Touch ID before the key exists, the phrase comes back once, the box is the account's, a fresh Mac restores it")
    func newBoxThroughAccount() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let linker = AccountLinker(vault: a.vault, server: server.url, timing: fast())
            let watch = Watch(linker)
            #expect(await linker.state == .idle)
            await linker.start(deviceName: "Ada's MacBook")
            await linker.start(deviceName: "ignored while running")

            let pending = try await watch.pending()
            #expect(pending.mode == .newBox)
            #expect(pending.userCode.count == 9)
            #expect(pending.url.absoluteString == "\(server.url.absoluteString)/connect?code=\(pending.userCode)", "built from our server address and the code")
            #expect(pending.expiresAt > Date() && pending.expiresAt < Date().addingTimeInterval(601))
            #expect(!pending.isOffline)
            #expect(try await a.vault.identity() == nil, "nothing is created before the person approves")
            #expect(try server.value("SELECT COUNT(*) FROM connect_requests") == "1")

            try server.approveConnect(userCode: pending.userCode, account: "acct_ada")
            try server.approveConnect(userCode: pending.userCode, account: "acct_mallory")   // a second approval changes nothing

            guard case .linked(let linked) = try await watch.finished() else { Issue.record("expected linked, saw \(watch.history)"); return }
            #expect(linked.mode == .newBox)
            let phrase = try #require(linked.recoveryPhrase)
            #expect(linked.boxID == (try server.onlyBoxID()))
            #expect(try server.value("SELECT owner_id FROM boxes") == "acct_ada", "the first approval won")
            #expect(try boxCount(server) == "1")
            #expect(a.gate.calls.contains { $0.contains("Create your box") }, "Touch ID was asked for")
            #expect(watch.history.contains(.registering(.newBox)))
            #expect(!"\(watch.history)".contains("deviceCode"), "no secret in the states")
            #expect(await linker.cancel() == false, "a finished link cannot be cancelled")

            let item = try await a.vault.save(login("After", password: "p-after"))
            #expect(try await a.vault.sync().pushed >= 1)
            let fresh = try Device("fresh")
            try await fresh.vault.recover(server: server.url, phrase: phrase, deviceName: "fresh", boxID: linked.boxID)
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: item.id) == "p-after")
        }
    }

    @Test("a local box is linked: the box is made from the existing vault, every local item goes up and shows on a second Mac")
    func linkLocalBox() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            let phrase = try await a.vault.bootstrapLocal(deviceName: "Ada's MacBook")
            let one = try await a.vault.save(login("One", password: "p1"))
            let two = try await a.vault.save(login("Two", password: "p2"))
            let before = try await a.vault.pendingChanges()
            #expect(before >= 2)

            let linker = AccountLinker(vault: a.vault, server: server.url, timing: fast())
            let watch = Watch(linker)
            await linker.start(deviceName: "unused: the vault knows its name")
            let pending = try await watch.pending()
            #expect(pending.mode == .linkLocalBox)
            #expect(try await a.vault.identity()?.serverURL == nil, "still local while waiting")

            try server.approveConnect(userCode: pending.userCode, account: "acct_ada")
            guard case .linked(let linked) = try await watch.finished() else { Issue.record("expected linked, saw \(watch.history)"); return }
            #expect(linked.mode == .linkLocalBox)
            #expect(linked.recoveryPhrase == nil, "the phrase is the one already written down")
            #expect(linked.itemsUploaded == before && linked.itemsStillPending == 0)
            #expect(watch.history.contains(.uploading(pending: before)))
            #expect(try server.value("SELECT owner_id FROM boxes") == "acct_ada")
            #expect(try await a.vault.identity()?.boxID == (try server.onlyBoxID()))
            #expect(try await a.vault.pendingChanges() == 0)
            #expect(a.gate.calls.contains { $0.contains("Connect") })

            let fresh = try Device("fresh")
            try await fresh.vault.recover(server: server.url, phrase: phrase, deviceName: "fresh", boxID: linked.boxID)
            try await fresh.vault.sync()
            #expect(try await fresh.vault.revealPassword(id: one.id) == "p1")
            #expect(try await fresh.vault.revealPassword(id: two.id) == "p2")
            #expect(try await fresh.vault.items().items.count == 2)
        }
    }

    @Test("an expired code, a hard timeout, a denial, an account that already has a box: each ends the wait with its own reason and creates nothing")
    func refusals() async throws {
        try await TestServer.with { server in
            // The code runs out on the server.
            let a = try Device("a")
            _ = try await a.vault.bootstrapLocal(deviceName: "a")
            let expiring = AccountLinker(vault: a.vault, server: server.url, timing: fast())
            let w1 = Watch(expiring)
            await expiring.start(deviceName: "a")
            try server.expireConnect(userCode: try await w1.pending().userCode)
            #expect(try await w1.finished() == .failed(.expired))
            #expect(!AccountLinker.Failure.expired.isRetryable)

            // After a failure the same linker starts over with a new code.
            let expiredCode = try await w1.pending().userCode
            await expiring.start(deviceName: "a")
            try await w1.wait("a new code", where: { if case .waitingForApproval(let p) = $0 { return p.userCode != expiredCode } else { return false } })
            await expiring.cancel()

            // Nobody answers and no code expires on the server: the app's own deadline ends it.
            let b = try Device("b")
            let patient = AccountLinker(vault: b.vault, server: server.url, timing: fast(hardTimeout: 0.4))
            let w2 = Watch(patient)
            await patient.start(deviceName: "b")
            #expect(try await w2.finished() == .failed(.timedOut))

            // The person says no.
            let c = try Device("c")
            _ = try await c.vault.bootstrapLocal(deviceName: "c")
            let denied = AccountLinker(vault: c.vault, server: server.url, timing: fast())
            let w3 = Watch(denied)
            await denied.start(deviceName: "c")
            try server.denyConnect(userCode: try await w3.pending().userCode, account: "acct_eve")
            #expect(try await w3.finished() == .failed(.denied))
            #expect(try await c.vault.identity()?.serverURL == nil)

            #expect(try boxCount(server) == "0", "nothing was created by any of that")

            // Ada links one Mac; her second Mac is told the account already has a box, and Touch ID is not asked for.
            let d = try Device("d")
            _ = try await d.vault.bootstrapLocal(deviceName: "d")
            let first = AccountLinker(vault: d.vault, server: server.url, timing: fast())
            let w4 = Watch(first)
            await first.start(deviceName: "d")
            try server.approveConnect(userCode: try await w4.pending().userCode, account: "acct_ada")
            guard case .linked = try await w4.finished() else { Issue.record("expected linked, saw \(w4.history)"); return }

            let e = try Device("e")
            _ = try await e.vault.bootstrapLocal(deviceName: "e")
            let asked = e.gate.calls.count
            let again = AccountLinker(vault: e.vault, server: server.url, timing: fast())
            let w5 = Watch(again)
            await again.start(deviceName: "e")
            try server.approveConnect(userCode: try await w5.pending().userCode, account: "acct_ada")
            #expect(try await w5.finished() == .failed(.accountHasBox))
            #expect(e.gate.calls.count == asked)
            #expect(try await e.vault.identity()?.serverURL == nil)
            #expect(try boxCount(server) == "1")
        }
    }

    @Test("cancelling stops the wait, a later approval does nothing, and a cancelled flow can start again")
    func cancelled() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            _ = try await a.vault.bootstrapLocal(deviceName: "a")
            let linker = AccountLinker(vault: a.vault, server: server.url, timing: fast())
            let watch = Watch(linker)
            #expect(await linker.cancel() == false, "nothing to cancel yet")

            await linker.start(deviceName: "a")
            let first = try await watch.pending()
            #expect(await linker.cancel() == true)
            #expect(await linker.state == .cancelled)

            try server.approveConnect(userCode: first.userCode, account: "acct_ada")
            try await Task.sleep(for: .milliseconds(400))
            #expect(await linker.state == .cancelled, "an approval that arrives late is not redeemed")
            #expect(try boxCount(server) == "0")
            #expect(try await a.vault.identity()?.serverURL == nil)

            await linker.start(deviceName: "a")
            let second = try await watch.wait("a second code") { if case .waitingForApproval(let p) = $0 { return p.userCode != first.userCode } else { return false } }
            guard case .waitingForApproval(let p) = second else { return }
            try server.approveConnect(userCode: p.userCode, account: "acct_ada")
            guard case .linked = try await watch.wait("linked", where: { if case .linked = $0 { return true } else { return false } }) else { Issue.record("expected linked, saw \(watch.history)"); return }
            #expect(try boxCount(server) == "1")

            // Cancelling while waiting also works for a brand-new box, and leaves no identity behind.
            let b = try Device("b")
            let fresh = AccountLinker(vault: b.vault, server: server.url, timing: fast())
            let wb = Watch(fresh)
            await fresh.start(deviceName: "b")
            _ = try await wb.pending()
            #expect(await fresh.cancel())
            #expect(try await b.vault.identity() == nil)
            #expect(try b.keyStore.publicKeys() == nil, "no device key was made")
        }
    }

    @Test("a network that goes away mid-poll backs off and carries on; one that stays away ends in a retryable failure that resumes the same code")
    func networkFailureAndResume() async throws {
        try await TestServer.with { server in
            let a = try Device("a")
            _ = try await a.vault.bootstrapLocal(deviceName: "a")
            let flaky = FlakyTransport()
            let linker = AccountLinker(vault: a.vault, server: server.url, transport: flaky, timing: fast(failures: 4))
            let watch = Watch(linker)
            await linker.start(deviceName: "a")
            let pending = try await watch.pending()

            // A short outage: the screen is told, nothing is lost.
            let mark = watch.history.count
            flaky.failNextPolls(2)
            try await watch.wait(since: mark, "offline") { if case .waitingForApproval(let p) = $0 { return p.isOffline } else { return false } }
            let offlineAt = try #require(watch.history[mark...].firstIndex { if case .waitingForApproval(let p) = $0 { return p.isOffline } else { return false } })
            try await watch.wait(since: offlineAt + 1, "back online") { if case .waitingForApproval(let p) = $0 { return !p.isOffline && p.userCode == pending.userCode } else { return false } }

            // A long one: after four failures in a row the wait stops, keeping the code.
            flaky.failNextPolls(100)
            #expect(try await watch.finished() == .failed(.network))
            #expect(AccountLinker.Failure.network.isRetryable)
            #expect(try boxCount(server) == "0")

            // Approved while the app could not hear: resuming picks it up with the very same code.
            try server.approveConnect(userCode: pending.userCode, account: "acct_ada")
            flaky.heal()
            await linker.retry()
            guard case .linked(let linked) = try await watch.wait("linked", where: { if case .linked = $0 { return true } else { return false } }) else { return }
            #expect(linked.mode == .linkLocalBox)
            #expect(try server.value("SELECT COUNT(*) FROM connect_requests") == "1", "no second request was made")
            #expect(try boxCount(server) == "1")
        }
    }

    @Test("Touch ID refused: nothing is registered, the approval is kept, and retry asks again")
    func biometryRefused() async throws {
        try await TestServer.with { server in
            // A local box.
            let a = try Device("a")
            _ = try await a.vault.bootstrapLocal(deviceName: "a")
            _ = try await a.vault.save(login("Kept", password: "pk"))
            let linker = AccountLinker(vault: a.vault, server: server.url, timing: fast())
            let wa = Watch(linker)
            await linker.start(deviceName: "a")
            let pa = try await wa.pending()
            a.gate.deny(true)
            try server.approveConnect(userCode: pa.userCode, account: "acct_ada")
            #expect(try await wa.finished() == .failed(.biometryRefused))
            #expect(AccountLinker.Failure.biometryRefused.isRetryable)
            #expect(try boxCount(server) == "0", "the server was never asked to make the box")
            #expect(try await a.vault.identity()?.serverURL == nil)
            a.gate.deny(false)
            await linker.retry()
            guard case .linked(let linked) = try await wa.wait("linked", where: { if case .linked = $0 { return true } else { return false } }) else { return }
            #expect(linked.itemsStillPending == 0 && linked.itemsUploaded >= 1)

            // A new box: refused before any key exists.
            let b = try Device("b")
            let fresh = AccountLinker(vault: b.vault, server: server.url, timing: fast())
            let wb = Watch(fresh)
            b.gate.deny(true)
            await fresh.start(deviceName: "b")
            let pb = try await wb.pending()
            try server.approveConnect(userCode: pb.userCode, account: "acct_bob")
            #expect(try await wb.finished() == .failed(.biometryRefused))
            #expect(try await b.vault.identity() == nil)
            #expect(try b.keyStore.publicKeys() == nil, "refusing Touch ID leaves no device key")
            #expect(try boxCount(server) == "1")
            b.gate.deny(false)
            await fresh.retry()
            guard case .linked(let second) = try await wb.wait("linked", where: { if case .linked = $0 { return true } else { return false } }) else { return }
            #expect(second.recoveryPhrase != nil)
            #expect(try server.value("SELECT owner_id FROM boxes WHERE owner_id = 'acct_bob'") == "acct_bob")
        }
    }

    @Test("an existing server box is claimed by the account; a server naming another box is refused; an already linked box says so")
    func claimServerBox() async throws {
        try await TestServer.with { server in
            // A box that was made with the operator's token and has no owner yet.
            let a = try Device("a")
            try await a.bootstrap(server)
            let box = try #require(try await a.vault.identity()?.boxID)
            try await a.vault.unlock()
            #expect(try server.value("SELECT owner_id FROM boxes") == nil)

            // The server names another box than the one this vault has: nothing is written, and it says so.
            let lying = FlakyTransport()
            lying.reportBox("someone_elses_box_0000")
            let suspicious = AccountLinker(vault: a.vault, server: server.url, transport: lying, timing: fast())
            let ws = Watch(suspicious)
            await suspicious.start(deviceName: "a")
            let ps = try await ws.pending()
            #expect(ps.mode == .claimServerBox)
            try server.approveConnect(userCode: ps.userCode, account: "acct_ada")
            #expect(try await ws.finished() == .failed(.boxMismatch))
            #expect(try await a.vault.identity()?.boxID == box, "the stored box id is not overwritten")

            // The same box, claimed again by an honest run: it is already the account's, so the server refuses a second claim.
            let linker = AccountLinker(vault: a.vault, server: server.url, timing: fast())
            let wl = Watch(linker)
            await linker.start(deviceName: "a")
            #expect(try await wl.finished() == .failed(.alreadyLinked))
            #expect(try server.value("SELECT owner_id FROM boxes") == "acct_ada")

            // A second unowned box, claimed by a new account.
            let b = try Device("b")
            try await b.bootstrap(server)
            try await b.vault.unlock()
            let linkerB = AccountLinker(vault: b.vault, server: server.url, timing: fast())
            let wb = Watch(linkerB)
            await linkerB.start(deviceName: "b")
            let pb = try await wb.pending()
            try server.approveConnect(userCode: pb.userCode, account: "acct_bob")
            guard case .linked(let linked) = try await wb.finished() else { Issue.record("expected linked, saw \(wb.history)"); return }
            #expect(linked.mode == .claimServerBox && linked.recoveryPhrase == nil)
            #expect(linked.boxID == (try await b.vault.identity()?.boxID))
            #expect(try server.value("SELECT COUNT(*) FROM boxes WHERE owner_id = 'acct_bob'") == "1")
            _ = try await b.vault.sync()
        }
    }
}
#endif
