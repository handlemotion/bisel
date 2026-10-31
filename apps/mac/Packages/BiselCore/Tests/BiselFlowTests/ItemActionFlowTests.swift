#if BISEL_SOFTWARE_KEYS
import Foundation
import Testing
import BiselCore
import BiselTestSupport
import BiselLaneContract

// The panel's add / edit / delete / undo / generate operations, against the real store, real crypto and the local server.
@Suite("Item actions for the command panel", .serialized)
struct ItemActionFlowTests {

    private func issues(_ body: () async throws -> Void) async -> [ItemIssue] {
        do { try await body(); return [] } catch let e as ItemValidationError { return e.issues } catch { return [ItemIssue(.size, .tooLarge)] }
    }

    @Test("create: login, note and secret from drafts are normalised, validated, idempotent and reach another device")
    func createFromDrafts() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)

            var d = ItemDraft(type: .login)
            d.title = "  GitHub  "
            d.urls = ["GitHub.com/login", "https://GITHUB.com/login", "  ", "HTTPS://Example.ORG/"]
            d.username = " rodrigo "
            d.password = "pa ss"
            d.totp = "jbsw y3dp-ehpk 3pxp"
            d.notes = "  "
            d.tags = ["Dev", "dev", " ", "work"]
            d.fields = [CustomField(label: " Pin ", value: "1234", secret: true), CustomField(label: "", value: "")]
            #expect(ItemValidator.issues(for: d).isEmpty)
            let login = try await a.vault.createItem(d)
            #expect(login.id == d.id)
            #expect(login.title == "GitHub")
            #expect(login.urls == ["https://github.com/login", "https://example.org"], "scheme added, host lowercased, trailing slash and duplicates dropped")
            #expect(login.username == "rodrigo")
            #expect(login.password == "pa ss", "passwords are never trimmed")
            #expect(login.totp == TOTPParameters(secret: "JBSWY3DPEHPK3PXP"))
            #expect(login.notes == nil)
            #expect(login.tags == ["Dev", "work"])
            #expect(login.fields == [CustomField(label: "Pin", value: "1234", secret: true)])

            // The same draft submitted again (double Return) is the same item, not a second one.
            let again = try await a.vault.createItem(d)
            #expect(again == login)
            #expect(try await a.vault.items().items.count == 1)

            var n = ItemDraft(type: .note)
            n.title = "Wi-Fi"; n.notes = "router: 192.168.0.1"; n.username = "ignored"; n.password = "ignored"; n.urls = ["not a url"]
            let note = try await a.vault.createItem(n)
            #expect(note.type == .note && note.username == nil && note.password == nil && note.urls.isEmpty, "a note keeps only what a note can hold")

            var s = ItemDraft(type: .secret)
            s.title = "Stripe key"; s.password = "sk_test_123"; s.totp = "JBSWY3DPEHPK3PXP"
            let secret = try await a.vault.createItem(s)
            #expect(secret.type == .secret && secret.password == "sk_test_123" && secret.totp == nil)

            // A scheme that autofill must never open is refused, and a refused create writes nothing.
            var unsafe = ItemDraft(type: .login)
            unsafe.title = "Bad"; unsafe.urls = ["javascript:alert(1)"]
            #expect(await issues { _ = try await a.vault.createItem(unsafe) } == [ItemIssue(.urls, .unsupportedURLScheme, index: 0)])
            #expect(try await a.vault.items().items.count == 3)

            try await a.vault.sync()
            try await b.enroll(through: a, server: server)
            let onB = try await b.vault.items().items
            #expect(Set(onB.map(\.id)) == [login.id, note.id, secret.id])
            #expect(onB.first { $0.id == login.id }?.totp == login.totp)
        }
    }

    @Test("TOTP text round-trips: non-default parameters survive an edit of an unrelated field")
    func totpRoundTrip() async throws {
        let a = try Device("a")
        _ = try await a.vault.bootstrapLocal(deviceName: "a")
        var d = ItemDraft()
        d.title = "Bank"
        d.totp = "otpauth://totp/Bank:me?secret=jbswy3dpehpk3pxp&issuer=Bank&algorithm=sha256&digits=8&period=60"
        let item = try await a.vault.createItem(d)
        #expect(item.totp == TOTPParameters(secret: "JBSWY3DPEHPK3PXP", algo: .sha256, digits: 8, period: 60))
        var edit = ItemDraft(editing: item)
        edit.notes = "changed"
        let out = try await a.vault.updateItem(edit)
        guard case .saved(let saved, _) = out else { Issue.record("expected saved, got \(out)"); return }
        #expect(saved.totp == item.totp)
    }

    @Test("edit: only touched fields change, an untouched draft writes nothing and asks for nothing")
    func editTouchesOnlyWhatChanged() async throws {
        try await TestServer.with { server in
            let gate = RecordingGate()
            let a = try Device("a", gate: gate)
            try await a.bootstrap(server)
            // An item as an importer would have stored it: an address the validator would normalise, extra data the form never shows.
            let imported = try await a.vault.save(Item(title: "Legacy", urls: ["legacy.example", "androidapp://com.legacy"], username: "u",
                                                       password: "p", passkey: .object(["credentialId": .string("abc")])))
            let stored = try await a.vault.item(id: imported.id)

            let untouched = ItemDraft(editing: stored)
            let before = gate.calls.count
            #expect(try await a.vault.updateItem(untouched) == .unchanged(stored))
            #expect(gate.calls.count == before, "no change, no biometric prompt")
            #expect(try await a.vault.pendingChanges() == 2, "and nothing new to push (the item and the manifest)")

            var d = ItemDraft(editing: stored)
            d.title = "Legacy 2"
            let out = try await a.vault.updateItem(d)
            guard case .saved(let saved, let merged) = out else { Issue.record("expected saved"); return }
            #expect(!merged)
            #expect(saved.title == "Legacy 2")
            #expect(saved.urls == ["legacy.example", "androidapp://com.legacy"], "untouched addresses are not rewritten")
            #expect(saved.passkey == stored.passkey && saved.createdAt == stored.createdAt && saved.id == stored.id)
            #expect(gate.calls.suffix(1) == ["Edit Legacy"], "a real edit asks once")
            #expect(try await a.vault.item(id: stored.id) == saved)

            // Touching the addresses applies today's rules to what was typed, but keeps the entries that were already there.
            var e = ItemDraft(editing: saved)
            e.urls = ["androidapp://com.legacy", "New.Example"]
            guard case .saved(let r, _) = try await a.vault.updateItem(e) else { Issue.record("expected saved"); return }
            #expect(r.urls == ["androidapp://com.legacy", "https://new.example"])
            var f = ItemDraft(editing: r)
            f.urls.append("javascript:alert(1)")
            await #expect(throws: ItemValidationError(issues: [ItemIssue(.urls, .unsupportedURLScheme, index: 2)])) { _ = try await a.vault.updateItem(f) }

            // A passkey item cannot be turned into something else, and its credential survives an edit.
            let pk = try await a.vault.save(Item(type: .passkey, title: "Passkey", passkey: .string("blob")))
            var g = ItemDraft(editing: pk); g.type = .login
            await #expect(throws: ItemValidationError(issues: [ItemIssue(.type, .unsupportedType)])) { _ = try await a.vault.updateItem(g) }
            var h = ItemDraft(editing: pk); h.title = "Passkey renamed"
            guard case .saved(let kept, _) = try await a.vault.updateItem(h) else { Issue.record("expected saved"); return }
            #expect(kept.passkey == .string("blob") && kept.type == .passkey)
        }
    }

    @Test("edit against a stale revision merges disjoint changes from another device and never loses either side")
    func staleEditMergesAcrossDevices() async throws {
        try await TestServer.with { server in
            let a = try Device("a"), b = try Device("b")
            try await a.bootstrap(server)
            let item = try await a.vault.createItem({ var d = ItemDraft(); d.title = "Mail"; d.username = "me"; d.password = "old"; d.notes = "n"; return d }())
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            // A opens the form; meanwhile B changes the password and syncs; A's sync pulls it in.
            var form = ItemDraft(editing: item)
            var onB = ItemDraft(editing: try await b.vault.item(id: item.id))
            onB.password = "from-b"; onB.tags = ["b-tag"]
            try await b.vault.updateItem(onB)
            try await b.vault.sync()
            try await a.vault.sync()
            #expect(try await a.vault.item(id: item.id).password == "from-b")

            form.title = "Mail (work)"; form.notes = "mine"
            let out = try await a.vault.updateItem(form)
            guard case .saved(let saved, let merged) = out else { Issue.record("expected saved, got \(out)"); return }
            #expect(merged, "the outcome says another device's changes were kept")
            #expect(saved.title == "Mail (work)" && saved.notes == "mine")
            #expect(saved.password == "from-b" && saved.tags == ["b-tag"], "the other device's edits survive a stale save")
            #expect(saved.username == "me")

            try await a.vault.sync(); try await b.vault.sync()
            #expect(try await b.vault.item(id: item.id) == saved)
        }
    }

    @Test("edit conflicts: nothing is written until the owner chooses, and each choice keeps data")
    func conflictResolutions() async throws {
        let a = try Device("a")
        _ = try await a.vault.bootstrapLocal(deviceName: "a")
        func fresh(_ title: String) async throws -> Item {
            var d = ItemDraft(); d.title = title; d.username = "u"; d.password = "base"; d.notes = "base notes"
            return try await a.vault.createItem(d)
        }
        // "Another device" = a direct save on top of the item the form was opened on.
        func elsewhere(_ item: Item, _ change: (inout Item) -> Void) async throws {
            var other = try await a.vault.item(id: item.id); change(&other); try await a.vault.save(other)
        }

        // Both sides changed the password differently, the form also changed the title.
        let one = try await fresh("One")
        var form = ItemDraft(editing: one)
        form.password = "mine"; form.title = "One!"
        try await elsewhere(one) { $0.password = "theirs"; $0.notes = "their notes" }
        let conflict = try await expectConflict { _ = try await a.vault.updateItem(form) }
        #expect(conflict.fields == [.password] && conflict.current?.password == "theirs" && conflict.mine.password == "mine")
        #expect(try await a.vault.item(id: one.id).password == "theirs", "the conflicting save wrote nothing")

        // useMine: my password wins, their notes stay.
        guard case .saved(let m, _) = try await a.vault.updateItem(form, resolution: .init(.useMine, for: conflict)) else { Issue.record("expected saved"); return }
        #expect(m.password == "mine" && m.title == "One!" && m.notes == "their notes")
        #expect(try await a.vault.trash().contains { $0.itemID == one.id && $0.item.password == "theirs" }, "what was overwritten stays recoverable")

        // useTheirs: their password stays, my title still lands.
        let two = try await fresh("Two")
        var form2 = ItemDraft(editing: two); form2.password = "mine"; form2.title = "Two!"
        try await elsewhere(two) { $0.password = "theirs" }
        let c2 = try await expectConflict { _ = try await a.vault.updateItem(form2) }
        guard case .saved(let t, _) = try await a.vault.updateItem(form2, resolution: .init(.useTheirs, for: c2)) else { Issue.record("expected saved"); return }
        #expect(t.password == "theirs" && t.title == "Two!")

        // useTheirs when nothing else was touched: the draft is simply dropped.
        let three = try await fresh("Three")
        var form3 = ItemDraft(editing: three); form3.password = "mine"
        try await elsewhere(three) { $0.password = "theirs" }
        let c3 = try await expectConflict { _ = try await a.vault.updateItem(form3) }
        guard case .discarded(let kept) = try await a.vault.updateItem(form3, resolution: .init(.useTheirs, for: c3)) else { Issue.record("expected discarded"); return }
        #expect(kept?.password == "theirs")

        // keepBoth: the original is untouched and my version becomes "<title> (conflict)".
        let four = try await fresh("Four")
        var form4 = ItemDraft(editing: four); form4.password = "mine"
        try await elsewhere(four) { $0.password = "theirs" }
        let c4 = try await expectConflict { _ = try await a.vault.updateItem(form4) }
        guard case .savedAsCopy(let copy) = try await a.vault.updateItem(form4, resolution: .init(.keepBoth, for: c4)) else { Issue.record("expected copy"); return }
        #expect(copy.id != four.id && copy.title == "Four (conflict)" && copy.password == "mine")
        #expect(try await a.vault.item(id: four.id).password == "theirs")

        // A resolution is only good for the conflict the owner saw: if the item changed again, they see the new one first.
        let five = try await fresh("Five")
        var form5 = ItemDraft(editing: five); form5.password = "mine"
        try await elsewhere(five) { $0.password = "theirs" }
        let c5 = try await expectConflict { _ = try await a.vault.updateItem(form5) }
        try await elsewhere(five) { $0.password = "theirs again" }
        let c5b = try await expectConflict { _ = try await a.vault.updateItem(form5, resolution: .init(.useMine, for: c5)) }
        #expect(c5b.current?.password == "theirs again")
        #expect(try await a.vault.item(id: five.id).password == "theirs again")
    }

    @Test("an edit of an item that was deleted elsewhere is a conflict; the owner's version can be brought back")
    func editOfDeletedItem() async throws {
        let a = try Device("a")
        _ = try await a.vault.bootstrapLocal(deviceName: "a")
        var d = ItemDraft(); d.title = "Gone"; d.password = "p"
        let item = try await a.vault.createItem(d)
        var form = ItemDraft(editing: item); form.notes = "typed a long note"
        _ = try await a.vault.trashItem(id: item.id)

        let c = try await expectConflict { _ = try await a.vault.updateItem(form) }
        #expect(c.itemWasDeleted && c.mine.notes == "typed a long note")
        guard case .discarded(nil) = try await a.vault.updateItem(form, resolution: .init(.useTheirs, for: c)) else { Issue.record("expected discarded"); return }
        #expect(try await a.vault.items().items.isEmpty)
        guard case .saved(let back, _) = try await a.vault.updateItem(form, resolution: .init(.useMine, for: c)) else { Issue.record("expected saved"); return }
        #expect(back.id == item.id && back.notes == "typed a long note" && back.password == "p")
        #expect(try await a.vault.items().items.map(\.id) == [item.id])
    }

    @Test("trash and undo: gated delete, undo without a prompt inside the window, restore on another device after sync")
    func trashAndUndo() async throws {
        try await TestServer.with { server in
            let gate = RecordingGate()
            let a = try Device("a", gate: gate), b = try Device("b")
            try await a.bootstrap(server)
            let keep = try await a.vault.createItem({ var d = ItemDraft(); d.title = "Keep"; d.password = "k"; return d }())
            let doomed = try await a.vault.createItem({ var d = ItemDraft(); d.title = "Doomed"; d.password = "secret-1"; d.totp = "JBSWY3DPEHPK3PXP"; return d }())
            try await a.vault.sync()
            try await b.enroll(through: a, server: server)

            let receipt = try await a.vault.trashItem(id: doomed.id)
            #expect(gate.calls.last == "Delete item", "deleting asks for Touch ID")
            #expect(receipt.title == "Doomed" && receipt.itemID == doomed.id && receipt.type == .login)
            #expect(try await a.vault.items().items.map(\.id) == [keep.id])
            #expect(try await a.vault.recentlyDeleted().map(\.itemID) == [doomed.id])
            await #expect(throws: VaultError.notFound(doomed.id)) { _ = try await a.vault.trashItem(id: doomed.id) }

            // Undo inside the window: no prompt, same id, same secrets.
            let prompts = gate.calls.count
            let back = try await a.vault.undoTrash(receipt)
            #expect(gate.calls.count == prompts, "undo inside the window needs no biometric check")
            #expect(back.id == doomed.id && back.password == "secret-1" && back.totp == doomed.totp)
            #expect(try await a.vault.recentlyDeleted().isEmpty)
            #expect(try await a.vault.undoTrash(receipt) == back, "undoing twice is harmless")

            // The delete reaches the server, then the owner changes their mind: the item comes back everywhere.
            try await a.vault.sync()
            let second = try await a.vault.trashItem(id: doomed.id)
            try await a.vault.sync(); try await b.vault.sync()
            #expect(try await b.vault.items().items.map(\.id) == [keep.id], "the delete arrived on B")
            let restored = try await a.vault.undoTrash(second)
            try await a.vault.sync(); try await b.vault.sync()
            #expect(Set(try await b.vault.items().items.map(\.id)) == [keep.id, doomed.id])
            #expect(try await b.vault.item(id: doomed.id).password == restored.password)

            // Past the window the restore asks like any other.
            let third = try await a.vault.trashItem(id: keep.id)
            try await Task.sleep(for: .seconds(TrashReceipt.undoWindow + 1))
            let calls = gate.calls.count
            _ = try await a.vault.undoTrash(third)
            #expect(gate.calls.count == calls + 1 && gate.calls.last == "Restore Keep")

            // A refused biometric check leaves the item where it is.
            gate.deny(true)
            await #expect(throws: KeyStoreError.userCancelled) { _ = try await a.vault.trashItem(id: keep.id) }
            gate.deny(false)
            #expect(try await a.vault.items().items.count == 2)
        }
    }

    @Test("trash an item that never reached the server, and undo it after a relaunch (local-only box)")
    func trashNeverSyncedAndRelaunch() async throws {
        let a = try Device("a")
        _ = try await a.vault.bootstrapLocal(deviceName: "a")
        let item = try await a.vault.createItem({ var d = ItemDraft(); d.title = "Scratch"; d.password = "s"; return d }())
        let receipt = try await a.vault.trashItem(id: item.id)
        #expect(try await a.vault.items().items.isEmpty)

        let relaunched = try a.relaunched()
        try await relaunched.unlock()
        let listed = try await relaunched.recentlyDeleted()
        #expect(listed.map(\.itemID) == [item.id] && listed.first?.title == "Scratch")
        let back = try await relaunched.undoTrash(try #require(listed.first))
        #expect(back.password == "s" && back.id == item.id)
        #expect(try await relaunched.items().items.map(\.id) == [item.id])
        _ = receipt
    }

    private func expectConflict(_ body: () async throws -> Void) async throws -> ItemConflict {
        do { try await body() } catch let c as ItemConflict { return c }
        Issue.record("expected a conflict"); throw ItemActionError.undoUnavailable
    }
}
#endif
