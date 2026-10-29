#if DEBUG
import AppKit
import BiselCore

/// DEBUG-ONLY scripted run of the real app code paths (VaultService, the panel's search/secret/copy path, importers,
/// lock triggers, recovery) for headless verification when no one is at the screen. Compiled out of Release.
///   BISEL_DEV_FLOW=<phase>  BISEL_DEV_FLOW_LOG=<file>  BISEL_DEV_SERVER  BISEL_DEV_TOKEN  BISEL_DEV_PHRASE_FILE  (+ BISEL_DEV_1PUX, BISEL_DEV_CSV, BISEL_DEV_EXPORT_PATH)
///   phases: create (bootstrap → items → search → copy → lock/unlock → import → export)
///           recover (fresh store: recover from the phrase file → items present → devices → revoke the other device)
///           revoked (original store after being revoked: unlock → sync must be refused)
@MainActor
enum DebugFlow {
    private static var log = ""
    private static var failures = 0

    static func runIfRequested() {
        let env = ProcessInfo.processInfo.environment
        guard let phase = env["BISEL_DEV_FLOW"], let logPath = env["BISEL_DEV_FLOW_LOG"] else { return }
        Log.app.fault("BISEL_DEV_FLOW=\(phase, privacy: .public) active (debug build only)")
        Task {
            await AppModel.shared.service.start()
            switch phase {
            case "create": await create(env)
            case "recover": await recover(env)
            case "revoked": await revoked(env)
            case "localedit": await edit(title: "Acme LOCAL", viaCore: true)
            case "remoteedit": await edit(title: "Acme REMOTE", viaCore: false)
            case "resolve": await resolve()
            case "offline": await offline()
            case "online": await online()
            case "revokeother": await revokeOther()
            case "restore": await restore(env)
            case "strict": await strict()
            case "security": await security(env)
            case "bootstraponly": await bootstrapOnly(env)
            case "unconfirmed": await unconfirmed(env)
            default: note("unknown phase")
            }
            note(failures == 0 ? "RESULT: ALL PASSED" : "RESULT: \(failures) FAILED")
            try? log.write(toFile: logPath, atomically: true, encoding: .utf8)
            try? await Task.sleep(for: .seconds(1))
            NSApp.terminate(nil)
        }
    }

    private static func note(_ s: String) { log += s + "\n" }
    private static func check(_ ok: Bool, _ what: String) {
        note((ok ? "PASS  " : "FAIL  ") + what)
        if !ok { failures += 1 }
    }
    private static func sleep(_ s: Double) async { try? await Task.sleep(for: .seconds(s)) }

    private static func create(_ env: [String: String]) async {
        let svc = AppModel.shared.service
        let panel = AppModel.shared.vault
        let server = URL(string: env["BISEL_DEV_SERVER"] ?? "http://localhost:8790")!
        check(svc.phase == .needsSetup, "fresh store starts in needsSetup")
        do {
            try await svc.bootstrap(server: server, token: env["BISEL_DEV_TOKEN"] ?? "dev-bootstrap-token", deviceName: "Flow Mac A")
            check(svc.pendingPhrase?.words.count == 24, "bootstrap shows a 24-word phrase and holds it until confirmed")
            if let path = env["BISEL_DEV_PHRASE_FILE"], let p = svc.pendingPhrase { try? p.text.write(toFile: path, atomically: true, encoding: .utf8) }
            check(svc.phase == .unlocked, "vault is unlocked right after bootstrap")
            svc.confirmPhraseStored()

            // items → panel search/secret/copy
            let saved = try await svc.save(Item(type: .login, title: "Acme Flow Test", urls: ["https://acme-flow.test"], username: "flow.user@acme.test",
                                                password: "Fl0w-Pass-123", totp: TOTPParameters(secret: "JBSWY3DPEHPK3PXP"), tags: ["work"]))
            _ = try await svc.save(Item(type: .login, title: "Other Site", urls: ["https://other.test"], username: "o", password: "o-pass"))
            _ = try await svc.save(Item(type: .note, title: "A Note", notes: "body"))
            let hits = panel.search("acme", limit: 10)
            check(hits.first?.title == "Acme Flow Test", "panel search finds the item by title (\(hits.count) hit)")
            check(panel.search("acme-flow", limit: 10).first?.id == saved.id, "panel search finds the item by URL host")
            check(panel.search("a note", limit: 10).isEmpty, "notes are not offered in the panel")
            check((try? await panel.secret(.password, for: saved.id)) == "Fl0w-Pass-123", "panel secret(.password) returns the stored password")
            check((try? await panel.secret(.username, for: saved.id)) == "flow.user@acme.test", "panel secret(.username)")
            let code = try? await panel.secret(.totp, for: saved.id)
            let expected = try? TOTPGenerator.code(TOTPParameters(secret: "JBSWY3DPEHPK3PXP")).code
            check(code != nil && code == expected, "panel secret(.totp) matches RFC 6238 for the stored secret")
            // the panel's real copy path (SecureClipboard), then clear
            if let r = hits.first {
                AppModel.shared.panelModel.runCopy?(.password, r)
                await sleep(0.8)
                let cp = NSPasteboard.general.string(forType: .string)
                check(cp == "Fl0w-Pass-123", "panel copy puts the password on the pasteboard")
                check(NSPasteboard.general.types?.contains(SecureClipboard.concealedType) == true, "copy is marked concealed")
                SecureClipboard.shared.clearIfUnchanged(expected: NSPasteboard.general.changeCount)
            }

            // sync
            await svc.sync(reason: "flow")
            if case .synced = svc.syncState { check(true, "sync ok, pending=\(svc.pendingChanges)") } else { check(false, "sync state \(svc.syncState)") }
            check(svc.pendingChanges == 0, "nothing pending after sync")

            // lock → everything gone → unlock
            svc.lock(reason: "flow")
            await sleep(0.3)
            check(svc.phase == .locked && !svc.isUnlocked, "lock() locks")
            check(panel.search("acme", limit: 10).isEmpty && svc.rows.isEmpty, "search index and rows are dropped on lock")
            check((try? await panel.secret(.password, for: saved.id)) == nil, "secrets refuse while locked")
            let vaultLocked = await !(svc.vault?.isUnlocked ?? true)
            check(vaultLocked, "core Vault actor is locked too (VK zeroed)")
            try await svc.unlock()
            check(svc.phase == .unlocked && panel.search("acme", limit: 10).count == 1, "unlock restores the index")

            // OS lock trigger path (the notification macOS posts on screen lock)
            DistributedNotificationCenter.default().postNotificationName(Notification.Name("com.apple.screenIsLocked"), object: nil, userInfo: nil, deliverImmediately: true)
            await sleep(0.6)
            check(svc.phase == .locked, "screen-lock notification locks the vault")
            try await svc.unlock()

            // edit + delete honor the gate (bypassed here), conflict-free
            var edit = try await svc.item(id: saved.id)
            edit.title = "Acme Flow Test 2"
            _ = try await svc.save(edit)
            check(svc.rows.contains { $0.title == "Acme Flow Test 2" } && !svc.rows.contains { $0.title == "Acme Flow Test" }, "edit updates the row")
            try await svc.delete(id: svc.rows.first { $0.title == "Other Site" }!.id)
            check(!svc.rows.contains { $0.title == "Other Site" }, "delete removes the row")

            // import
            if let p = env["BISEL_DEV_1PUX"] {
                let o = try OnePuxImporter.parse(url: URL(fileURLWithPath: p))
                check(o.items.count == 5 && o.skipped.count == 1, "1pux: 5 items imported, archived one skipped (got \(o.items.count)/\(o.skipped.count))")
                check(o.withTOTP == 1 && o.passkeys == 1 && o.notes == 1 && o.secrets == 1, "1pux: totp=1 passkey=1 note=1 secret=1")
                if let pk = o.items.first(where: { $0.passkey != nil }) {
                    check(pk.passkey == .object(["credentialId": .string("FAKECRED123"), "rpId": .string("passkey-fake.test"), "userHandle": .string("FAKEHANDLE"),
                                                  "privateKey": .string("FAKE-PRIVATE-KEY-BLOB"), "counter": .number(7)]), "1pux: passkey blob kept losslessly")
                }
                try await svc.saveMany(o.items)
            }
            if let p = env["BISEL_DEV_CSV"] {
                let o = try CSVImporter.parse(url: URL(fileURLWithPath: p))
                check(o.items.count == 3, "csv: 3 rows → 3 items (got \(o.items.count))")
                check(o.items.first { $0.title == "CSV Shop (FAKE)" }?.password == "FAKE,comma;pass", "csv: quoted comma/semicolon password intact")
                check(o.items.first { $0.title == "CSV Shop (FAKE)" }?.notes == "multi\nline note", "csv: multi-line note intact")
                check(o.items.first { $0.title == "CSV Shop (FAKE)" }?.totp?.secret == "GEZDGNBVGY3TQOJQ", "csv: otpauth URI → TOTP secret")
                check(o.items.first { $0.title == "CSV Note (FAKE)" }?.type == .note, "csv: row with only a note becomes a note")
                try await svc.saveMany(o.items)
            }
            check(svc.rows.count >= 8, "vault now holds \(svc.rows.count) items")
            check(panel.search("passkey", limit: 5).first?.title == "Passkey Site (FAKE)", "imported passkey item is searchable")
            await svc.sync(reason: "flow-final")
            check(svc.pendingChanges == 0, "imports synced")

            // backup export
            if let out = env["BISEL_DEV_EXPORT_PATH"] {
                try await svc.exportBackup(to: URL(fileURLWithPath: out))
                check(FileManager.default.fileExists(atPath: out), "backup file written")
            }
            check((try? await svc.devices().count) == 1, "devices() lists this Mac")
        } catch {
            check(false, "unexpected error: \(describe(error))")
        }
    }

    private static func recover(_ env: [String: String]) async {
        let svc = AppModel.shared.service
        let panel = AppModel.shared.vault
        let server = URL(string: env["BISEL_DEV_SERVER"] ?? "http://localhost:8790")!
        do {
            check(svc.phase == .needsSetup, "fresh store (no keys, no data)")
            let phrase = try String(contentsOfFile: env["BISEL_DEV_PHRASE_FILE"]!, encoding: .utf8)
            do { try await svc.recover(server: server, phrase: "abandon " + phrase.split(separator: " ").dropFirst().joined(separator: " "), deviceName: "Wrong") ; check(false, "a wrong phrase must be refused") }
            catch { check(true, "wrong phrase refused: \(describe(error))") }
            try await svc.recover(server: server, phrase: phrase, deviceName: "Flow Mac B (recovered)")
            check(svc.phase == .unlocked, "recovery unlocks the new device")
            check(svc.rows.count >= 8, "items restored from the server (\(svc.rows.count))")
            let hit = panel.search("acme", limit: 5).first
            check(hit?.title == "Acme Flow Test 2", "restored item searchable")
            if let hit { check((try? await panel.secret(.password, for: hit.id)) == "Fl0w-Pass-123", "restored password decrypts with the recovered VK") }
            let devs = try await svc.devices()
            check(devs.count == 2, "two devices listed (\(devs.count))")
            if env["BISEL_DEV_KEEP_A"] != "1", let other = devs.first(where: { $0.id != svc.deviceID }) {
                try await svc.revoke(deviceID: other.id)
                let after = try await svc.devices()
                check(after.first { $0.id == other.id }?.isRevoked == true, "original device revoked")
            }
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    /// Edits "Acme Flow Test 2" (or whatever the title currently is). `viaCore` saves straight into the core store without
    /// syncing, leaving a pending local edit (the situation of a device that was offline).
    private static func edit(title: String, viaCore: Bool) async {
        let svc = AppModel.shared.service
        do {
            try await svc.unlock()
            await svc.sync(reason: "flow-pre")
            if viaCore {
                // Device B was added with the recovery phrase meanwhile: this Mac must have been told, loudly.
                check(svc.securityAlerts.contains { $0.text.contains("recovery phrase") }, "a device added with the recovery phrase raises a security alert (\(svc.securityAlerts.count))")
                check(!(await svc.recentEvents()).isEmpty, "the Devices window has recent activity to list")
            }
            guard let row = svc.rows.first(where: { $0.title.hasPrefix("Acme") }) else { check(false, "no Acme item"); return }
            var item = try await svc.item(id: row.id)
            item.title = title
            if viaCore { _ = try await svc.vault!.save(item); check((try await svc.vault!.pendingChanges()) == 1, "local edit is pending (not synced)") }
            else { _ = try await svc.save(item); await svc.sync(reason: "flow-post"); check(svc.pendingChanges == 0, "remote edit synced") }
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    private static func resolve() async {
        let svc = AppModel.shared.service
        do {
            try await svc.unlock()
            await svc.sync(reason: "flow-resolve")
            for _ in 0..<20 where svc.syncState == .syncing { await sleep(0.25) }
            let titles = svc.rows.map(\.title)
            check(titles.contains("Acme REMOTE"), "remote version kept (titles: \(titles.filter { $0.hasPrefix("Acme") }))")
            check(titles.contains("Acme LOCAL (conflict)"), "local edit kept as “… (conflict)” copy, no silent overwrite")
            check(svc.lastConflicts == 1, "sync reported 1 conflict")
            check(svc.pendingChanges == 0, "nothing left pending after resolution")
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    private static func offline() async {
        let svc = AppModel.shared.service
        do {
            try await svc.unlock()
            _ = try await svc.save(Item(type: .login, title: "Made Offline", username: "u", password: "p"))
            await svc.sync(reason: "flow-offline")
            for _ in 0..<20 where svc.syncState == .syncing { await sleep(0.25) }
            if case .offline = svc.syncState { check(true, "server down → state is offline, not an error") } else { check(false, "state \(svc.syncState)") }
            check(svc.pendingChanges >= 1, "edit kept locally and pending (\(svc.pendingChanges))")
            check(svc.rows.contains { $0.title == "Made Offline" }, "item usable while offline")
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    private static func online() async {
        let svc = AppModel.shared.service
        do {
            try await svc.unlock()
            await svc.sync(reason: "flow-online")
            for _ in 0..<20 where svc.syncState == .syncing { await sleep(0.25) }
            if case .synced = svc.syncState { check(true, "back online → synced") } else { check(false, "state \(svc.syncState)") }
            check(svc.pendingChanges == 0, "offline edit pushed")
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    private static func revokeOther() async {
        let svc = AppModel.shared.service
        do {
            try await svc.unlock()
            let devs = try await svc.devices()
            guard let other = devs.first(where: { $0.id != svc.deviceID && !$0.isRevoked }) else { check(false, "no other device"); return }
            try await svc.revoke(deviceID: other.id)
            check(try await svc.devices().first { $0.id == other.id }?.isRevoked == true, "other device revoked")
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    /// Fresh store + FRESH server: restore from the .bisel-backup written by the create phase.
    private static func restore(_ env: [String: String]) async {
        let svc = AppModel.shared.service
        let server = URL(string: env["BISEL_DEV_SERVER"] ?? "http://localhost:8790")!
        do {
            let phrase = try String(contentsOfFile: env["BISEL_DEV_PHRASE_FILE"]!, encoding: .utf8)
            do { try await svc.importBackup(from: URL(fileURLWithPath: env["BISEL_DEV_EXPORT_PATH"]!), phrase: "abandon " + phrase.split(separator: " ").dropFirst().joined(separator: " "),
                                            server: server, token: "dev-bootstrap-token", deviceName: "Wrong") ; check(false, "wrong phrase must be refused") }
            catch { check(true, "restore with a wrong phrase refused: \(describe(error))") }
            try await svc.importBackup(from: URL(fileURLWithPath: env["BISEL_DEV_EXPORT_PATH"]!), phrase: phrase, server: server,
                                       token: env["BISEL_DEV_TOKEN"] ?? "dev-bootstrap-token", deviceName: "Flow Mac C (restored)")
            check(svc.phase == .unlocked, "restore unlocks")
            check(svc.rows.count >= 8, "items restored from the backup file onto the new server (\(svc.rows.count))")
            let hit = AppModel.shared.vault.search("acme", limit: 3).first
            if let hit { check((try? await AppModel.shared.vault.secret(.password, for: hit.id)) == "Fl0w-Pass-123", "restored password decrypts") } else { check(false, "acme item missing") }
            await svc.sync(reason: "flow-restore")
            check(svc.pendingChanges == 0, "restored items are on the new server")
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    /// Launched with `-security.requireTouchIDForSecrets YES` (argument domain: not persisted into the user's real preferences).
    private static func strict() async {
        let svc = AppModel.shared.service
        let panel = AppModel.shared.vault
        do {
            check(SecuritySettings.requireTouchID, "strict mode is on for this run")
            try await svc.unlock()
            guard let hit = panel.search("acme", limit: 3).first else { check(false, "no acme item"); return }
            let base = BiometricGate.promptCount
            _ = try await panel.secret(.username, for: hit.id)
            check(BiometricGate.promptCount == base, "username needs no prompt")
            _ = try await panel.secret(.password, for: hit.id)
            check(BiometricGate.promptCount == base + 1, "strict: reading the password prompts (fill and copy share this gate)")
            _ = try await panel.secret(.password, for: hit.id)
            check(BiometricGate.promptCount == base + 2, "strict: a second read prompts again")
            _ = try await panel.secret(.totp, for: hit.id)
            check(BiometricGate.promptCount == base + 3, "strict: reading the OTP prompts")
            let b = BiometricGate.promptCount
            _ = try await panel.secret(.totp, for: hit.id)
            check(BiometricGate.promptCount == b, "strict: OTP refresh inside the reveal window does not prompt again")
            // the panel prompts first, then reads: one prompt for that one action
            let c = BiometricGate.promptCount
            try await BiometricGate.authenticate(reason: "panel prompt")
            _ = try await panel.secret(.password, for: hit.id)
            check(BiometricGate.promptCount == c + 1, "panel-then-secret is a single prompt")
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    private static func bootstrapOnly(_ env: [String: String]) async {
        let svc = AppModel.shared.service
        do {
            try await svc.bootstrap(server: URL(string: env["BISEL_DEV_SERVER"] ?? "http://localhost:8790")!, token: "dev-bootstrap-token", deviceName: "Unconfirmed Mac")
            if let path = env["BISEL_DEV_PHRASE_FILE"], let p = svc.pendingPhrase { try? p.text.write(toFile: path, atomically: true, encoding: .utf8) }
            check(svc.recoveryUnconfirmed && svc.pendingPhrase != nil, "bootstrap marks the recovery phrase unconfirmed while it is on screen")
            // the process now quits without "I have stored it"
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    private static func unconfirmed(_ env: [String: String]) async {
        let svc = AppModel.shared.service
        do {
            let old = try String(contentsOfFile: env["BISEL_DEV_PHRASE_FILE"]!, encoding: .utf8)
            check(svc.recoveryUnconfirmed, "the unconfirmed marker survived the quit")
            try await svc.unlock()
            await sleep(1.0)
            check(svc.pendingPhrase != nil && svc.pendingPhrase?.text != old, "next unlock issues a NEW phrase to show (the old one was never confirmed)")
            svc.confirmPhraseStored()
            check(!svc.recoveryUnconfirmed, "marker cleared after the words are confirmed")
        } catch { check(false, "unexpected error: \(describe(error))") }
    }

    /// Pure-policy checks of the security fixes, run through the real code (URL policy, icon host policy, PSL, image limits, importers).
    private static func security(_ env: [String: String]) async {
        func url(_ s: String, _ want: URLPolicy.Decision) { check(URLPolicy.decide(s) == want, "URLPolicy \(s.prefix(40)) → \(want)") }
        url("https://example.com/login", .open(URL(string: "https://example.com/login")!))
        url("example.com", .open(URL(string: "https://example.com")!))
        url("http://example.com", .confirmHTTP(URL(string: "http://example.com")!))
        for bad in ["file:///Users/x/y.command", "smb://host/share", "vnc://h", "x-apple.systempreferences:com.apple.preference", "javascript:alert(1)",
                    "mailto:a@b.c", "data:text/html,hi", "ssh://h", "https://exa\nmple.com"] {
            if case .refuse = URLPolicy.decide(bad) { check(true, "URLPolicy refuses \(bad.prefix(30).replacingOccurrences(of: "\n", with: "⏎"))") } else { check(false, "URLPolicy accepted \(bad)") }
        }
        for h in ["127.0.0.1", "192.168.1.5", "localhost", "printer.local", "10.0.0.1", "0x7f.0.0.1", "2130706433", "[::1]", "::1", "intranet", "github.io", "co.uk", "foo.internal"] {
            check(!IconHostPolicy.acceptable(host: h, port: nil), "icon host refused: \(h)")
        }
        check(!IconHostPolicy.acceptable(host: "example.com", port: 8443), "icon host refused: non-443 port")
        check(IconHostPolicy.acceptable(host: "example.com", port: 443) && IconHostPolicy.acceptable(host: "a.github.io", port: nil), "icon host accepted: example.com, a.github.io")
        for a in ["169.254.169.254", "100.64.0.1", "172.16.0.1", "172.31.255.1", "10.1.2.3", "192.168.0.1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "fd00::1", "fe80::1", "ff02::1", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
            check(!IconHostPolicy.isPublic(addressString: a), "address not public: \(a)")
        }
        for a in ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "172.32.0.1"] { check(IconHostPolicy.isPublic(addressString: a), "address public: \(a)") }
        check(!IconHostPolicy.resolvesToPublicAddressesOnly("localhost"), "localhost resolves to loopback → refused")
        check(DomainName.registrable("a.b.example.co.uk") == "example.co.uk", "PSL: example.co.uk")
        check(DomainName.registrable("x.github.io") == "x.github.io" && DomainName.registrable("y.github.io") == "y.github.io", "PSL: github.io tenants are separate sites")
        check(DomainName.registrable("foo.bar.ck") == "foo.bar.ck" && DomainName.registrable("sub.www.ck") == "www.ck", "PSL: wildcard and exception rules")
        check(DomainName.registrable("www.example.com") == "example.com", "PSL: www.example.com → example.com")
        // fill policy (M9): which field may receive a password
        func field(secure: Bool, terminal: Bool = false, ref: Bool = true) -> FocusedField {
            FocusedField(pid: 1, bundleID: nil, role: "AXTextField", subrole: nil, isTextInput: true, isSecure: secure, isClearlyNotText: false,
                         isTerminal: terminal, kind: secure ? .password : .username, hasElement: true,
                         ref: ref ? AXRef(element: AXUIElementCreateSystemWide()) : nil)
        }
        check(FillEngine.refusal(for: .password, in: field(secure: true), forced: false) == nil, "fill: password into a secure field is allowed")
        check(FillEngine.refusal(for: .password, in: field(secure: false), forced: false) != nil, "fill: password into a plain text field is refused")
        check(FillEngine.refusal(for: .password, in: field(secure: false), forced: true) == nil, "fill: …unless forced from ⌘K")
        check(FillEngine.refusal(for: .password, in: field(secure: false, terminal: true), forced: true) != nil, "fill: terminal without secure input refuses even a forced password")
        check(FillEngine.refusal(for: .password, in: field(secure: true, ref: false), forced: false) != nil, "fill: no verifiable focused element → password refused")
        check(FillEngine.refusal(for: .username, in: field(secure: false), forced: false) == nil && FillEngine.refusal(for: .totp, in: field(secure: false), forced: false) == nil, "fill: username and OTP are not restricted")
        check(IconStore.shared.enabled == false, "site icons are off by default")
        // images: header-declared huge PNG rejected before decoding, non-allow-listed type rejected, small PNG accepted
        func crc(_ d: Data) -> UInt32 { var c: UInt32 = 0xFFFFFFFF; for b in d { c ^= UInt32(b); for _ in 0..<8 { c = (c & 1) != 0 ? (c >> 1) ^ 0xEDB88320 : c >> 1 } }; return ~c }
        func chunk(_ type: String, _ body: Data) -> Data {
            var out = Data(); var len = UInt32(body.count).bigEndian
            out.append(Data(bytes: &len, count: 4)); let tb = Data(type.utf8) + body; out.append(tb)
            var c = crc(tb).bigEndian; out.append(Data(bytes: &c, count: 4)); return out
        }
        var ihdr = Data(); var w = UInt32(40000).bigEndian, h = UInt32(40000).bigEndian
        ihdr.append(Data(bytes: &w, count: 4)); ihdr.append(Data(bytes: &h, count: 4)); ihdr.append(contentsOf: [1, 0, 0, 0, 0])
        let bomb = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + chunk("IHDR", ihdr) + chunk("IDAT", Data([0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01])) + chunk("IEND", Data()) + Data(repeating: 0, count: 64)
        let t0 = ContinuousClock.now
        check(IconFetcher.normalize(bomb) == nil, "40000×40000 PNG rejected from its header")
        check(ContinuousClock.now - t0 < .milliseconds(500), "…without decoding it (took \(ContinuousClock.now - t0))")
        let small = NSImage(size: NSSize(width: 64, height: 64), flipped: false) { r in NSColor.systemBlue.setFill(); r.fill(); return true }
        if let tiff = small.tiffRepresentation { check(IconFetcher.normalize(tiff) == nil, "TIFF is not an allow-listed image type") }
        if let tiff = small.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff), let png = rep.representation(using: .png, properties: [:]) {
            check(IconFetcher.normalize(png) != nil, "an ordinary 64 px PNG is accepted")
        }
        check(!IconStore.canPersist || true, "icon cache persistence: \(IconStore.canPersist ? "keychain key" : "memory only (no keychain key in this build)")")
        // hostile archives
        for name in ["evil-dotdot.1pux", "evil-symlink.1pux"] {
            if let dir = env["BISEL_DEV_FIXTURES"] {
                do { _ = try OnePuxImporter.parse(url: URL(fileURLWithPath: dir + "/" + name)); check(false, "\(name) was accepted") }
                catch { check(true, "\(name) refused: \(error.localizedDescription)") }
            }
        }
    }

    private static func revoked(_ env: [String: String]) async {
        let svc = AppModel.shared.service
        do {
            try await svc.unlock()
            await svc.sync(reason: "flow-revoked")
            for _ in 0..<20 where svc.syncState == .syncing { await sleep(0.25) }
            if case .failed(let m) = svc.syncState { check(true, "revoked device's sync is refused: \(m.prefix(60))") } else { check(false, "sync state was \(svc.syncState)") }
        } catch { check(false, "unexpected error: \(describe(error))") }
    }
}
#endif
