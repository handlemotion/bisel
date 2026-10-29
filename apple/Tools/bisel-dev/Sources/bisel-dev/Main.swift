import ArgumentParser
import BiselCore
import Foundation
import CryptoKit

@main
struct BiselDev: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "bisel-dev",
        abstract: "Drives BiselCore against a bisel server using the SOFTWARE key store (test only, not secure).",
        discussion: """
        Each simulated device is a directory (--home, or $BISEL_HOME, default ~/.bisel-dev/default). \
        Use different homes for device A, device B, a fresh install, and so on.
        """,
        subcommands: [Bootstrap.self, Status.self, Add.self, Edit.self, Remove.self, List.self, Get.self, TOTPCommand.self,
                      SyncCommand.self, Devices.self, Enroll.self, Revoke.self, Recover.self, RotateRecovery.self,
                      Backup.self, SEProbe.self]
    )
}

struct Global: ParsableArguments {
    @Option(name: .long, help: "Device home directory holding the local store and software keys.")
    var home: String?

    func location() -> StoreLocation {
        let path = home ?? ProcessInfo.processInfo.environment["BISEL_HOME"]
            ?? (NSHomeDirectory() + "/.bisel-dev/default")
        return StoreLocation(directory: URL(fileURLWithPath: (path as NSString).expandingTildeInPath, isDirectory: true))
    }

    func vault(unlock: Bool = true) async throws -> Vault {
        let v = try Vault(.software(location: location()))
        if unlock, await v.isConfigured { try await v.unlock() }
        return v
    }
}

func say(_ s: String) { print(s) }

func parseURL(_ s: String) throws -> URL {
    guard let u = URL(string: s), u.scheme != nil, u.host != nil else { throw ValidationError("bad URL: \(s)") }
    return u
}

func parsePhrase(_ s: String) throws -> RecoveryPhrase {
    do { return try RecoveryPhrase(s) } catch { throw ValidationError("that is not a valid 24-word recovery phrase") }
}

func describe(_ report: SyncReport) -> String {
    var s = "synced: pushed \(report.pushed), pulled \(report.pulled), head seq \(report.headSeq)"
    for c in report.conflicts { s += "\n  CONFLICT on \(c.itemID): remote kept, your edit saved as \(c.copyID)" }
    for d in report.deferredConflicts { s += "\n  deferred conflict (vault locked): \(d)" }
    return s
}

struct Bootstrap: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "First device: create the vault on a fresh server and print the recovery phrase.")
    @OptionGroup var global: Global
    @Option var server: String
    @Option var token: String
    @Option var name: String = "bisel-dev"
    func run() async throws {
        let vault = try await global.vault(unlock: false)
        let phrase = try await vault.bootstrap(server: parseURL(server), bootstrapToken: token, deviceName: name)
        say("bootstrapped device '\(name)' at \(server)")
        say("RECOVERY PHRASE (shown once):")
        say(phrase.text)
    }
}

struct Status: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Show this device's identity and local state.")
    @OptionGroup var global: Global
    func run() async throws {
        let vault = try await global.vault(unlock: false)
        guard let id = try await vault.identity() else { say("not configured"); return }
        say("device \(id.deviceID) '\(id.deviceName)' keystore=\(id.keyStore) server=\(id.serverURL)")
        say(id.envelope == nil ? "state: enrollment pending approval" : "state: enrolled")
        say("pending local changes: \(try await vault.pendingChanges())")
    }
}

struct ItemFlags: ParsableArguments {
    @Option var title: String?
    @Option var username: String?
    @Option var password: String?
    @Option(name: .customLong("url")) var urls: [String] = []
    @Option var notes: String?
    @Option(name: .customLong("tag")) var tags: [String] = []
    @Option(help: "Base32 TOTP secret.") var totpSecret: String?
    @Option var type: String?
}

struct Add: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Add an item and push it.")
    @OptionGroup var global: Global
    @OptionGroup var flags: ItemFlags
    @Flag var noSync = false
    func run() async throws {
        guard let title = flags.title else { throw ValidationError("--title is required") }
        let vault = try await global.vault()
        var item = Item(type: ItemType(rawValue: flags.type ?? "login") ?? .login, title: title, urls: flags.urls,
                        username: flags.username, password: flags.password, notes: flags.notes, tags: flags.tags)
        if let s = flags.totpSecret { item.totp = TOTPParameters(secret: s) }
        let saved = try await vault.save(item)
        say("added \(saved.id)  \(saved.title)")
        if !noSync { say(describe(try await vault.sync())) }
    }
}

struct Edit: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Edit an item (pass --no-sync to create offline edits for conflict flows).")
    @OptionGroup var global: Global
    @Argument var id: String
    @OptionGroup var flags: ItemFlags
    @Flag var noSync = false
    func run() async throws {
        let vault = try await global.vault()
        var item = try await vault.item(id: id)
        if let v = flags.title { item.title = v }
        if let v = flags.username { item.username = v }
        if let v = flags.password { item.password = v }
        if let v = flags.notes { item.notes = v }
        if !flags.urls.isEmpty { item.urls = flags.urls }
        if !flags.tags.isEmpty { item.tags = flags.tags }
        if let s = flags.totpSecret { item.totp = TOTPParameters(secret: s) }
        try await vault.save(item)
        say("edited \(id)")
        if !noSync { say(describe(try await vault.sync())) }
    }
}

struct Remove: AsyncParsableCommand {
    static let commandName = "delete"
    static let configuration = CommandConfiguration(commandName: "delete", abstract: "Delete an item.")
    @OptionGroup var global: Global
    @Argument var id: String
    @Flag var noSync = false
    func run() async throws {
        let vault = try await global.vault()
        try await vault.delete(id: id)
        say("deleted \(id)")
        if !noSync { say(describe(try await vault.sync())) }
    }
}

struct List: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "List decrypted items (no passwords).")
    @OptionGroup var global: Global
    @Flag var json = false
    @Flag(help: "Sync before listing.") var sync = false
    func run() async throws {
        let vault = try await global.vault()
        if sync { say(describe(try await vault.sync())) }
        let listing = try await vault.items()
        if json {
            let rows = listing.items.map { ["id": $0.id, "title": $0.title, "username": $0.username ?? "", "type": $0.type.rawValue] }
            print(String(decoding: try JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys]), as: UTF8.self))
        } else {
            if listing.items.isEmpty { say("(no items)") }
            for i in listing.items {
                say("\(i.id)  \(i.type.rawValue)  \(i.title)  \(i.username ?? "-")  \(i.urls.first ?? "")")
            }
        }
        for bad in listing.undecryptable { say("UNDECRYPTABLE record \(bad) (failed authentication; not shown)") }
    }
}

struct Get: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Show one item. --reveal does the fresh-biometric password reveal.")
    @OptionGroup var global: Global
    @Argument var id: String
    @Flag var reveal = false
    @Flag var json = false
    func run() async throws {
        let vault = try await global.vault()
        let item = try await vault.item(id: id)
        let password = reveal ? try await vault.revealPassword(id: id) : "••••••••"
        if json {
            let obj: [String: Any] = ["id": item.id, "title": item.title, "username": item.username ?? "",
                                      "password": reveal ? password : "", "urls": item.urls, "notes": item.notes ?? ""]
            print(String(decoding: try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]), as: UTF8.self))
            return
        }
        say("id:       \(item.id)\ntype:     \(item.type.rawValue)\ntitle:    \(item.title)")
        say("username: \(item.username ?? "-")\npassword: \(password)")
        say("urls:     \(item.urls.joined(separator: ", "))\nnotes:    \(item.notes ?? "-")\ntags:     \(item.tags.joined(separator: ", "))")
        say("totp:     \(item.totp == nil ? "-" : "configured")")
    }
}

struct TOTPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "totp", abstract: "Current one-time code for an item.")
    @OptionGroup var global: Global
    @Argument var id: String
    func run() async throws {
        let code = try await global.vault().copyTOTP(id: id)
        say("\(code.code)  (\(code.secondsRemaining)s left)")
    }
}

struct SyncCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(commandName: "sync", abstract: "Push pending edits, pull remote changes.")
    @OptionGroup var global: Global
    @Flag(help: "Do not unlock first: conflicts that need decrypting are deferred.") var locked = false
    func run() async throws {
        let vault = try await global.vault(unlock: !locked)
        say(describe(try await vault.sync()))
    }
}

struct Devices: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "List devices known to the server.")
    @OptionGroup var global: Global
    func run() async throws {
        let vault = try await global.vault(unlock: false)
        let me = try await vault.identity()?.deviceID
        for d in try await vault.devices() {
            say("\(d.id)  \(d.name)  \(d.kind)\(d.isRevoked ? "  REVOKED" : "")\(d.id == me ? "  (this device)" : "")")
        }
    }
}

struct Enroll: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Add a second device.",
                                                    subcommands: [Request.self, Approve.self, Complete.self])
    struct Request: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "NEW device: create keys, write an enrollment request file.")
        @OptionGroup var global: Global
        @Option var server: String
        @Option var name: String = "bisel-dev-2"
        @Option(name: .shortAndLong, help: "Where to write the request JSON.") var out: String
        func run() async throws {
            let vault = try await global.vault(unlock: false)
            let req = try await vault.prepareEnrollment(server: parseURL(server), deviceName: name)
            let enc = JSONEncoder()
            enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            try enc.encode(req).write(to: URL(fileURLWithPath: out))
            say("enrollment request for '\(name)' written to \(out)\nfingerprint: \(req.fingerprint)")
        }
    }
    struct Approve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "ENROLLED device: approve a request file.")
        @OptionGroup var global: Global
        @Argument var file: String
        func run() async throws {
            let req = try JSONDecoder().decode(EnrollmentRequest.self, from: Data(contentsOf: URL(fileURLWithPath: file)))
            say("approving '\(req.name)' fingerprint \(req.fingerprint)")
            try await global.vault().approveEnrollment(req)
            say("approved")
        }
    }
    struct Complete: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "NEW device: fetch the envelope once approved, then first sync.")
        @OptionGroup var global: Global
        func run() async throws {
            let vault = try await global.vault(unlock: false)
            try await vault.completeEnrollment()
            try await vault.unlock()
            say("enrollment complete")
            say(describe(try await vault.sync()))
        }
    }
}

struct Revoke: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Revoke a device (effective immediately on the server).")
    @OptionGroup var global: Global
    @Argument var deviceID: String
    func run() async throws {
        try await global.vault().revoke(deviceID: deviceID)
        say("revoked \(deviceID)")
    }
}

struct Recover: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Fresh store: rebuild from the 24-word phrase.")
    @OptionGroup var global: Global
    @Option var server: String
    @Option var phrase: String
    @Option var name: String = "bisel-dev-recovered"
    func run() async throws {
        let vault = try await global.vault(unlock: false)
        try await vault.recover(server: parseURL(server), phrase: parsePhrase(phrase), deviceName: name)
        say("recovered; new device registered as '\(name)'")
        say(describe(try await vault.sync()))
    }
}

struct RotateRecovery: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Replace the recovery phrase (old phrase stops working).")
    @OptionGroup var global: Global
    func run() async throws {
        let phrase = try await global.vault().rotateRecovery()
        say("NEW RECOVERY PHRASE (shown once):\n\(phrase.text)")
    }
}

struct Backup: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Backup files.", subcommands: [Export.self, Import.self, Inspect.self])
    struct Export: AsyncParsableCommand {
        @OptionGroup var global: Global
        @Argument var file: String
        func run() async throws {
            try await global.vault().exportBackup(to: URL(fileURLWithPath: file))
            say("backup written to \(file)")
        }
    }
    struct Import: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Restore onto a fresh server (bootstraps it with the backup's recovery key).")
        @OptionGroup var global: Global
        @Argument var file: String
        @Option var phrase: String
        @Option var server: String
        @Option var token: String
        @Option var name: String = "bisel-dev-restored"
        func run() async throws {
            let vault = try await global.vault(unlock: false)
            try await vault.importBackup(from: URL(fileURLWithPath: file), phrase: parsePhrase(phrase), server: parseURL(server),
                                         bootstrapToken: token, deviceName: name)
            say("restored \(try await vault.items().items.count) item(s) onto \(server)")
        }
    }
    struct Inspect: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Open a backup offline with the phrase and list titles.")
        @Argument var file: String
        @Option var phrase: String
        func run() async throws {
            let backup = try BackupFile.decode(Data(contentsOf: URL(fileURLWithPath: file)))
            let (vkData, _) = try backup.vaultKey(phrase: parsePhrase(phrase))
            let vk = SymmetricKey(data: vkData)
            for r in backup.records where !r.deleted {
                let item = try ItemCodec.decode(ItemSealer.open(blob: r.blob, id: r.id, rev: r.rev, vaultKey: vk), id: r.id)
                say("\(r.id)  rev \(r.rev)  \(item.title)")
            }
        }
    }
}
