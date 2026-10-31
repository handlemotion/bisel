import CryptoKit
import Foundation
import Darwin

/// Starts the real bisel server (`wrangler dev`, local D1 in a throwaway directory) for flow tests.
/// Nothing is deployed and no Cloudflare resource is touched. Dev/test only; the apps do not link this.
public final class TestServer: @unchecked Sendable {
    public static let bootstrapToken = "dev-bootstrap-token"   // apps/server/.dev.vars.example

    public let url: URL
    private let process: Process
    private let stateDirectory: URL
    private let logURL: URL
    private let serverDirectory: String

    public enum Failure: Error, CustomStringConvertible {
        case serverDirectoryMissing(String)
        case didNotStart(String)
        public var description: String {
            switch self {
            case .serverDirectoryMissing(let p): return "server directory not found at \(p) (set BISEL_SERVER_DIR)"
            case .didNotStart(let log): return "server did not start; log:\n\(log)"
            }
        }
    }

    /// Runs `body` against a fresh, un-bootstrapped server and always shuts it down.
    public static func with<T>(vars: [String: String] = [:], _ body: (TestServer) async throws -> T) async throws -> T {
        let server = try await TestServer.start(vars: vars)
        do {
            let result = try await body(server)
            server.stop()
            return result
        } catch {
            server.stop()
            throw error
        }
    }

    /// `vars` are extra Worker variables for this instance, for example `["RECOVERY_ACTIVATION_DELAY_SECONDS": "3"]`.
    public static func start(serverDirectory: String? = nil, vars: [String: String] = [:]) async throws -> TestServer {
        let dir = serverDirectory ?? ProcessInfo.processInfo.environment["BISEL_SERVER_DIR"] ?? defaultServerDirectory()
        guard FileManager.default.fileExists(atPath: dir + "/wrangler.jsonc") else { throw Failure.serverDirectoryMissing(dir) }
        // The database comes from a copy of one migrated state, built once per migrations/wrangler version and shared by every server.
        let state = FileManager.default.temporaryDirectory.appendingPathComponent("bisel-test-\(UUID().uuidString)")
        try FileManager.default.copyItem(at: try await MigratedState.shared.directory(serverDirectory: dir), to: state)
        let log = state.appendingPathComponent("server.log")
        FileManager.default.createFile(atPath: log.path, contents: nil)

        let varArguments = vars.map { "--var '\($0.key):\($0.value)'" }.joined(separator: " ")
        // Port 0 for both: wrangler binds its own free ports and prints the real one ("Ready on http://localhost:PORT"), so there is no
        // window between picking a port and binding it for another server (the flow suites run in parallel) to take it.
        // A login shell so pnpm/node from mise/nvm/homebrew are on PATH.
        let script = "cd '\(dir)' && exec pnpm exec wrangler dev --port 0 --inspector-port 0 --persist-to '\(state.path)' \(varArguments)"
        let p = Process()
        // setsid() makes the child a process-group leader so `stop()` can take down pnpm, node and workerd together.
        p.executableURL = URL(fileURLWithPath: "/usr/bin/perl")
        p.arguments = ["-e", "use POSIX; POSIX::setsid(); exec @ARGV", "/bin/zsh", "-lc", script]
        let handle = try FileHandle(forWritingTo: log)
        p.standardOutput = handle
        p.standardError = handle
        try p.run()

        // Ready is two facts: wrangler says which port it bound, and the Worker answers /healthz 200 (its D1 query ran).
        // Fail at once if the process dies; otherwise wait up to two minutes for a cold, loaded runner.
        let deadline = Date().addingTimeInterval(120)
        var url: URL?
        while p.isRunning && Date() < deadline {
            if url == nil { url = readyURL(inLog: log) }
            if let url, await healthy(url) {
                return TestServer(url: url, process: p, state: state, log: log, directory: dir)
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        let text = (try? String(contentsOf: log, encoding: .utf8)) ?? ""
        TestServer(url: url ?? URL(fileURLWithPath: "/"), process: p, state: state, log: log, directory: dir).stop()
        throw Failure.didNotStart(text)
    }

    private init(url: URL, process: Process, state: URL, log: URL, directory: String) {
        self.url = url; self.process = process; self.stateDirectory = state; self.logURL = log; self.serverDirectory = directory
    }

    /// Runs SQL against this instance's local database, the way a hostile server operator (or a breach) could change it.
    /// Test-only: lets flows tamper with what the server holds and check that clients notice.
    public func sql(_ statement: String) throws { _ = try run(statement, json: false) }

    /// The first column of the first row of a `SELECT` (nil when there is no row), as text.
    public func value(_ statement: String) throws -> String? {
        let out = try run(statement, json: true)
        guard !out.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,   // sqlite3 -json prints nothing for no rows
              let rows = try JSONSerialization.jsonObject(with: Data(out.utf8)) as? [[String: Any]],
              let first = rows.first?.values.first, !(first is NSNull) else { return nil }
        return "\(first)"
    }

    /// The id of the only box on this server (a fresh test server has exactly one after the first bootstrap): what a person
    /// would read off the dashboard to restore onto a new Mac.
    public func onlyBoxID() throws -> String {
        guard let id = try value("SELECT id FROM boxes") else { throw Failure.didNotStart("no box on this server yet") }
        return id
    }

    /// Talks to the database file directly, as a second SQLite connection beside the Worker's own. WAL lets it read while the
    /// Worker writes; a write waits out the Worker's (busy timeout) and takes the write lock up front (`BEGIN IMMEDIATE`), so it
    /// cannot fail halfway with SQLITE_BUSY_SNAPSHOT the way a second `wrangler d1 execute` process did.
    private func run(_ statement: String, json: Bool) throws -> String {
        let database = stateDirectory.appendingPathComponent("v3/d1/miniflare-D1DatabaseObject")
        let files = ((try? FileManager.default.contentsOfDirectory(atPath: database.path)) ?? [])
            .filter { $0.hasSuffix(".sqlite") && $0 != "metadata.sqlite" }
        guard files.count == 1 else { throw Failure.didNotStart("expected one D1 database in \(database.path), found \(files)") }
        let script = json
            ? "PRAGMA foreign_keys = ON;\n\(statement)\n;\n"
            : "PRAGMA foreign_keys = ON;\nBEGIN IMMEDIATE;\n\(statement)\n;\nCOMMIT;\n"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        p.arguments = ["-bail", "-cmd", ".timeout 30000"] + (json ? ["-json"] : []) + [database.appendingPathComponent(files[0]).path]
        let input = Pipe(), out = Pipe()
        p.standardInput = input
        p.standardOutput = out
        p.standardError = out
        try p.run()
        input.fileHandleForWriting.write(Data(script.utf8))
        try input.fileHandleForWriting.close()
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw Failure.didNotStart("sql failed: \(text)") }
        return text
    }

    // MARK: the dashboard's half of device-code connect

    /// What the person does on `/connect?code=…` after signing in as `account` (any string stands in for the user id): the same
    /// updates `src/web.ts` makes on approve. A `create` request becomes `approved`; a `claim` links its box to the account
    /// (`consumed`), or is `denied` when the account already owns a box. Test-only: there is no browser here.
    public func approveConnect(userCode: String, account: String) throws {
        try sql("""
        UPDATE connect_requests SET status = 'approved', account_id = '\(account)' WHERE user_code = '\(userCode)' AND kind = 'create' AND status = 'pending';
        UPDATE connect_requests SET status = 'denied', account_id = '\(account)' WHERE user_code = '\(userCode)' AND kind = 'claim' AND status = 'pending' \
          AND EXISTS (SELECT 1 FROM boxes WHERE owner_id = '\(account)');
        UPDATE boxes SET owner_id = '\(account)' WHERE owner_id IS NULL \
          AND id = (SELECT box_id FROM connect_requests WHERE user_code = '\(userCode)' AND kind = 'claim' AND status = 'pending');
        UPDATE connect_requests SET status = 'consumed', account_id = '\(account)' WHERE user_code = '\(userCode)' AND kind = 'claim' AND status = 'pending' \
          AND EXISTS (SELECT 1 FROM boxes WHERE id = connect_requests.box_id AND owner_id = '\(account)');
        """)
    }

    public func denyConnect(userCode: String, account: String) throws {
        try sql("UPDATE connect_requests SET status = 'denied', account_id = '\(account)' WHERE user_code = '\(userCode)' AND status = 'pending'")
    }

    /// Lets the request's ten minutes run out.
    public func expireConnect(userCode: String) throws {
        try sql("UPDATE connect_requests SET expires_at = 1 WHERE user_code = '\(userCode)'")
    }

    public func stop() {
        if process.isRunning {
            let group = -process.processIdentifier
            kill(group, SIGTERM)
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline { usleep(50_000) }
            kill(group, SIGKILL)
        }
        try? FileManager.default.removeItem(at: stateDirectory)
    }

    public var log: String { (try? String(contentsOf: logURL, encoding: .utf8)) ?? "" }

    /// The port wrangler printed once it was listening.
    private static func readyURL(inLog log: URL) -> URL? {
        guard let text = try? String(contentsOf: log, encoding: .utf8),
              let match = text.firstMatch(of: /Ready on http:\/\/(?:localhost|127\.0\.0\.1):(\d+)/) else { return nil }
        return URL(string: "http://localhost:\(match.1)")
    }

    /// `/healthz` is 200 only when the Worker ran a query against D1.
    private static func healthy(_ url: URL) async -> Bool {
        var request = URLRequest(url: url.appendingPathComponent("healthz"))
        request.timeoutInterval = 2
        guard let (_, response) = try? await URLSession.shared.data(for: request) else { return false }
        return (response as? HTTPURLResponse)?.statusCode == 200
    }

    private static func defaultServerDirectory() -> String {
        // …/apps/mac/Packages/BiselCore/Sources/BiselTestSupport/TestServer.swift -> …/apps/server
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("server").path
    }
}

/// One migrated, empty local D1, built once and copied for every server instead of running `wrangler d1 migrations apply` (about 6 s
/// of cold wrangler each) per server. Keyed on the migrations, the wrangler config and the installed wrangler version, so a change to
/// any of them builds a new one; built beside the final name and renamed into place, so concurrent test processes can share it.
private actor MigratedState {
    static let shared = MigratedState()
    private var builds: [String: Task<URL, Error>] = [:]

    func directory(serverDirectory dir: String) async throws -> URL {
        if let build = builds[dir] { return try await build.value }
        let build = Task { try await Self.build(serverDirectory: dir) }
        builds[dir] = build
        do { return try await build.value } catch { builds[dir] = nil; throw error }
    }

    private static func build(serverDirectory dir: String) async throws -> URL {
        let fm = FileManager.default
        // `.dev.vars` is untracked (it holds the dev bootstrap token the tests use), so a fresh clone gets it from the example, as `pnpm dev` does.
        if !fm.fileExists(atPath: dir + "/.dev.vars") { try fm.copyItem(atPath: dir + "/.dev.vars.example", toPath: dir + "/.dev.vars") }

        var key = SHA256()
        let migrations = try fm.contentsOfDirectory(atPath: dir + "/migrations").sorted()
        for name in migrations { key.update(data: Data(name.utf8)); key.update(data: try Data(contentsOf: URL(fileURLWithPath: dir + "/migrations/" + name))) }
        key.update(data: try Data(contentsOf: URL(fileURLWithPath: dir + "/wrangler.jsonc")))
        key.update(data: (try? Data(contentsOf: URL(fileURLWithPath: dir + "/node_modules/wrangler/package.json"))) ?? Data())
        let name = key.finalize().prefix(8).map { String(format: "%02x", $0) }.joined()
        let final = fm.temporaryDirectory.appendingPathComponent("bisel-test-migrated-\(name)")
        if fm.fileExists(atPath: final.path) { return final }

        let building = fm.temporaryDirectory.appendingPathComponent("bisel-test-migrating-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: building) }
        let (status, output) = try await shell("cd '\(dir)' && pnpm exec wrangler d1 migrations apply bisel --local --persist-to '\(building.path)'")
        guard status == 0 else { throw TestServer.Failure.didNotStart("migrations failed:\n\(output)") }
        // Fold the write-ahead log into the database file so the copy is the database alone.
        for file in try fm.subpathsOfDirectory(atPath: building.path) where file.hasSuffix(".sqlite") {
            let (code, text) = try await run("/usr/bin/sqlite3", [building.appendingPathComponent(file).path, "PRAGMA wal_checkpoint(TRUNCATE);"])
            guard code == 0 else { throw TestServer.Failure.didNotStart("checkpoint failed:\n\(text)") }
            for suffix in ["-wal", "-shm"] { try? fm.removeItem(atPath: building.appendingPathComponent(file + suffix).path) }
        }
        do { try fm.moveItem(at: building, to: final) } catch where fm.fileExists(atPath: final.path) { /* another process won the race */ }
        return final
    }

    private static func shell(_ script: String) async throws -> (Int32, String) { try await run("/bin/zsh", ["-lc", script]) }

    private static func run(_ executable: String, _ arguments: [String]) async throws -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        let finished = Task.detached { () -> (Int32, String) in
            try p.run()
            let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            p.waitUntilExit()
            return (p.terminationStatus, text)
        }
        return try await finished.value
    }
}
