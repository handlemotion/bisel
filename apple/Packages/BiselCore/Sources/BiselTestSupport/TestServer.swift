import Foundation
import Darwin

/// Starts the real bisel server (`wrangler dev`, local D1 in a throwaway directory) for flow tests.
/// Nothing is deployed and no Cloudflare resource is touched. Dev/test only; the apps do not link this.
public final class TestServer: @unchecked Sendable {
    public static let bootstrapToken = "dev-bootstrap-token"   // server/.dev.vars.example

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
        let state = FileManager.default.temporaryDirectory.appendingPathComponent("bisel-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        let port = try freePort(), inspector = try freePort()
        let log = state.appendingPathComponent("server.log")
        FileManager.default.createFile(atPath: log.path, contents: nil)

        let varArguments = vars.map { "--var '\($0.key):\($0.value)'" }.joined(separator: " ")
        // A login shell so pnpm/node from mise/nvm/homebrew are on PATH. `.dev.vars` is untracked (it holds the dev bootstrap token the
        // tests use), so a fresh clone gets it from the example, as `pnpm dev` does.
        let script = """
        cd '\(dir)' && { [ -f .dev.vars ] || cp .dev.vars.example .dev.vars; } \
        && pnpm exec wrangler d1 migrations apply bisel --local --persist-to '\(state.path)' >/dev/null 2>&1 \
        && exec pnpm exec wrangler dev --port \(port) --inspector-port \(inspector) --persist-to '\(state.path)' \(varArguments)
        """
        let p = Process()
        // setsid() makes the child a process-group leader so `stop()` can take down pnpm, node and workerd together.
        p.executableURL = URL(fileURLWithPath: "/usr/bin/perl")
        p.arguments = ["-e", "use POSIX; POSIX::setsid(); exec @ARGV", "/bin/zsh", "-lc", script]
        let handle = try FileHandle(forWritingTo: log)
        p.standardOutput = handle
        p.standardError = handle
        try p.run()

        let server = TestServer(url: URL(string: "http://localhost:\(port)")!, process: p, state: state, log: log, directory: dir)
        for _ in 0..<240 {
            if !p.isRunning { break }
            if await server.responds() { return server }
            try await Task.sleep(for: .milliseconds(250))
        }
        let text = (try? String(contentsOf: log, encoding: .utf8)) ?? ""
        server.stop()
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
        // wrangler prints a banner first; the JSON starts on a line of its own.
        guard let start = out.range(of: "\n[\n")?.lowerBound ?? (out.hasPrefix("[\n") ? out.startIndex : nil),
              let parsed = try JSONSerialization.jsonObject(with: Data(out[start...].utf8)) as? [[String: Any]],
              let row = (parsed.first?["results"] as? [[String: Any]])?.first, let first = row.values.first, !(first is NSNull) else { return nil }
        return "\(first)"
    }

    /// The id of the only box on this server (a fresh test server has exactly one after the first bootstrap): what a person
    /// would read off the dashboard to restore onto a new Mac.
    public func onlyBoxID() throws -> String {
        guard let id = try value("SELECT id FROM boxes") else { throw Failure.didNotStart("no box on this server yet") }
        return id
    }

    private func run(_ statement: String, json: Bool) throws -> String {
        let escaped = statement.replacingOccurrences(of: "'", with: "'\\''")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/zsh")
        p.arguments = ["-lc", "cd '\(serverDirectory)' && pnpm exec wrangler d1 execute bisel --local --persist-to '\(stateDirectory.path)'\(json ? " --json" : "") --command '\(escaped)'"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
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

    private func responds() async -> Bool {
        var request = URLRequest(url: url.appendingPathComponent("v1/sync"))
        request.timeoutInterval = 1
        return (try? await URLSession.shared.data(for: request)) != nil
    }

    private static func defaultServerDirectory() -> String {
        // …/apple/Packages/BiselCore/Sources/BiselTestSupport/TestServer.swift -> …/server
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("server").path
    }

    private static func freePort() throws -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0 else { throw Failure.didNotStart("could not find a free port") }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &len) }
        }
        return Int(UInt16(bigEndian: addr.sin_port))
    }
}
