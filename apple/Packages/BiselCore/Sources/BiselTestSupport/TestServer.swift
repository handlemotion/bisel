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
    public static func with<T>(_ body: (TestServer) async throws -> T) async throws -> T {
        let server = try await TestServer.start()
        do {
            let result = try await body(server)
            server.stop()
            return result
        } catch {
            server.stop()
            throw error
        }
    }

    public static func start(serverDirectory: String? = nil) async throws -> TestServer {
        let dir = serverDirectory ?? ProcessInfo.processInfo.environment["BISEL_SERVER_DIR"] ?? defaultServerDirectory()
        guard FileManager.default.fileExists(atPath: dir + "/wrangler.jsonc") else { throw Failure.serverDirectoryMissing(dir) }
        let state = FileManager.default.temporaryDirectory.appendingPathComponent("bisel-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
        let port = try freePort(), inspector = try freePort()
        let log = state.appendingPathComponent("server.log")
        FileManager.default.createFile(atPath: log.path, contents: nil)

        // A login shell so pnpm/node from mise/nvm/homebrew are on PATH.
        let script = """
        cd '\(dir)' && pnpm exec wrangler d1 migrations apply bisel --local --persist-to '\(state.path)' >/dev/null 2>&1 \
        && exec pnpm exec wrangler dev --port \(port) --inspector-port \(inspector) --persist-to '\(state.path)'
        """
        let p = Process()
        // setsid() makes the child a process-group leader so `stop()` can take down pnpm, node and workerd together.
        p.executableURL = URL(fileURLWithPath: "/usr/bin/perl")
        p.arguments = ["-e", "use POSIX; POSIX::setsid(); exec @ARGV", "/bin/zsh", "-lc", script]
        let handle = try FileHandle(forWritingTo: log)
        p.standardOutput = handle
        p.standardError = handle
        try p.run()

        let server = TestServer(url: URL(string: "http://localhost:\(port)")!, process: p, state: state, log: log)
        for _ in 0..<240 {
            if !p.isRunning { break }
            if await server.responds() { return server }
            try await Task.sleep(for: .milliseconds(250))
        }
        let text = (try? String(contentsOf: log, encoding: .utf8)) ?? ""
        server.stop()
        throw Failure.didNotStart(text)
    }

    private init(url: URL, process: Process, state: URL, log: URL) {
        self.url = url; self.process = process; self.stateDirectory = state; self.logURL = log
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
