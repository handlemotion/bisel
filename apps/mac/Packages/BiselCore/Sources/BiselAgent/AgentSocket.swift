#if os(macOS)
import Darwin
import Foundation

/// One request and one answer per connection, as a length-prefixed JSON frame, over a socket only this user can reach.
public enum AgentSocket {
    /// The app answers for at most this long: a 60 s prompt, then the work.
    static let clientTimeout: Int = 75
    static let serverTimeout: Int = 5
    static let maxFrame = 1 << 20

    /// In the account's real home, not `$HOME`, which the caller of the tool controls.
    public static func path(name: String) -> String {
        directory + "/" + name + ".sock"
    }

    static var directory: String { supportDirectory + "/agent" }

    /// `bisel` in Application Support of the account's real home.
    public static var supportDirectory: String {
        let home = getpwuid(getuid()).flatMap { $0.pointee.pw_dir.map { String(cString: $0) } } ?? NSHomeDirectory()
        return home + "/Library/Application Support/bisel"
    }

    /// Sends one request. `serverRequirement` nil skips the signature check (Debug only, the caller decides).
    public static func send(_ request: AgentRequest, path: String, serverRequirement: String?) throws(AgentError) -> AgentResult {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw AgentError(.failed) }
        defer { close(fd) }
        configure(fd, timeout: clientTimeout)
        guard var address = address(path) else { throw AgentError(.failed) }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { throw AgentError(.appNotRunning) }
        if let serverRequirement, !AgentPeer.satisfies(serverRequirement, fd: fd) { throw AgentError(.untrustedApp) }
        guard let body = try? JSONEncoder().encode(request), writeFrame(fd, body) else { throw AgentError(.failed) }
        let frame: Data?
        do { frame = try readFrame(fd) } catch { throw AgentError(.timeout) }
        guard let frame, let result = try? JSONDecoder().decode(AgentResult.self, from: frame) else { throw AgentError(.failed) }
        return result
    }

    static func address(_ path: String) -> sockaddr_un? {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        return address
    }

    static func configure(_ fd: Int32, timeout seconds: Int) {
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var limit = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
    }

    static func writeFrame(_ fd: Int32, _ body: Data) -> Bool {
        guard body.count <= maxFrame else { return false }
        var length = UInt32(body.count).bigEndian
        var frame = withUnsafeBytes(of: &length) { Data($0) }
        frame.append(body)
        return frame.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = write(fd, raw.baseAddress! + sent, raw.count - sent)
                if n < 0, errno == EINTR { continue }
                guard n > 0 else { return false }
                sent += n
            }
            return true
        }
    }

    struct ReadTimedOut: Error {}

    /// nil when the peer closed or the frame is malformed.
    static func readFrame(_ fd: Int32) throws -> Data? {
        guard let header = try readExactly(fd, 4) else { return nil }
        let length = header.reduce(0) { $0 << 8 | Int($1) }
        guard length <= maxFrame else { return nil }
        return try readExactly(fd, length)
    }

    private static func readExactly(_ fd: Int32, _ count: Int) throws -> Data? {
        var data = Data(count: count)
        var got = 0
        while got < count {
            let n = data.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, count - got) }
            if n < 0, errno == EINTR { continue }
            if n < 0, errno == EAGAIN { throw ReadTimedOut() }
            guard n > 0 else { return nil }
            got += n
        }
        return data
    }
}

/// The app's end. Checks the caller's signature before reading a byte of its request.
public final class AgentListener: Sendable {
    public typealias Handler = @Sendable (AgentRequest) async -> AgentResult

    private let path: String
    private let clientRequirement: String?
    private let handler: Handler

    /// `clientRequirement` nil skips the signature check (Debug only, the caller decides).
    public init(path: String, clientRequirement: String?, handler: @escaping Handler) {
        self.path = path; self.clientRequirement = clientRequirement; self.handler = handler
    }

    public func start() throws(AgentError) {
        let directory = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        var info = stat()
        guard chmod(directory, 0o700) == 0, lstat(directory, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid() else {
            throw AgentError(.failed)
        }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0, var address = AgentSocket.address(path) else { throw AgentError(.failed) }
        unlink(path)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, chmod(path, 0o600) == 0, listen(fd, 8) == 0 else {
            close(fd)
            throw AgentError(.failed)
        }
        let thread = Thread { [self] in acceptLoop(fd) }
        thread.name = "bisel.agent.accept"
        thread.start()
    }

    private func acceptLoop(_ listener: Int32) {
        while true {
            let fd = accept(listener, nil, nil)
            if fd < 0 {
                if errno == EINTR || errno == ECONNABORTED { continue }
                return
            }
            DispatchQueue.global(qos: .userInitiated).async { [self] in serve(fd) }
        }
    }

    private func serve(_ fd: Int32) {
        AgentSocket.configure(fd, timeout: AgentSocket.serverTimeout)
        if let clientRequirement, !AgentPeer.satisfies(clientRequirement, fd: fd) { close(fd); return }
        guard let frame = try? AgentSocket.readFrame(fd), let request = try? JSONDecoder().decode(AgentRequest.self, from: frame) else {
            close(fd)
            return
        }
        let handler = handler
        Task {
            let result = await handler(request)
            if let body = try? JSONEncoder().encode(result) { _ = AgentSocket.writeFrame(fd, body) }
            close(fd)
        }
    }
}
#endif
