import BiselAgent
import Darwin
import Foundation

// `bisel-browser-host`: what Chrome launches for the extension, once per message (docs/SPEC.md §8, "Chrome extension"). It holds no keys
// and opens no store: it reads one message, passes it to the running app, writes the answer and exits. Nothing here logs.
// Chrome's framing: a 32-bit length in native byte order, then the JSON.

func read(_ count: Int) -> Data? {
    var data = Data(count: count)
    var got = 0
    while got < count {
        let n = data.withUnsafeMutableBytes { Darwin.read(STDIN_FILENO, $0.baseAddress! + got, count - got) }
        if n < 0, errno == EINTR { continue }
        guard n > 0 else { return nil }
        got += n
    }
    return data
}

func write(_ body: Data) {
    var length = UInt32(body.count)
    let frame = withUnsafeBytes(of: &length) { Data($0) } + body
    frame.withUnsafeBytes { raw in
        var sent = 0
        while sent < raw.count {
            let n = Darwin.write(STDOUT_FILENO, raw.baseAddress! + sent, raw.count - sent)
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { return }
            sent += n
        }
    }
}

#if DEBUG
let path = BrowserLink.socketPath(debug: true)
let requirement = ProcessInfo.processInfo.environment["BISEL_DEV_AGENT_UNSIGNED"] == "1" ? nil : AgentPeer.appRequirement
#else
let path = BrowserLink.socketPath(debug: false)
let requirement: String? = AgentPeer.appRequirement
#endif

guard let header = read(4) else { exit(0) }
let length = Int(header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
// Too long is answered unread, as a message that does not decode.
let message = length <= BrowserLink.maxMessage ? (read(length) ?? Data()) : Data()
write(BrowserRelay.answer(message, callerOrigin: CommandLine.arguments.dropFirst().first, socketPath: path, serverRequirement: requirement))
