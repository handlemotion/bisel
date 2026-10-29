import Foundation
import Testing
import BiselTestSupport

/// Drives the real `bisel-dev` binary against a real local server: the whole product story through the CLI.
@Suite("bisel-dev CLI flow", .serialized)
struct CLIFlowTests {
    struct Result { let status: Int32; let out: String; let err: String }

    static let binary: URL = {
        // …/Tools/bisel-dev/Tests/BiselDevFlowTests/CLIFlowTests.swift -> …/Tools/bisel-dev/.build/<config>/bisel-dev
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<3 { root.deleteLastPathComponent() }
        for config in ["debug", "release"] {
            let candidate = root.appendingPathComponent(".build/\(config)/bisel-dev")
            if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
        }
        return root.appendingPathComponent(".build/debug/bisel-dev")
    }()

    @discardableResult
    static func run(_ args: [String], expectSuccess: Bool = true) throws -> Result {
        let p = Process()
        p.executableURL = binary
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let o = out.fileHandleForReading.readDataToEndOfFile(), e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let r = Result(status: p.terminationStatus, out: String(decoding: o, as: UTF8.self), err: String(decoding: e, as: UTF8.self))
        if expectSuccess { #expect(r.status == 0, "bisel-dev \(args.joined(separator: " ")) failed: \(r.out) \(r.err)") }
        return r
    }

    @Test("bootstrap, enroll a second device, sync both ways, conflict, revoke, recover from phrase, backup and restore")
    func fullStory() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("bisel-cli-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let home = { (n: String) in ["--home", root.appendingPathComponent(n).path] }
        let token = TestServer.bootstrapToken
        var phrase = ""
        var itemID = ""
        let backupFile = root.appendingPathComponent("v.bisel-backup").path

        try await TestServer.with { server in
            let srv = server.url.absoluteString
            // First device
            let boot = try Self.run(["bootstrap"] + home("a") + ["--server", srv, "--token", token, "--name", "Mac A"])
            phrase = try #require(boot.out.split(separator: "\n").last.map(String.init))
            #expect(phrase.split(separator: " ").count == 24)
            #expect(boot.err.contains("SOFTWARE KEY STORE IN USE"), "software keys must be loud")
            let add = try Self.run(["add"] + home("a") + ["--title", "GitHub", "--username", "rodrigo", "--password", "pw-from-A",
                                                          "--url", "https://github.com"])
            itemID = try #require(add.out.split(separator: " ").dropFirst().first.map(String.init))

            // Second device
            let req = root.appendingPathComponent("b.json").path
            try Self.run(["enroll", "request"] + home("b") + ["--server", srv, "--name", "Mac B", "-o", req])
            try Self.run(["enroll", "approve"] + home("a") + [req])
            try Self.run(["enroll", "complete"] + home("b"))
            let onB = try Self.run(["get"] + home("b") + [itemID, "--reveal", "--json"])
            let json = try #require(try JSONSerialization.jsonObject(with: Data(onB.out.utf8)) as? [String: Any])
            #expect(json["password"] as? String == "pw-from-A")

            // Concurrent edits
            try Self.run(["edit"] + home("a") + [itemID, "--password", "A2", "--no-sync"])
            try Self.run(["edit"] + home("b") + [itemID, "--password", "B2", "--no-sync"])
            try Self.run(["sync"] + home("a"))
            let conflict = try Self.run(["sync"] + home("b"))
            #expect(conflict.out.contains("CONFLICT"))
            let list = try Self.run(["list", "--json"] + home("b"))
            #expect(list.out.contains("GitHub (conflict)"))

            // Revoke B
            let devices = try Self.run(["devices"] + home("a")).out
            let bID = try #require(devices.split(separator: "\n").first { $0.contains("Mac B") }?.split(separator: " ").first.map(String.init))
            try Self.run(["revoke"] + home("a") + [bID])
            let after = try Self.run(["sync"] + home("b"), expectSuccess: false)
            #expect(after.status != 0)
            #expect(after.err.contains("notAuthorized"))

            // Recovery on an empty home
            try Self.run(["recover"] + home("c") + ["--server", srv, "--phrase", phrase])
            #expect(try Self.run(["list"] + home("c")).out.contains("GitHub (conflict)"))
            let bad = try Self.run(["recover"] + home("d") + ["--server", srv, "--phrase", phrase.replacingOccurrences(of: "a", with: "b")], expectSuccess: false)
            #expect(bad.status != 0)

            try Self.run(["backup", "export"] + home("c") + [backupFile])
        }

        // New server, restore from the file.
        try await TestServer.with { server in
            let srv = server.url.absoluteString
            try Self.run(["backup", "import"] + home("f") + [backupFile, "--phrase", phrase, "--server", srv, "--token", token])
            let titles = try Self.run(["list"] + home("f")).out
            #expect(titles.contains("GitHub") && titles.contains("(conflict)"))
            let pw = try Self.run(["get"] + home("f") + [itemID, "--reveal"]).out
            #expect(pw.contains("A2"), "the A edit (remote wins) is what the restore holds")
            // And the same phrase still opens a brand-new install on the restored server.
            try Self.run(["recover"] + home("g") + ["--server", srv, "--phrase", phrase])
        }
    }
}
