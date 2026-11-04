import BiselAgent
import Darwin
import Foundation

/// The child gets these and the secrets, nothing else. A variable such as NODE_OPTIONS, BASH_ENV or DYLD_INSERT_LIBRARIES set by the
/// caller would run code the Touch ID prompt never showed. `bl run -- env NAME=value tool` still works, and shows in the prompt.
private let keptEnvironment = ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SSH_AUTH_SOCK"]

private struct RunPlan {
    var envNames: [String] = []
    var refs: [AgentSecretRef] = []
    var stdinIndex: Int?
    var command: [String] = []
}

private func parse(_ arguments: [String]) -> RunPlan {
    var plan = RunPlan()
    var rest = arguments[...]
    while let argument = rest.popFirst() {
        switch argument {
        case "--":
            plan.command = Array(rest)
            rest = []
        case "--env":
            guard let pair = rest.popFirst(), let split = pair.firstIndex(of: "=") else { fail(.badRequest, hint: "Use --env NAME=<ref>.") }
            let name = String(pair[..<split])
            guard isVariableName(name), let ref = AgentSecretRef(parsing: String(pair[pair.index(after: split)...])) else {
                fail(.badRequest, hint: "Use --env NAME=<ref>. Run bl --help for the form of a ref.")
            }
            plan.envNames.append(name)
            plan.refs.append(ref)
        case "--stdin":
            guard plan.stdinIndex == nil, let text = rest.popFirst(), let ref = AgentSecretRef(parsing: text) else {
                fail(.badRequest, hint: "Use --stdin <ref>, once.")
            }
            plan.refs.append(ref)
            plan.envNames.append("")
            plan.stdinIndex = plan.refs.count - 1
        default:
            fail(.badRequest, hint: "Unknown flag. Put the command after --. Secrets are never passed as arguments.")
        }
    }
    guard !plan.refs.isEmpty, !plan.command.isEmpty else { fail(.badRequest, hint: "Use bl run --stdin <ref> -- <command> or --env NAME=<ref>.") }
    return plan
}

private func isVariableName(_ name: String) -> Bool {
    guard let first = name.unicodeScalars.first, first == "_" || (first.isASCII && first.properties.isAlphabetic) else { return false }
    return name.unicodeScalars.allSatisfy { $0 == "_" || ($0.isASCII && ($0.properties.isAlphabetic || $0.properties.numericType != nil)) }
}

/// The full path, so a changed PATH shows in the prompt.
private func resolve(_ name: String) -> String? {
    var candidates: [String]
    if name.contains("/") {
        candidates = [name.hasPrefix("/") ? name : FileManager.default.currentDirectoryPath + "/" + name]
    } else {
        candidates = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map { "\($0)/\(name)" }
    }
    candidates = candidates.map { ($0 as NSString).standardizingPath }
    return candidates.first {
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: $0, isDirectory: &isDirectory) && !isDirectory.boolValue && access($0, X_OK) == 0
    }
}

func runCommand(_ arguments: [String]) -> Never {
    let plan = parse(arguments)
    guard let path = resolve(plan.command[0]) else { fail(.commandRefused, hint: "That command was not found or cannot run.") }
    let argv = [path] + plan.command.dropFirst()
    guard case .secrets(let secrets) = request(.run(refs: plan.refs, command: argv)), secrets.count == plan.refs.count else { fail(.failed) }

    let inherited = ProcessInfo.processInfo.environment
    var environment = inherited.filter { keptEnvironment.contains($0.key) }
    for (name, secret) in zip(plan.envNames, secrets) where !name.isEmpty {
        guard let value = String(data: secret.bytes, encoding: .utf8) else { fail(.failed) }
        environment[name] = value
    }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = Array(argv.dropFirst())
    process.environment = environment
    let out = Pipe(), err = Pipe()
    process.standardOutput = out
    process.standardError = err
    let input = plan.stdinIndex.map { _ in Pipe() }
    if let input { process.standardInput = input }
    do { try process.run() } catch { fail(.commandRefused, hint: "That command could not start.") }

    // After the launch, so the child keeps the default handlers.
    signal(SIGPIPE, SIG_IGN)
    var forwards: [DispatchSourceSignal] = []
    for number in [SIGINT, SIGTERM, SIGHUP] {
        signal(number, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: number, queue: .global())
        source.setEventHandler { kill(process.processIdentifier, number) }
        source.resume()
        forwards.append(source)
    }

    if let input, let index = plan.stdinIndex {
        let writer = input.fileHandleForWriting
        writeAll(writer.fileDescriptor, Array(secrets[index].bytes))
        try? writer.close()
    }

    let values = secrets.map(\.bytes)
    let readers = DispatchGroup()
    relay(out.fileHandleForReading.fileDescriptor, to: STDOUT_FILENO, masking: values, group: readers)
    relay(err.fileHandleForReading.fileDescriptor, to: STDERR_FILENO, masking: values, group: readers)
    process.waitUntilExit()
    // A background process the command left behind can hold the pipes open; its later output is dropped, never shown unmasked.
    _ = readers.wait(timeout: .now() + 1)
    let status = process.terminationStatus
    exit(process.terminationReason == .uncaughtSignal ? 128 + status : status)
}

private func relay(_ source: Int32, to destination: Int32, masking secrets: [Data], group: DispatchGroup) {
    DispatchQueue.global().async(group: group) {
        var masker = SecretMasker(secrets: secrets)
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while true {
            let n = read(source, &buffer, buffer.count)
            if n < 0, errno == EINTR { continue }
            guard n > 0 else { break }
            writeAll(destination, masker.push(buffer[..<n]))
        }
        writeAll(destination, masker.finish())
    }
}
