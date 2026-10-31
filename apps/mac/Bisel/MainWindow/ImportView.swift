import SwiftUI
import UniformTypeIdentifiers
import BiselCore

struct ImportView: View {
    let service: VaultService
    @Environment(\.theme) private var theme
    @State private var picking = false
    @State private var fileName: String?
    @State private var outcome: ImportOutcome?
    @State private var error: String?
    @State private var done: String?
    @State private var working = false
    @State private var progress = 0
    @State private var debugPath = ""

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            Caption("1Password (.1pux) or a CSV with logins, notes and one-time codes. Everything is encrypted on this Mac before it syncs. Delete the export file afterwards: it contains your passwords in the clear.")
            HStack {
                Button("Choose file…", systemImage: "doc") { picking = true }.controlSize(.small).accessibilityIdentifier("import-choose")
                if let fileName { Text(DisplayText.clean(fileName)).foregroundStyle(theme.colors.secondaryText.color) }
            }
            #if DEBUG
            // Debug builds only: lets flow tests pick a file without driving the out-of-process open panel.
            TextField("", text: $debugPath, prompt: Text("debug: file path")).textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("import-debug-path").onSubmit { load(URL(fileURLWithPath: debugPath)) }
            #endif
            ErrorLine(text: error)
            if let o = outcome {
                VStack(alignment: .leading, spacing: theme.spacing.s) {
                    Text("Found \(Self.items(o.items.count))").font(theme.font(theme.fonts.detail, weight: .medium)).accessibilityIdentifier("import-summary")
                    Caption(Self.breakdown(o))
                    if !o.skipped.isEmpty {
                        Caption("\(o.skipped.count) skipped:")
                        ForEach(Array(o.skipped.prefix(8).enumerated()), id: \.offset) { _, s in Caption("• " + DisplayText.clean(s)) }
                    }
                }
                Button(working ? "Importing… \(progress)/\(o.items.count)" : "Import \(Self.items(o.items.count))") { run(o) }
                    .buttonStyle(.borderedProminent).disabled(working || o.items.isEmpty).accessibilityIdentifier("import-run")
            }
            if let done { Text(done).foregroundStyle(theme.colors.success.color).accessibilityIdentifier("import-done") }
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [UTType(filenameExtension: "1pux") ?? .zip, .commaSeparatedText, .plainText]) { r in
            guard case .success(let url) = r else { return }
            load(url)
        }
    }

    private static func items(_ n: Int) -> String { n == 1 ? "1 item" : "\(n) items" }

    /// "2 logins · 1 note · 1 with a one-time code", leaving out what is zero.
    private static func breakdown(_ o: ImportOutcome) -> String {
        [(o.logins, "login", "logins"), (o.notes, "note", "notes"), (o.secrets, "secret", "secrets")]
            .filter { $0.0 > 0 }.map { "\($0.0) \($0.0 == 1 ? $0.1 : $0.2)" }
            .appending(o.withTOTP > 0 ? ["\(o.withTOTP) with \(o.withTOTP == 1 ? "a one-time code" : "one-time codes")"] : [])
            .appending(o.passkeys > 0 ? ["\(o.passkeys) with \(o.passkeys == 1 ? "a passkey" : "passkeys")"] : [])
            .joined(separator: " · ")
    }

    private func load(_ url: URL) {
        error = nil; done = nil; outcome = nil; fileName = url.lastPathComponent
        guard let format = ImportFormat(url: url) else { error = "Unsupported file type (use .1pux or .csv)"; return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do { outcome = try format.parse(url: url) } catch { self.error = error.localizedDescription }
    }

    private func run(_ o: ImportOutcome) {
        working = true; progress = 0
        Task {
            defer { working = false }
            do {
                try await service.saveMany(o.items) { progress = $0 }
                done = "Imported \(Self.items(o.items.count))."
                outcome = nil
            } catch { self.error = describe(error) }
        }
    }
}

private extension Array {
    func appending(_ more: [Element]) -> [Element] { self + more }
}
