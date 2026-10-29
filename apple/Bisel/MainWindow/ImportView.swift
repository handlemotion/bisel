import SwiftUI
import UniformTypeIdentifiers

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
        ScrollView {
            VStack(alignment: .leading, spacing: theme.spacing.l) {
                Text("Import").font(theme.font(theme.fonts.title, weight: .semibold))
                Text("1Password (.1pux) or a CSV with logins, notes and one-time codes. Everything is encrypted on this Mac before it syncs. Delete the export file afterwards: it contains your passwords in the clear.")
                    .font(theme.font(theme.fonts.subtitle)).foregroundStyle(theme.colors.secondaryText.color)
                HStack {
                    Button("Choose file…", systemImage: "doc") { picking = true }.accessibilityIdentifier("import-choose")
                    if let fileName { Text(fileName).foregroundStyle(theme.colors.secondaryText.color) }
                }
                #if DEBUG
                // Debug builds only: lets flow tests pick a file without driving the out-of-process open panel.
                TextField("", text: $debugPath, prompt: Text("debug: file path")).textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("import-debug-path").onSubmit { load(URL(fileURLWithPath: debugPath)) }
                #endif
                ErrorLine(text: error)
                if let o = outcome {
                    VStack(alignment: .leading, spacing: theme.spacing.s) {
                        Text("Found \(o.items.count) item(s)").font(theme.font(theme.fonts.detail, weight: .medium)).accessibilityIdentifier("import-summary")
                        Caption("\(o.logins) logins · \(o.notes) notes · \(o.secrets) secrets · \(o.withTOTP) with one-time codes · \(o.passkeys) with passkeys")
                        if !o.skipped.isEmpty {
                            Caption("\(o.skipped.count) skipped:")
                            ForEach(Array(o.skipped.prefix(8).enumerated()), id: \.offset) { _, s in Caption("• " + s) }
                        }
                    }
                    Button(working ? "Importing… \(progress)/\(o.items.count)" : "Import \(o.items.count) item(s)") { run(o) }
                        .buttonStyle(.borderedProminent).disabled(working || o.items.isEmpty).accessibilityIdentifier("import-run")
                }
                if let done { Text(done).foregroundStyle(theme.colors.success.color).accessibilityIdentifier("import-done") }
            }
            .padding(theme.spacing.l)
            .frame(maxWidth: 640, alignment: .leading)
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [UTType(filenameExtension: "1pux") ?? .zip, .commaSeparatedText, .plainText]) { r in
            guard case .success(let url) = r else { return }
            load(url)
        }
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
                done = "Imported \(o.items.count) item(s)."
                outcome = nil
            } catch { self.error = describe(error) }
        }
    }
}
