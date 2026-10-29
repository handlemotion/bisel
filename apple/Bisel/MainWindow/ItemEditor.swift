import SwiftUI
import BiselCore

/// Editable copy of an item. Anything the editor doesn't expose (passkey blob, creation date) is carried through.
struct ItemDraft: Identifiable {
    let id = UUID()
    var itemID = ""
    var type: ItemType = .login
    var title = ""
    var urlsText = ""
    var username = ""
    var password = ""
    var totpInput = ""
    var tagsText = ""
    var notes = ""
    var fields: [CustomField] = []
    var createdAt = Date()
    var passkey: JSONValue?
    var existingTOTP: TOTPParameters?

    init(type: ItemType = .login) { self.type = type }

    init(_ item: Item) {
        itemID = item.id; type = item.type; title = item.title; urlsText = item.urls.joined(separator: "\n")
        username = item.username ?? ""; password = item.password ?? ""; totpInput = item.totp?.secret ?? ""
        tagsText = item.tags.joined(separator: ", "); notes = item.notes ?? ""; fields = item.fields
        createdAt = item.createdAt; passkey = item.passkey; existingTOTP = item.totp
    }

    var isNew: Bool { itemID.isEmpty }

    /// nil input = no TOTP; throws-by-nil when the input is not usable.
    func totp() -> (ok: Bool, params: TOTPParameters?) {
        let t = totpInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return (true, nil) }
        guard let parsed = OTPAuth.parse(t) else { return (false, nil) }
        if !t.lowercased().hasPrefix("otpauth://"), let ex = existingTOTP, ex.secret == t { return (true, ex) }
        return (true, parsed.params)
    }

    func build() -> Item {
        func opt(_ s: String) -> String? { s.isEmpty ? nil : s }
        let urls = urlsText.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let tags = tagsText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        return Item(id: itemID, type: type, title: title.trimmingCharacters(in: .whitespaces), urls: urls,
                    username: type == .login ? opt(username) : nil, password: type == .note ? nil : opt(password),
                    totp: type == .login ? totp().params : nil, notes: opt(notes),
                    fields: fields.filter { !$0.label.isEmpty || !$0.value.isEmpty }, tags: tags,
                    createdAt: createdAt, updatedAt: Date(), passkey: passkey)
    }
}

struct ItemEditor: View {
    @State var draft: ItemDraft
    let service: VaultService
    var onSaved: (Item) -> Void
    var onCancel: () -> Void
    @Environment(\.theme) private var theme
    @State private var showPassword = false
    @State private var showGenerator = false
    @State private var error: String?
    @State private var saving = false

    var body: some View {
        VStack(spacing: 0) {
            Form {
                if draft.isNew {
                    Picker("Type", selection: $draft.type) {
                        Text("Login").tag(ItemType.login); Text("Secure note").tag(ItemType.note); Text("Secret").tag(ItemType.secret)
                    }.pickerStyle(.segmented).accessibilityIdentifier("editor-type")
                }
                Section {
                    TextField("Title", text: $draft.title).accessibilityIdentifier("editor-title")
                    if draft.type != .note {
                        VStack(alignment: .leading) {
                            Text("Websites (one per line)").font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.secondaryText.color)
                            TextEditor(text: $draft.urlsText).frame(height: 44).scrollContentBackground(.hidden)
                                .accessibilityIdentifier("editor-urls")
                        }
                    }
                }
                if draft.type == .login {
                    Section("Sign-in") {
                        TextField("Username", text: $draft.username).accessibilityIdentifier("editor-username")
                        passwordRow
                    }
                    Section("One-time code") {
                        TextField("Secret key or otpauth:// link", text: $draft.totpInput).accessibilityIdentifier("editor-totp")
                        totpPreview
                    }
                } else if draft.type == .secret {
                    Section("Value") { passwordRow }
                }
                Section("Notes") {
                    TextEditor(text: $draft.notes).frame(minHeight: draft.type == .note ? 160 : 60)
                        .scrollContentBackground(.hidden).accessibilityIdentifier("editor-notes")
                }
                if draft.type != .note {
                    Section("Custom fields") {
                        ForEach($draft.fields.indices, id: \.self) { i in
                            HStack {
                                TextField("Label", text: $draft.fields[i].label)
                                if draft.fields[i].secret { SecureField("Value", text: $draft.fields[i].value) }
                                else { TextField("Value", text: $draft.fields[i].value) }
                                Toggle("Secret", isOn: $draft.fields[i].secret).toggleStyle(.checkbox)
                                Button(role: .destructive) { draft.fields.remove(at: i) } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                            }
                        }
                        Button("Add field", systemImage: "plus") { draft.fields.append(CustomField(label: "", value: "")) }
                    }
                }
                Section("Tags") { TextField("Comma separated", text: $draft.tagsText).accessibilityIdentifier("editor-tags") }
                if draft.passkey != nil {
                    Section { Label("A passkey is stored with this item and is kept as is. Sign-in with passkeys isn't supported yet.", systemImage: "person.badge.key") }
                }
            }
            .formStyle(.grouped).scrollContentBackground(.hidden)
            Divider()
            HStack {
                ErrorLine(text: error)
                Spacer()
                Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction).accessibilityIdentifier("editor-cancel")
                Button(draft.isNew ? "Add" : "Save", action: save)
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(saving || draft.title.trimmingCharacters(in: .whitespaces).isEmpty).accessibilityIdentifier("editor-save")
            }
            .padding(theme.spacing.m)
        }
        .frame(width: 560, height: 640)
        .themedPage(theme)
        .hiddenFromCapture()
    }

    private var passwordRow: some View {
        HStack {
            Group {
                if showPassword { TextField(draft.type == .secret ? "Value" : "Password", text: $draft.password) }
                else { SecureField(draft.type == .secret ? "Value" : "Password", text: $draft.password) }
            }.accessibilityIdentifier("editor-password")
            Button { showPassword.toggle() } label: { Image(systemName: showPassword ? "eye.slash" : "eye") }.buttonStyle(.borderless)
            Button { showGenerator = true } label: { Image(systemName: "wand.and.stars") }.buttonStyle(.borderless)
                .help("Generate a password").accessibilityIdentifier("editor-generate")
                .popover(isPresented: $showGenerator) {
                    GeneratorView { draft.password = $0; showGenerator = false; showPassword = true }
                        .padding(theme.spacing.l).frame(width: 340).themedPage(theme).hiddenFromCapture()
                }
        }
    }

    @ViewBuilder private var totpPreview: some View {
        let t = draft.totp()
        if let p = t.params {
            TimelineView(.periodic(from: .now, by: 1)) { _ in
                if let c = try? TOTPGenerator.code(p) {
                    Text("Current code: \(c.code)  ·  \(c.secondsRemaining) s").font(theme.font(theme.fonts.caption).monospacedDigit())
                        .foregroundStyle(theme.colors.secondaryText.color)
                }
            }
        } else if !t.ok {
            Text("Not a valid secret or otpauth:// link").font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.danger.color)
        }
    }

    private func save() {
        guard draft.totp().ok else { error = "The one-time code secret isn't valid"; return }
        error = nil; saving = true
        let item = draft.build()
        Task {
            defer { saving = false }
            do { onSaved(try await service.save(item)) }
            catch KeyStoreError.userCancelled { error = "Touch ID cancelled, nothing was changed" }
            catch { self.error = describe(error) }
        }
    }
}
