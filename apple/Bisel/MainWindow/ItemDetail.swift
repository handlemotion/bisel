import SwiftUI
import BiselCore

/// Detail of one item in the main window. Honors SPEC §4: relaxed mode (default) reveals/copies inside the fill
/// window without another prompt; "Require Touch ID to reveal or copy" asks for a fresh check every time.
struct ItemDetail: View {
    let row: ItemRow
    let service: VaultService
    var onEdit: (Item) -> Void
    var onDeleted: () -> Void
    @Environment(\.theme) private var theme
    @State private var item: Item?
    @State private var loadError: String?
    @State private var revealed: Set<String> = []
    @State private var copiedKey: String?
    @State private var confirmDelete = false
    @State private var error: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: theme.spacing.l) {
                header
                if let item { content(item) } else if let loadError { ErrorLine(text: loadError) } else { ProgressView().controlSize(.small) }
            }
            .padding(theme.spacing.l)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .task(id: "\(row.id)|\(row.updatedAt.timeIntervalSince1970)") { await load() }
        .confirmationDialog("Delete “\(row.title)”?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) { delete() }.accessibilityIdentifier("delete-confirm")
            Button("Cancel", role: .cancel) {}
        } message: { Text("It is removed from every device on the next sync. This can't be undone.") }
        .onChange(of: service.phase) { _, p in if p != .unlocked { item = nil; revealed = [] } }
    }

    private var header: some View {
        HStack(spacing: theme.spacing.m) {
            SiteIcon(title: row.title, domain: row.domain, size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(row.title).font(theme.font(theme.fonts.detailTitle, weight: .semibold)).accessibilityIdentifier("detail-title")
                Text(typeLabel).font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.secondaryText.color)
            }
            Spacer()
            Button("Edit", systemImage: "pencil") { if let item { onEdit(item) } }.disabled(item == nil).accessibilityIdentifier("detail-edit")
            Button("Delete", systemImage: "trash", role: .destructive) { confirmDelete = true }.accessibilityIdentifier("detail-delete")
        }
    }

    private var typeLabel: String {
        switch row.type { case .login: "Login"; case .note: "Secure note"; case .secret: "Secret"; case .passkey: "Passkey" }
    }

    @ViewBuilder private func content(_ item: Item) -> some View {
        ErrorLine(text: error)
        VStack(spacing: 0) {
            if let u = item.username, !u.isEmpty { valueRow("Username", u, key: "user", secret: false) }
            if let p = item.password, !p.isEmpty { valueRow(item.type == .secret ? "Value" : "Password", p, key: "pass", secret: true) }
            if let t = item.totp { otpRow(t) }
            ForEach(Array(item.urls.enumerated()), id: \.offset) { i, u in
                HStack {
                    label(i == 0 ? "Website" : "")
                    Text(u).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button { open(u) } label: { Image(systemName: "arrow.up.right.square") }.buttonStyle(.borderless).help("Open")
                }.rowStyle()
            }
            ForEach(Array(item.fields.enumerated()), id: \.offset) { i, f in
                valueRow(f.label.isEmpty ? "Field" : f.label, f.value, key: "f\(i)", secret: f.secret)
            }
        }
        .background(RoundedRectangle(cornerRadius: theme.radii.valuesCard).stroke(theme.colors.border.color, lineWidth: theme.card.hairline))
        if let n = item.notes, !n.isEmpty {
            VStack(alignment: .leading, spacing: theme.spacing.xs) {
                Caption("Notes")
                Text(n).textSelection(.disabled).frame(maxWidth: .infinity, alignment: .leading)
                    .accessibilityIdentifier("detail-notes")
                Button("Copy notes", systemImage: "doc.on.doc") { copy(n, key: "notes", secret: true, title: "Notes") }
                    .buttonStyle(.borderless).accessibilityIdentifier("copy-notes")
            }
        }
        if !item.tags.isEmpty { Caption("Tags: " + item.tags.joined(separator: ", ")) }
        if item.passkey != nil { Label("Passkey stored (sign-in comes later)", systemImage: "person.badge.key").font(theme.font(theme.fonts.caption)) }
        Caption("Updated \(item.updatedAt.formatted(date: .abbreviated, time: .shortened))")
    }

    private func label(_ s: String) -> some View {
        Text(s).font(theme.font(theme.fonts.valuesLabel)).foregroundStyle(theme.colors.valueLabel.color).frame(width: 96, alignment: .leading)
    }

    private func valueRow(_ title: String, _ value: String, key: String, secret: Bool) -> some View {
        let shown = !secret || revealed.contains(key)
        return HStack {
            label(title)
            Text(shown ? value : String(repeating: "•", count: min(max(value.count, 8), 20)))
                .font(theme.font(theme.fonts.value).monospaced(secret))
                .textSelection(.disabled).lineLimit(1).truncationMode(.middle)
                .accessibilityIdentifier("value-\(key)")
            Spacer()
            if secret {
                Button { toggleReveal(key, title) } label: { Image(systemName: shown ? "eye.slash" : "eye") }
                    .buttonStyle(.borderless).help(shown ? "Hide" : "Reveal").accessibilityIdentifier("reveal-\(key)")
            }
            Button { copy(value, key: key, secret: secret, title: title) } label: {
                Image(systemName: copiedKey == key ? "checkmark" : "doc.on.doc")
            }.buttonStyle(.borderless).help("Copy").accessibilityIdentifier("copy-\(key)")
        }.rowStyle()
    }

    private func otpRow(_ p: TOTPParameters) -> some View {
        let shown = revealed.contains("otp") || !SecuritySettings.requireTouchID
        return HStack {
            label("One-time code")
            TimelineView(.periodic(from: .now, by: 1)) { _ in
                if let c = try? TOTPGenerator.code(p) {
                    HStack(spacing: theme.spacing.s) {
                        Text(shown ? Self.group(c.code) : "••• •••").font(theme.font(theme.fonts.value, weight: .medium).monospacedDigit())
                            .accessibilityIdentifier("value-otp")
                        Circle().trim(from: 0, to: Double(c.secondsRemaining) / Double(p.period)).stroke(
                            c.secondsRemaining <= max(p.period / 10, 3) ? theme.colors.danger.color : theme.colors.ring.color,
                            style: StrokeStyle(lineWidth: theme.card.ringStroke, lineCap: .round)).rotationEffect(.degrees(-90))
                            .frame(width: theme.card.ringSize * 0.8, height: theme.card.ringSize * 0.8)
                    }
                } else { Text("Invalid secret").foregroundStyle(theme.colors.danger.color) }
            }
            Spacer()
            if SecuritySettings.requireTouchID {
                Button { toggleReveal("otp", "Reveal one-time code") } label: { Image(systemName: shown ? "eye.slash" : "eye") }.buttonStyle(.borderless)
            }
            Button { copyOTP(p) } label: { Image(systemName: copiedKey == "otp" ? "checkmark" : "doc.on.doc") }
                .buttonStyle(.borderless).help("Copy code").accessibilityIdentifier("copy-otp")
        }.rowStyle()
    }

    private static func group(_ code: String) -> String {
        guard code.count == 6 else { return code }
        return code.prefix(3) + " " + code.suffix(3)
    }

    // MARK: actions

    private func load() async {
        loadError = nil
        do { item = try await service.item(id: row.id) }
        catch { loadError = describe(error); item = nil }
    }

    private func toggleReveal(_ key: String, _ reason: String) {
        if revealed.contains(key) { revealed.remove(key); return }
        Task {
            do {
                if SecuritySettings.requireTouchID { try await BiometricGate.authenticate(reason: reason, grantsCredit: false) }
                revealed.insert(key)
                try? await Task.sleep(for: .seconds(30))
                revealed.remove(key)
            } catch { self.error = describe(error) }
        }
    }

    private func copy(_ value: String, key: String, secret: Bool, title: String) {
        Task {
            do {
                if secret && SecuritySettings.requireTouchID { try await BiometricGate.authenticate(reason: "Copy \(title.lowercased())", grantsCredit: false) }
                // Every copy goes through SecureClipboard (concealed, this Mac only, cleared after 30 s), username and notes included.
                SecureClipboard.shared.copySecret(value)
                if service.isUnlocked { service.recordUse(id: row.id) }
                flash(key)
            } catch { self.error = describe(error) }
        }
    }

    private func copyOTP(_ p: TOTPParameters) {
        Task {
            do {
                if SecuritySettings.requireTouchID { try await BiometricGate.authenticate(reason: "Copy one-time code", grantsCredit: false) }
                SecureClipboard.shared.copySecret(try TOTPGenerator.code(p).code)
                flash("otp")
            } catch { self.error = describe(error) }
        }
    }

    private func flash(_ key: String) {
        copiedKey = key
        Task { try? await Task.sleep(for: .milliseconds(900)); if copiedKey == key { copiedKey = nil } }
    }

    private func open(_ s: String) {
        if let why = URLPolicy.openWithPolicy(s) { error = why }
    }

    private func delete() {
        Task {
            do { try await service.delete(id: row.id); onDeleted() }
            catch KeyStoreError.userCancelled { error = "Touch ID cancelled, nothing was deleted" }
            catch { self.error = describe(error) }
        }
    }
}

private extension View {
    func rowStyle() -> some View { modifier(RowStyle()) }
}
private struct RowStyle: ViewModifier {
    @Environment(\.theme) private var theme
    func body(content: Content) -> some View {
        content.padding(.horizontal, theme.spacing.m).frame(minHeight: theme.card.valueRowHeight)
            .overlay(alignment: .bottom) { Rectangle().fill(theme.colors.border.color).frame(height: theme.card.hairline) }
    }
}
