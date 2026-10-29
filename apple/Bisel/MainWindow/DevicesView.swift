import SwiftUI
import BiselCore

struct DevicesView: View {
    let service: VaultService
    @Environment(\.theme) private var theme
    @State private var devices: [DeviceInfo] = []
    @State private var loading = false
    @State private var error: String?
    @State private var revoking: DeviceInfo?

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            HStack {
                Text("Devices").font(theme.font(theme.fonts.title, weight: .semibold))
                Spacer()
                Button("Refresh", systemImage: "arrow.clockwise") { Task { await load() } }.disabled(loading).accessibilityIdentifier("devices-refresh")
            }
            if service.isLocalOnly { Caption("This box is on this Mac only. Connect a server in Settings → Box to add your iPhone or another Mac.") }
            ErrorLine(text: error)
            List(devices) { d in
                HStack(spacing: theme.spacing.m) {
                    Image(systemName: d.kind == "iphone" ? "iphone" : "laptopcomputer")
                        .foregroundStyle(d.isRevoked ? theme.colors.tertiaryText.color : theme.colors.accent.color)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(Self.clean(d.name)).font(theme.font(theme.fonts.row, weight: .medium))
                            if d.id == service.deviceID { badge("This Mac") }
                            if d.isRevoked { badge("Revoked", danger: true) }
                        }
                        Caption("Added \(Date(timeIntervalSince1970: TimeInterval(d.createdAt)).formatted(date: .abbreviated, time: .omitted))"
                                + (d.lastSeenAt.map { " · last seen \(Date(timeIntervalSince1970: TimeInterval($0)).formatted(.relative(presentation: .named)))" } ?? ""))
                    }
                    Spacer()
                    if !d.isRevoked && d.id != service.deviceID {
                        Button("Revoke", role: .destructive) { revoking = d }.accessibilityIdentifier("revoke-\(Self.clean(d.name))")
                    }
                }
                .padding(.vertical, 2)
            }
            .scrollContentBackground(.hidden)
            .overlay {
                if service.isLocalOnly {
                    ContentUnavailableView(service.deviceName, systemImage: "laptopcomputer",
                                           description: Text("This Mac holds the only copy of your box."))
                } else if devices.isEmpty && !loading {
                    ContentUnavailableView("No devices", systemImage: "laptopcomputer")
                }
            }
            Caption("A revoked device is refused by the server immediately. Adding a second Mac or an iPhone comes with the iPhone app.")
        }
        .padding(theme.spacing.l)
        .task { await load() }
        .confirmationDialog("Revoke “\(Self.clean(revoking?.name ?? ""))”?", isPresented: Binding(get: { revoking != nil }, set: { if !$0 { revoking = nil } }),
                            titleVisibility: .visible) {
            Button("Revoke", role: .destructive) { if let d = revoking { Task { await revoke(d) } } }.accessibilityIdentifier("revoke-confirm")
            Button("Cancel", role: .cancel) {}
        } message: { Text("It can no longer sync, and the box key is replaced. Anything it already saw stays readable to whoever has that device, so change the passwords of sensitive accounts. Touch ID is required.") }
    }

    /// Device names come from the server: drop control and bidirectional-override characters before showing them.
    private static func clean(_ name: String) -> String {
        let bad = CharacterSet.controlCharacters.union(CharacterSet(charactersIn: "\u{200E}\u{200F}\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}\u{2067}\u{2068}\u{2069}"))
        return String(name.unicodeScalars.filter { !bad.contains($0) }).trimmingCharacters(in: .whitespaces)
    }

    private func badge(_ t: String, danger: Bool = false) -> some View {
        Text(t).font(theme.font(theme.fonts.caption, weight: .medium))
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(Capsule().fill((danger ? theme.colors.danger.color : theme.colors.badge.color).opacity(danger ? 0.2 : 1)))
            .foregroundStyle(danger ? theme.colors.danger.color : theme.colors.secondaryText.color)
    }

    private func load() async {
        guard !service.isLocalOnly else { devices = []; error = nil; return }
        loading = true; defer { loading = false }
        do { devices = try await service.devices(); error = nil }
        catch { self.error = describe(error) }
    }

    private func revoke(_ d: DeviceInfo) async {
        do { try await service.revoke(deviceID: d.id); await load() }
        catch KeyStoreError.userCancelled { error = "Touch ID cancelled, nothing was revoked" }
        catch { self.error = describe(error) }
    }
}
