import SwiftUI
import BiselCore

struct DevicesView: View {
    let service: VaultService
    @Environment(\.theme) private var theme
    @State private var devices: [DeviceInfo] = []
    @State private var loading = false
    @State private var error: String?
    @State private var revoking: DeviceInfo?
    @State private var events: [ServerEvent] = []
    @State private var revokeReport: RotationReport?

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            HStack {
                Text("Devices").font(theme.font(theme.fonts.detail, weight: .medium))
                Spacer()
                Button { Task { await load() } } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.borderless).help("Refresh").accessibilityLabel("Refresh").disabled(loading || service.isLocalOnly)
                    .accessibilityIdentifier("devices-refresh")
            }
            ErrorLine(text: error)
            ForEach(service.securityAlerts) { alert in
                HStack(alignment: .top, spacing: theme.spacing.s) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(theme.colors.danger.color)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(alert.text).font(theme.font(theme.fonts.row)).fixedSize(horizontal: false, vertical: true)
                        Caption(alert.date.formatted(date: .abbreviated, time: .shortened))
                    }
                    Spacer()
                    Button("Dismiss") { service.dismissAlert(alert.id) }.buttonStyle(.borderless).accessibilityIdentifier("dismiss-alert")
                }
                .padding(theme.spacing.s)
                .background(RoundedRectangle(cornerRadius: 8).fill(theme.colors.danger.color.opacity(0.12)))
                .accessibilityIdentifier("security-alert")
            }
            if service.recoveryKeyChanged {
                Text("The server’s recovery keys differ from the ones this Mac pinned. They were not adopted and backups are blocked until you have checked this.")
                    .font(theme.font(theme.fonts.row)).foregroundStyle(theme.colors.danger.color)
                    .fixedSize(horizontal: false, vertical: true).accessibilityIdentifier("recovery-changed")
            }
            if service.isLocalOnly {
                Caption("\(service.deviceName) holds the only copy of your box.")
            } else if devices.isEmpty && !loading {
                Caption("No devices yet.")
            }
            ForEach(devices) { d in
                HStack(spacing: theme.spacing.m) {
                    Image(systemName: d.kind == "iphone" ? "iphone" : "laptopcomputer")
                        .foregroundStyle(d.isRevoked ? theme.colors.tertiaryText.color : theme.colors.accent.color)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(Self.clean(d.name)).font(theme.font(theme.fonts.row, weight: .medium))
                            if d.id == service.deviceID { badge("This Mac") }
                            if d.isRevoked { badge("Revoked", danger: true) }
                            if d.isPending() { badge("Held back", danger: true) }
                        }
                        if d.isPending(), let at = d.activatesAt {
                            Caption("Added with the recovery phrase. It cannot sync until \(Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .shortened)). If that was not you, revoke it now.")
                        }
                        Caption("Added \(Date(timeIntervalSince1970: TimeInterval(d.createdAt)).formatted(date: .abbreviated, time: .omitted))"
                                + (d.lastSeenAt.map { " · last seen \(Date(timeIntervalSince1970: TimeInterval($0)).formatted(.relative(presentation: .named)))" } ?? ""))
                    }
                    Spacer()
                    if !d.isRevoked && d.id != service.deviceID {
                        Button(d.isPending() ? "Cancel it" : "Revoke", role: .destructive) { revoking = d }.accessibilityIdentifier("revoke-\(Self.clean(d.name))")
                    }
                }
                .padding(.vertical, 2)
            }
            if !events.isEmpty {
                DisclosureGroup("Recent activity") {
                    ForEach(events.suffix(10).reversed()) { e in
                        Caption("\(e.date.formatted(date: .abbreviated, time: .shortened)) · \(Self.eventText(e))")
                    }
                }
                .font(theme.font(theme.fonts.caption))
            }
            if !service.isLocalOnly { Caption("A revoked device can no longer sync, and the box key is replaced.") }
        }
        .task { await load() }
        .sheet(item: Binding(get: { revokeReport.map(ReportBox.init) }, set: { if $0 == nil { revokeReport = nil } })) { box in
            RevokeReportSheet(report: box.report) { revokeReport = nil }
        }
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

    private static func eventText(_ e: ServerEvent) -> String {
        switch e.type {
        case "bootstrap": "box created"
        case "approve": "a device was approved"
        case "revoke": "a device was revoked"
        case "rotate": "the box key was replaced"
        case "recovery": e.subjectId == nil ? "the recovery phrase was used" : "a device was added with the recovery phrase"
        case "recovery_rotate": "the recovery phrase was replaced"
        default: e.type
        }
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
        events = await service.recentEvents()
    }

    private func revoke(_ d: DeviceInfo) async {
        do {
            let report = try await service.revoke(deviceID: d.id)
            await load()
            if !report.secretsToChange.isEmpty { revokeReport = report }
        }
        catch KeyStoreError.userCancelled { error = "Touch ID cancelled, nothing was revoked" }
        catch { self.error = describe(error) }
    }
}

private struct ReportBox: Identifiable {
    let report: RotationReport
    var id: Int { report.epoch }
}

/// After a revoke: the device is cut off and the box key replaced, but whatever it already read stays read.
private struct RevokeReportSheet: View {
    let report: RotationReport
    let done: () -> Void
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            Text("Change these passwords").font(theme.font(theme.fonts.title, weight: .semibold))
            Caption("“\(report.revokedDeviceName ?? "The device")” can no longer sync, but it may have already read these logins. Change them at the sites.")
            List(report.secretsToChange) { item in
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.title).font(theme.font(theme.fonts.row, weight: .medium))
                    if let u = item.username, !u.isEmpty { Caption(u) }
                }
            }
            .frame(minHeight: 160)
            HStack { Spacer(); Button("Done", action: done).keyboardShortcut(.defaultAction).accessibilityIdentifier("revoke-report-done") }
        }
        .padding(theme.spacing.l)
        .frame(width: 420)
    }
}
