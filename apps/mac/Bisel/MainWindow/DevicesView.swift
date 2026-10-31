import SwiftUI
import BiselCore

struct DevicesView: View {
    let service: VaultService
    @Environment(\.theme) private var theme
    @State private var devices: [DeviceInfo] = []
    @State private var loading = false
    @State private var error: String?
    @State private var events: [ServerEvent] = []
    /// One sheet at a time: the revoke confirmation, then the new phrase, then what the revoked device could have read.
    @State private var sheet: DevicesSheet?
    @State private var queued: [DevicesSheet] = []
    @State private var working = false

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
                    VStack(alignment: .trailing, spacing: theme.spacing.s) {
                        Button("Dismiss") { service.dismissAlert(alert.id) }.buttonStyle(.borderless).accessibilityIdentifier("dismiss-alert")
                        if alert.recoveredDeviceID != nil {
                            Button("New phrase and revoke") { Task { await answer(alert) } }
                                .controlSize(.small).disabled(working).accessibilityIdentifier("alert-new-phrase-revoke")
                        }
                    }
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
                        Button(d.isPending() ? "Cancel it" : "Revoke", role: .destructive) { sheet = .confirm(d) }
                            .disabled(working).accessibilityIdentifier("revoke-\(Self.clean(d.name))")
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
        .sheet(item: $sheet, onDismiss: showNext) { shown in
            switch shown {
            case .confirm(let d):
                RevokeConfirmSheet(name: Self.clean(d.name), onICloud: service.isOnICloud) { newPhrase in
                    sheet = nil
                    Task { await revoke(d, newPhrase: newPhrase) }
                } cancel: { sheet = nil }
            case .phrase(let phrase):
                PhraseGateView(service: service, phrase: phrase, title: "Your new recovery phrase") { sheet = nil; service.confirmPhraseStored() }
                    .frame(width: 640, height: 520).themedPage(ThemeStore.shared.current)
            case .report(let report):
                RevokeReportSheet(report: report, onICloud: service.isOnICloud) { sheet = nil }
            }
        }
    }

    /// The next sheet in line, once the one on screen is gone.
    private func showNext() {
        guard sheet == nil, !queued.isEmpty else { return }
        sheet = queued.removeFirst()
    }

    private func present(_ sheets: [DevicesSheet]) {
        queued = sheets
        if sheet == nil { showNext() }
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

    private func revoke(_ d: DeviceInfo, newPhrase: Bool) async {
        working = true; defer { working = false }
        do {
            let report = try await service.revoke(deviceID: d.id)
            let outcome = newPhrase ? await service.replacePhrase(after: report) : RevokeOutcome(report: report, phrase: nil)
            await finished(outcome)
        }
        catch KeyStoreError.userCancelled { error = "Touch ID cancelled, nothing was revoked" }
        catch { self.error = describe(error) }
    }

    /// The alert's one action: revoke the device that recovered with the phrase, then replace the phrase.
    private func answer(_ alert: SecurityAlert) async {
        working = true; defer { working = false }
        do { await finished(try await service.answerRecovery(alert)) }
        catch KeyStoreError.userCancelled { error = "Touch ID cancelled, nothing was revoked" }
        catch { self.error = describe(error) }
    }

    private func finished(_ outcome: RevokeOutcome) async {
        await load()
        error = outcome.phraseError.map { "The device was revoked, but the recovery phrase was not replaced (\($0)). Replace it in Account settings." }
        var next: [DevicesSheet] = []
        if let phrase = outcome.phrase { next.append(.phrase(phrase)) }
        if !outcome.report.secretsToChange.isEmpty || service.isOnICloud { next.append(.report(outcome.report)) }
        present(next)
    }
}

private enum DevicesSheet: Identifiable {
    case confirm(DeviceInfo)
    case phrase(RecoveryPhrase)
    case report(RotationReport)

    var id: String {
        switch self {
        case .confirm(let d): "confirm-\(d.id)"
        case .phrase: "phrase"
        case .report(let r): "report-\(r.epoch)"
        }
    }
}

/// Before a revoke: what it does, the option to replace the recovery phrase too (on by default), and on iCloud, that the device
/// must also leave the Apple Account.
private struct RevokeConfirmSheet: View {
    let name: String
    let onICloud: Bool
    let revoke: (_ newPhrase: Bool) -> Void
    let cancel: () -> Void
    @State private var newPhrase = true
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            Text("Revoke “\(name)”?").font(theme.font(theme.fonts.title, weight: .semibold))
            Caption("It can no longer sync, and the box key is replaced. Anything it already saw stays readable to whoever has that device, so change the passwords of sensitive accounts. Touch ID is required.")
                .fixedSize(horizontal: false, vertical: true)
            if onICloud { AppleAccountNote(name: name) }
            VStack(alignment: .leading, spacing: 2) {
                Toggle("Also replace the recovery phrase", isOn: $newPhrase).toggleStyle(.checkbox)
                    .accessibilityIdentifier("revoke-new-phrase")
                Caption("Until the phrase changes, the revoked device can still make backup files that your phrase opens.")
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel", action: cancel).buttonStyle(PillButtonStyle(primary: false)).keyboardShortcut(.cancelAction)
                Button("Revoke", role: .destructive) { revoke(newPhrase) }
                    .buttonStyle(PillButtonStyle()).accessibilityIdentifier("revoke-confirm")
            }
        }
        .padding(theme.spacing.l)
        .frame(width: 420)
    }
}

/// iCloud has no server to shut a device out: a revoked Mac signed in to the same Apple Account keeps reaching the box's storage
/// until it leaves that account (SECURITY-REVIEW.md C9).
private struct AppleAccountNote: View {
    let name: String
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.s) {
            Caption("“\(name)” is still signed in to your Apple Account, so it can still reach the box in iCloud. Remove it from your Apple Account too.")
                .fixedSize(horizontal: false, vertical: true)
            Button("Open Apple Account Settings") { AppleAccountSettings.openDevices() }
                .controlSize(.small).accessibilityIdentifier("open-apple-account")
        }
    }
}

/// System Settings at the Apple Account's devices, or at least the Apple Account pane.
@MainActor
enum AppleAccountSettings {
    static func openDevices() {
        let urls = ["x-apple.systempreferences:com.apple.systempreferences.AppleIDSettings",
                    "x-apple.systempreferences:com.apple.preferences.AppleIDPrefPane"].compactMap(URL.init(string:))
        for url in urls where NSWorkspace.shared.open(url) { return }
    }
}

/// After a revoke: the device is cut off and the box key replaced, but whatever it already read stays read.
private struct RevokeReportSheet: View {
    let report: RotationReport
    let onICloud: Bool
    let done: () -> Void
    @Environment(\.theme) private var theme

    var body: some View {
        let name = report.revokedDeviceName ?? "The device"
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            if report.secretsToChange.isEmpty {
                Text("Remove it from your Apple Account").font(theme.font(theme.fonts.title, weight: .semibold))
            } else {
                Text("Change these passwords").font(theme.font(theme.fonts.title, weight: .semibold))
                Caption("“\(name)” can no longer sync, but it may have already read these logins. Change them at the sites.")
                List(report.secretsToChange) { item in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.title).font(theme.font(theme.fonts.row, weight: .medium))
                        if let u = item.username, !u.isEmpty { Caption(u) }
                    }
                }
                .frame(minHeight: 160)
            }
            if onICloud { AppleAccountNote(name: name) }
            HStack { Spacer(); Button("Done", action: done).keyboardShortcut(.defaultAction).accessibilityIdentifier("revoke-report-done") }
        }
        .padding(theme.spacing.l)
        .frame(width: 420)
    }
}
