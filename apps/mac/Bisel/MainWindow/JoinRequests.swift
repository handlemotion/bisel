import SwiftUI
import BiselCore

/// Settings → Sync on an iCloud box: requests from a new Mac (or iPhone) on the same Apple Account to join, and the approval with
/// its 8 words (LANES.md, "Enrollment over iCloud"). Nothing is ever approved without the person typing the words.
struct JoinRequestsCard: View {
    let service: VaultService
    @State private var requests: [PendingEnrollment] = []
    @State private var approving: PendingEnrollment?
    @State private var hidden: Set<String> = []
    @Environment(\.theme) private var theme

    /// While the page is open, look for new requests this often (a sync, then the lane's pending list).
    private static let poll: Duration = .seconds(8)

    var body: some View {
        SettingsCard(title: "Add a device") {
            let shown = requests.filter { !hidden.contains($0.id) }.sorted { $0.receivedAt > $1.receivedAt }
            if shown.isEmpty {
                Caption("On the new Mac, choose Add this Mac. Its request shows up here, and you approve it with the 8 words it shows.")
            }
            ForEach(shown) { r in
                SettingsRow(label: DisplayText.clean(r.request.name)) {
                    if r.isExpired {
                        Button("Dismiss") { hidden.insert(r.id) }.controlSize(.small)
                    } else {
                        Button("Approve…") { approving = r }.controlSize(.small).accessibilityIdentifier("join-approve")
                    }
                }
                Caption(r.isExpired ? "Expired. Start again on the new device." : "Asked \(r.receivedAt.formatted(.relative(presentation: .named))).")
            }
        }
        .task(id: service.isOnICloud) {
            guard service.isOnICloud else { return }
            while !Task.isCancelled {
                await service.sync(reason: "join requests")
                requests = await service.pendingEnrollments()
                try? await Task.sleep(for: Self.poll)
            }
        }
        .sheet(item: $approving) { r in
            ApproveJoinSheet(service: service, pending: r) {
                approving = nil
                hidden.insert(r.id)
            }
            .themedPage(ThemeStore.shared.current)
        }
    }
}

private struct ApproveJoinSheet: View {
    let service: VaultService
    let pending: PendingEnrollment
    let done: () -> Void
    @State private var words = ""
    @State private var error: String?
    @State private var working = false
    @State private var code: String?
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            if let code {
                Text("Type this code on “\(name)”").font(theme.font(theme.fonts.title, weight: .semibold))
                Text(code).font(.system(size: theme.fonts.detailTitle, design: .monospaced)).textSelection(.enabled)
                    .accessibilityIdentifier("join-code")
                Caption("The new device checks it against its own copy of the box key. If it says the codes don't match, revoke it in Devices.")
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("Done", action: done).buttonStyle(PillButtonStyle()).keyboardShortcut(.defaultAction)
                }
            } else {
                Text("Approve “\(name)”?").font(theme.font(theme.fonts.title, weight: .semibold))
                Caption("Type the 8 words the new device shows. Check that it shows the same fingerprint. Approving gives it your whole box.")
                    .fixedSize(horizontal: false, vertical: true)
                SettingsRow(label: "Fingerprint") {
                    Text(pending.request.fingerprint).font(.system(size: theme.fonts.caption, design: .monospaced)).textSelection(.enabled)
                }
                TextField("", text: $words, prompt: Text("8 words"), axis: .vertical)
                    .lineLimit(2...3)
                    .onboardingField(theme, text: words)
                    .autocorrectionDisabled()
                    .accessibilityIdentifier("join-words")
                    .onSubmit(approve)
                ErrorLine(text: error)
                HStack {
                    Spacer()
                    Button("Cancel", action: done).buttonStyle(PillButtonStyle(primary: false)).keyboardShortcut(.cancelAction)
                    Button(working ? "Approving…" : "Approve", action: approve)
                        .buttonStyle(PillButtonStyle())
                        .disabled(working || typed.count != 8)
                        .accessibilityIdentifier("join-confirm")
                }
            }
        }
        .padding(theme.spacing.l)
        .frame(width: 420)
    }

    private var name: String { DisplayText.clean(pending.request.name) }
    private var typed: [String] { words.split(whereSeparator: { $0.isWhitespace || $0 == "," }).map(String.init) }

    private func approve() {
        guard !working, typed.count == 8 else { return }
        working = true; error = nil
        Task {
            defer { working = false }
            do {
                try await service.approve(pending, words: typed)
                code = try await service.verificationCode()
            } catch BiselCryptoError.invalidPairingSecret {
                error = "Those aren't the 8 words. Check each one against the new device."
            } catch EnrollmentError.pairingMismatch {
                error = "These words don't match this request, so nothing was approved. If you typed them right, the request was changed on the way: cancel it on the new device and start again."
            } catch EnrollmentError.expired {
                error = "This request expired. Start again on the new device."
            } catch RotationError.vaultKeyRotated {
                error = "The box key just changed. Approve again."
            } catch {
                self.error = describe(error)
            }
        }
    }
}
