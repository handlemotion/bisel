import SwiftUI

/// Small sync indicator for the main window (never in the panel).
struct SyncStatusView: View {
    let service: VaultService
    var compact = false
    @Environment(\.theme) private var theme

    var body: some View {
        HStack(spacing: theme.spacing.s) {
            icon
            TimelineView(.periodic(from: .now, by: 15)) { _ in
                Text(text).font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.secondaryText.color).lineLimit(2)
            }
            .accessibilityIdentifier("sync-status")
            if !compact && service.isUnlocked {
                Spacer(minLength: 0)
                Button { Task { await service.sync(reason: "manual") } } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.borderless).help("Sync now").accessibilityIdentifier("sync-now")
                    .disabled(service.syncState == .syncing)
            }
        }
    }

    @ViewBuilder private var icon: some View {
        switch service.syncState {
        case .syncing: ProgressView().controlSize(.mini)
        case .synced: Image(systemName: "checkmark.icloud").foregroundStyle(theme.colors.success.color)
        case .offline: Image(systemName: "icloud.slash").foregroundStyle(theme.colors.warning.color)
        case .failed: Image(systemName: "exclamationmark.icloud").foregroundStyle(theme.colors.danger.color)
        case .idle: Image(systemName: "icloud").foregroundStyle(theme.colors.tertiaryText.color)
        }
    }

    private var text: String {
        let pending = service.pendingChanges > 0 ? " · \(service.pendingChanges) pending" : ""
        switch service.syncState {
        case .idle: return "Not synced yet" + pending
        case .syncing: return "Syncing…" + pending
        case .synced(let d): return "Synced \(d.formatted(.relative(presentation: .named)))" + pending
        case .offline: return "Offline, changes are kept on this Mac" + pending
        case .failed(let m): return "Sync failed: \(m)" + pending
        }
    }
}
