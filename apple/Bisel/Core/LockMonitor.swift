import AppKit

/// Locks the vault on sleep, screen lock, fast-user-switch, system idle, and when the fill window (counted from
/// unlock) runs out (SPEC §4 "Unlock model" step 2).
@MainActor
final class LockMonitor {
    private unowned let service: VaultService
    private var timer: Timer?
    private var tokens: [(NotificationCenter, NSObjectProtocol)] = []

    init(service: VaultService) { self.service = service }

    func start() {
        let ws = NSWorkspace.shared.notificationCenter
        let dist = DistributedNotificationCenter.default()
        observe(ws, NSWorkspace.willSleepNotification, "sleep")
        observe(ws, NSWorkspace.screensDidSleepNotification, "screens asleep")
        observe(ws, NSWorkspace.sessionDidResignActiveNotification, "session switched out")
        observe(dist, Notification.Name("com.apple.screenIsLocked"), "screen locked")
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
    }

    private func observe(_ center: NotificationCenter, _ name: Notification.Name, _ reason: String) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.service.lock(reason: reason) }
        }
        tokens.append((center, token))
    }

    private func tick() {
        guard service.isUnlocked, let since = service.unlockedAt else { return }
        let window = Double(VaultService.fillWindowMinutes) * 60
        if Date().timeIntervalSince(since) >= window { service.lock(reason: "fill window over"); return }
        let idleLimit = Double(VaultService.idleLockMinutes) * 60
        let idle = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: ~0)!)
        if idle >= idleLimit { service.lock(reason: "idle") }
    }
}
