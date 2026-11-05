import AppKit
import BiselCore

/// One production Bisel per account. LaunchServices reuses a running app only for the same path, so a copy at another path, or a
/// binary started directly, would otherwise open the same store and fight over the hotkey and the agent socket. Debug builds never
/// call this: they run next to the installed app on purpose, and take no lock, so they never stop it from starting.
@MainActor
enum SingleInstance {
    private static let bringForward = Notification.Name("app.bisel.mac.bringForward")

    /// How long a new process waits for one that is on its way out. Sparkle relaunches only after the old process is gone, so an
    /// update needs no wait; this covers quitting and reopening at once, and a slow exit.
    private static let exitWait: Duration = .seconds(5)

    /// In the account's real home like the agent socket, so a changed `$HOME` does not get a second copy past it, and beside the
    /// `vault` folder rather than in it.
    private static var lockPath: String { AgentSocket.supportDirectory + "/instance.lock" }

    /// Kept for the life of the process.
    private static var lock: InstanceLock?

    /// Runs first, before the store, the hotkey or the agent socket exist. Returns as the only instance, or asks the running one to
    /// come forward and quits. A lock that cannot be read at all starts the app anyway: a password manager that silently refuses
    /// to open on an unusual home folder is worse than the case this guards against.
    static func claimOrQuit() {
        let deadline = ContinuousClock.now + exitWait
        var asked = false
        while true {
            switch InstanceLock.claim(path: lockPath) {
            case .held(let held):
                lock = held
                return
            case .failed(let code):
                Log.app.error("instance lock unavailable (errno \(code)); starting without it")
                return
            case .taken:
                if !asked {
                    asked = true
                    Log.app.notice("another Bisel is running; asking it to come forward")
                    // At once, so a real second launch answers right away; wrong only if that instance is exiting, and then the
                    // wait below takes over. Without `deliverImmediately` an inactive app, which a menu bar app nearly always is,
                    // would not hear this until it next became active.
                    DistributedNotificationCenter.default()
                        .postNotificationName(bringForward, object: nil, userInfo: nil, deliverImmediately: true)
                }
                if ContinuousClock.now >= deadline { exit(0) }
                Thread.sleep(forTimeInterval: 0.1)
            }
        }
    }

    /// The running instance's side. Any process of this user can post this; all it can do is open the window.
    static func listen() {
        DistributedNotificationCenter.default().addObserver(forName: bringForward, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { AppModel.shared.showMainWindow() }
        }
    }
}
