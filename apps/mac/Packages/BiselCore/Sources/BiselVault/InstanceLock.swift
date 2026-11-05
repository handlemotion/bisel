import Darwin
import Foundation

/// An exclusive hold on a file for as long as this process lives: what keeps a second copy of the app off a store that is open.
/// The kernel drops it when the process ends, however it ends, so a crash leaves nothing stale. There is no owner to compare and no
/// file to clean up; the file itself stays.
public final class InstanceLock: Sendable {
    public enum Claim: Sendable {
        case held(InstanceLock)
        /// Another process holds it.
        case taken
        /// The file could not be opened or locked: `errno`, and no answer about who else is running.
        case failed(Int32)
    }

    private let descriptor: Int32

    private init(descriptor: Int32) { self.descriptor = descriptor }

    deinit { close(descriptor) }

    /// Never waits. `O_CLOEXEC` matters: a lock belongs to every descriptor duplicated from this one, so a child that inherited it
    /// (an installer the app started) would go on holding it after the app quit, and the relaunch would find it taken.
    public static func claim(path: String) -> Claim {
        try? FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        let descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { return .failed(errno) }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let code = errno
            close(descriptor)
            return code == EWOULDBLOCK ? .taken : .failed(code)
        }
        return .held(InstanceLock(descriptor: descriptor))
    }
}
