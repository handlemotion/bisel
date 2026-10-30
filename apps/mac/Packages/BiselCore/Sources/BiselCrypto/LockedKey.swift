import Foundation
import CryptoKit

/// Holds key bytes in a page-locked (`mlock`) allocation that is zeroed on `zero()` / deinit.
/// CryptoKit's `SymmetricKey` copies are transient, created only inside `withKey`. `rawBytes()` hands out a
/// `Data` copy that the caller must `zeroize()`.
public final class LockedKey: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "LockedKey(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: []) }

    private let pointer: UnsafeMutableRawPointer
    private let count: Int
    private let mapped: Int
    private let lock = NSLock()
    private var live = true

    public init(_ key: Data) {
        count = key.count
        // Each key gets its own anonymous page(s), so `mlock`/`munlock` and the wipe never touch another key's memory
        // (a shared heap page would be unlocked while a neighbour still needs it).
        mapped = Int(getpagesize()) * max(1, (key.count + Int(getpagesize()) - 1) / Int(getpagesize()))
        guard let region = mmap(nil, mapped, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0), region != MAP_FAILED else {
            preconditionFailure("mmap failed")   // cannot hold a key safely; refusing is better than falling back to the heap
        }
        pointer = region
        _ = mlock(pointer, mapped)         // best effort; failure only means the page may be swappable
        key.withUnsafeBytes { source in
            if let base = source.baseAddress, count > 0 { pointer.copyMemory(from: base, byteCount: count) }
        }
    }

    public var isLive: Bool { lock.withLock { live } }

    public func withKey<T>(_ body: (SymmetricKey) throws -> T) throws -> T {
        try lock.withLock {
            guard live else { throw BiselCryptoError.authenticationFailed }
            return try body(SymmetricKey(data: UnsafeRawBufferPointer(start: pointer, count: count)))
        }
    }

    /// Predicate helper: false if the key is already zeroed.
    public func withKeyOrFalse(_ body: (SymmetricKey) -> Bool) -> Bool { (try? withKey(body)) ?? false }

    public func rawBytes() throws -> Data {
        try lock.withLock {
            guard live else { throw BiselCryptoError.authenticationFailed }
            return Data(bytes: pointer, count: count)
        }
    }

    public func zero() {
        lock.withLock {
            guard live else { return }
            memset_s(pointer, mapped, 0, mapped)
            munlock(pointer, mapped)
            live = false
        }
    }

    deinit {
        memset_s(pointer, mapped, 0, mapped)
        munlock(pointer, mapped)
        munmap(pointer, mapped)
    }
}
