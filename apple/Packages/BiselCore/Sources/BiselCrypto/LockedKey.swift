import Foundation
import CryptoKit

/// Holds key bytes in a page-locked (`mlock`) allocation that is zeroed on `zero()` / deinit.
/// CryptoKit's `SymmetricKey` copies are transient, created only inside `withKey`.
public final class LockedKey: @unchecked Sendable {
    private let pointer: UnsafeMutableRawPointer
    private let count: Int
    private let lock = NSLock()
    private var live = true

    public init(_ key: Data) {
        count = key.count
        pointer = UnsafeMutableRawPointer.allocate(byteCount: max(key.count, 1), alignment: 16)
        _ = mlock(pointer, count)          // best effort; failure only means the page may be swappable
        key.withUnsafeBytes { pointer.copyMemory(from: $0.baseAddress!, byteCount: count) }
    }

    public var isLive: Bool { lock.withLock { live } }

    public func withKey<T>(_ body: (SymmetricKey) throws -> T) throws -> T {
        try lock.withLock {
            guard live else { throw BiselCryptoError.authenticationFailed }
            return try body(SymmetricKey(data: UnsafeRawBufferPointer(start: pointer, count: count)))
        }
    }

    public func rawBytes() throws -> Data {
        try lock.withLock {
            guard live else { throw BiselCryptoError.authenticationFailed }
            return Data(bytes: pointer, count: count)
        }
    }

    public func zero() {
        lock.withLock {
            guard live else { return }
            memset_s(pointer, count, 0, count)
            munlock(pointer, count)
            live = false
        }
    }

    deinit {
        if live {
            memset_s(pointer, count, 0, count)
            munlock(pointer, count)
        }
        pointer.deallocate()
    }
}
