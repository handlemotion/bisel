import AppKit

/// Clipboard rules from SPEC.md §4:
///  - marked with `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` so well-behaved
///    clipboard managers skip the item;
///  - excluded from Universal Clipboard (Handoff to other Apple devices) with
///    `NSPasteboard.prepareForNewContents(with: .currentHostOnly)`  — the public AppKit option
///    `NSPasteboardContentsCurrentHostOnly` ("contents should not be available to other devices");
///  - auto-cleared 30 s after the copy, only if `changeCount` is unchanged since our write.
///
/// IMPORTANT ordering: `.currentHostOnly` is an option of `prepareForNewContents`, it persists only until the
/// next `prepareForNewContents`/`clearContents`, so it must be the call that starts the write, and the
/// data must then be added with `setString/setData` on the SAME pasteboard (not `writeObjects`, which can
/// start a new generation).
@MainActor
final class SecureClipboard {
    static let shared = SecureClipboard()

    static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    static let transientType = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    static let autoClearInterval: Duration = .seconds(30)

    private var clearTask: Task<Void, Never>?
    private var ownedChangeCount: Int?

    private init() {}

    /// Copies `secret` using the rules above. Returns the pasteboard change count of our write.
    @discardableResult
    func copySecret(_ secret: String, autoClear: Bool = true) -> Int {
        let pb = NSPasteboard.general
        pb.prepareForNewContents(with: [.currentHostOnly])
        pb.setString(secret, forType: .string)
        // The marker types carry no payload; their presence is the signal.
        pb.setString("", forType: Self.concealedType)
        pb.setString("", forType: Self.transientType)
        let count = pb.changeCount
        ownedChangeCount = count
        Log.clipboard.debug("secret copied (concealed, current-host-only)")   // not persisted: a log of secret use is a timeline
        if autoClear { scheduleClear(expecting: count) }
        return count
    }

    /// Clears the pasteboard only if nothing else has written since `expected`.
    func clearIfUnchanged(expected: Int) {
        let pb = NSPasteboard.general
        guard pb.changeCount == expected else {
            Log.clipboard.notice("auto-clear skipped: pasteboard changed since copy")
            return
        }
        pb.clearContents()
        ownedChangeCount = nil
        Log.clipboard.notice("auto-cleared secret from pasteboard")
    }

    /// Clears on quit if our secret is still the current contents.
    func clearOnTerminate() {
        if let c = ownedChangeCount { clearIfUnchanged(expected: c) }
    }

    private func scheduleClear(expecting count: Int) {
        clearTask?.cancel()
        clearTask = Task { [weak self] in
            try? await Task.sleep(for: Self.autoClearInterval)
            guard !Task.isCancelled else { return }
            self?.clearIfUnchanged(expected: count)
        }
    }

    // MARK: paste fallback for the fill engine

    /// Snapshot of every item/type on the general pasteboard, used to restore after a temporary paste.
    struct Snapshot: Sendable {
        let items: [[NSPasteboard.PasteboardType: Data]]
    }

    func snapshot() -> Snapshot {
        let items = (NSPasteboard.general.pasteboardItems ?? []).map { item in
            var d: [NSPasteboard.PasteboardType: Data] = [:]
            for t in item.types { if let data = item.data(forType: t) { d[t] = data } }
            return d
        }
        return Snapshot(items: items)
    }

    /// Puts `secret` on the pasteboard for a paste keystroke (same concealed/host-only rules, no auto-clear
    /// timer: the caller restores immediately). Returns the change count to verify before restoring.
    func stageForPaste(_ secret: String) -> Int { copySecret(secret, autoClear: false) }

    func restore(_ snap: Snapshot, ifChangeCountIs expected: Int) {
        let pb = NSPasteboard.general
        guard pb.changeCount == expected else { return }
        // Same write path as a copy: starts with prepareForNewContents(.currentHostOnly) so restoring never makes an earlier
        // local-only secret eligible for Universal Clipboard (L9). Items are put back through setData on this pasteboard; only the
        // first item's types survive (a multi-item clipboard is flattened, which is acceptable for a restore after a paste).
        pb.prepareForNewContents(with: [.currentHostOnly])
        ownedChangeCount = nil
        guard let first = snap.items.first else { return }
        for (t, d) in first { pb.setData(d, forType: t) }
        // What was there may be a secret copied a moment ago: its timer saw the paste's change count and gave up, so restart
        // it for the restored copy, or the secret would stay until something else is copied.
        if first[Self.concealedType] != nil {
            ownedChangeCount = pb.changeCount
            scheduleClear(expecting: pb.changeCount)
        }
    }
}
