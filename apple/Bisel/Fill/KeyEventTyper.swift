import AppKit
import CoreGraphics

/// Delivery by synthesized key events (SPEC.md §8 preferred path): one key-down/key-up pair per character
/// carrying the text via `CGEventKeyboardSetUnicodeString`. Nothing touches the clipboard.
///
/// Events are posted at the HID tap from a *private* event source with empty flags, so a modifier the user is
/// still physically holding (⌥ from ⌥Enter, ⌘ from ⌘K…) cannot leak into the typed characters. `waitForModifierRelease`
/// additionally waits for the keys to come up, because some apps read the global modifier state.
enum KeyEventTyper {
    nonisolated(unsafe) private static let source = CGEventSource(stateID: .privateState)

    static let tabKey: CGKeyCode = 0x30
    static let returnKey: CGKeyCode = 0x24
    static let vKey: CGKeyCode = 0x09

    static func waitForModifierRelease(timeout: Duration = .milliseconds(700)) async {
        let deadline = ContinuousClock.now + timeout
        let mask: CGEventFlags = [.maskCommand, .maskAlternate, .maskControl, .maskShift]
        while ContinuousClock.now < deadline {
            let flags = CGEventSource.flagsState(.combinedSessionState)
            if flags.intersection(mask).isEmpty { return }
            try? await Task.sleep(for: .milliseconds(15))
        }
    }

    /// Types `text` character by character. `\t` and `\n` become real Tab/Return key presses.
    static func type(_ text: String, interKeyDelay: useconds_t = 2_000) {
        for ch in text {
            switch ch {
            case "\t": press(tabKey)
            case "\n", "\r", "\r\n": press(returnKey)
            default: typeUnit(Array(String(ch).utf16))
            }
            usleep(interKeyDelay)
        }
    }

    static func press(_ key: CGKeyCode, flags: CGEventFlags = []) {
        for down in [true, false] {
            guard let e = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: down) else { continue }
            e.flags = flags
            e.post(tap: .cghidEventTap)
        }
    }

    private static func typeUnit(_ utf16: [UniChar]) {
        for down in [true, false] {
            guard let e = CGEvent(keyboardEventSource: source, virtualKey: 0, keyDown: down) else { continue }
            e.flags = []
            e.keyboardSetUnicodeString(stringLength: utf16.count, unicodeString: utf16)
            e.post(tap: .cghidEventTap)
        }
    }
}
