import AppKit
import ApplicationServices

typealias FieldKind = SecretKind

/// The classified element, kept so the fill engine can check focus has not moved before it types (security review M9).
struct AXRef: @unchecked Sendable {
    let element: AXUIElement
}

/// Value-type snapshot of the focused UI element of the frontmost app. Nothing here is a secret; label hints
/// are used for inference only and are never logged.
struct FocusedField: Sendable {
    var pid: pid_t
    var bundleID: String?
    var role: String?
    var subrole: String?
    /// True when the element is something we can type into (text field/area/combo/search/web text).
    var isTextInput: Bool
    var isSecure: Bool
    /// True when the element is clearly not a text input (button, checkbox, menu…).
    var isClearlyNotText: Bool
    var isTerminal: Bool
    var kind: FieldKind
    /// Whether the app is exposing a usable AX focus at all.
    var hasElement: Bool
    var ref: AXRef? = nil

    var describe: String {
        "role=\(role ?? "nil") subrole=\(subrole ?? "nil") text=\(isTextInput) secure=\(isSecure) kind=\(kind.rawValue) terminal=\(isTerminal)"
    }
}

/// Everything that touches `AXUIElement`. All functions are synchronous and non-isolated; call them off the
/// main thread (AX is IPC to the target app and can block up to the messaging timeout).
enum AccessibilityInspector {
    static func isTrusted(prompt: Bool = false) -> Bool {
        if prompt {
            // Shows the system "would like to control this computer" dialog. Only ever called from an explicit
            // user click in onboarding; it does not grant anything by itself.
            let key = "AXTrustedCheckOptionPrompt" as CFString
            return AXIsProcessTrustedWithOptions([key: true] as CFDictionary)
        }
        return AXIsProcessTrusted()
    }

    static let terminalBundleIDs: Set<String> = [
        "com.apple.Terminal", "com.mitchellh.ghostty", "com.googlecode.iterm2", "net.kovidgoyal.kitty",
        "org.alacritty", "com.github.wez.wezterm", "dev.warp.Warp-Stable", "co.zeit.hyper", "io.alacritty",
    ]

    // MARK: Chromium / Electron

    nonisolated(unsafe) private static var enabledPIDs = Set<pid_t>()
    private static let enabledLock = NSLock()
    nonisolated(unsafe) private static var chromiumCache: [String: Bool] = [:]

    /// Chromium-based apps (Chrome, Edge, Brave, Arc, Vivaldi, Opera) and Electron apps (Slack, Discord, Notion,
    /// VS Code, Linear…) build their web accessibility tree only when an AT announces itself. The documented
    /// signals are `AXManualAccessibility` (Electron) and `AXEnhancedUserInterface` (Chromium). We set them on the
    /// app element once per process, and only for apps whose bundle contains a Chromium/Electron framework, because
    /// `AXEnhancedUserInterface` has side effects (e.g. disables window animations) in native apps.
    @discardableResult
    static func enableChromiumAccessibilityIfNeeded(app: NSRunningApplication) -> Bool {
        guard let bundleURL = app.bundleURL else { return false }
        let key = app.bundleIdentifier ?? bundleURL.path
        let isChromium: Bool = enabledLock.withLock {
            if let c = chromiumCache[key] { return c }
            let c = looksLikeChromium(bundleURL)
            chromiumCache[key] = c
            return c
        }
        guard isChromium else { return false }
        let pid = app.processIdentifier
        let already = enabledLock.withLock { !enabledPIDs.insert(pid).inserted }
        if already { return true }
        let el = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(el, 0.5)
        let a = AXUIElementSetAttributeValue(el, "AXManualAccessibility" as CFString, kCFBooleanTrue)
        let b = AXUIElementSetAttributeValue(el, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
        Log.fill.notice("enabled Chromium AX for \(key): manual=\(a.rawValue) enhanced=\(b.rawValue)")
        return true
    }

    private static func looksLikeChromium(_ bundleURL: URL) -> Bool {
        let fw = bundleURL.appending(path: "Contents/Frameworks", directoryHint: .isDirectory)
        let names = (try? FileManager.default.contentsOfDirectory(atPath: fw.path)) ?? []
        return names.contains { n in
            n.contains("Electron Framework") || n.contains("Chromium Embedded Framework")
                || n.hasSuffix("Chrome Framework.framework") || n.hasSuffix("Chromium Framework.framework")
                || n.hasSuffix("Edge Framework.framework") || n.hasSuffix("Browser Framework.framework")
                || n.hasSuffix("Vivaldi Framework.framework") || n.hasSuffix("Opera Framework.framework")
        }
    }

    // MARK: Focused element

    private static let textRoles: Set<String> = [
        "AXTextField", "AXTextArea", "AXComboBox", "AXSearchField", "AXSecureTextField",
    ]
    private static let nonTextRoles: Set<String> = [
        "AXButton", "AXCheckBox", "AXRadioButton", "AXMenuItem", "AXMenuBar", "AXMenuBarItem", "AXPopUpButton",
        "AXTabGroup", "AXSlider", "AXImage", "AXStaticText", "AXLink", "AXToolbar", "AXMenu", "AXMenuButton",
    ]
    nonisolated(unsafe) private static let codeRegex = try! Regex(
        #"(otp|one[\s_-]?time|2fa|two[\s_-]?factor|verification|security[\s_-]?code|authenticator|totp|passcode|auth(entication)?[\s_-]?code|6[\s_-]?digit|c[oó]digo|\bmfa\b|token)"#
    ).ignoresCase()

    /// Reads the focused element of `app` (falls back to the system-wide focus), classifies it.
    static func focusedField(of app: NSRunningApplication) -> FocusedField {
        let pid = app.processIdentifier
        let appEl = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(appEl, 0.4)
        var focused = element(appEl, kAXFocusedUIElementAttribute)
        if focused == nil {
            let sys = AXUIElementCreateSystemWide()
            AXUIElementSetMessagingTimeout(sys, 0.4)
            if let e = element(sys, kAXFocusedUIElementAttribute) {
                var epid: pid_t = 0
                AXUIElementGetPid(e, &epid)
                if epid == pid { focused = e }
            }
        }
        let bundleID = app.bundleIdentifier
        let terminal = bundleID.map(terminalBundleIDs.contains) ?? false
        guard let el = focused else {
            return FocusedField(pid: pid, bundleID: bundleID, role: nil, subrole: nil, isTextInput: false, isSecure: false,
                                isClearlyNotText: false, isTerminal: terminal, kind: .username, hasElement: false)
        }
        let role = string(el, kAXRoleAttribute)
        let subrole = string(el, kAXSubroleAttribute)
        let roleDesc = string(el, kAXRoleDescriptionAttribute)
        let secure = subrole == "AXSecureTextField" || role == "AXSecureTextField"
            || (roleDesc?.lowercased().contains("secure") ?? false)
        let valueSettable = isSettable(el, kAXValueAttribute)
        let hasSelRange = copy(el, kAXSelectedTextRangeAttribute) != nil
        let textInput = secure || (role.map(textRoles.contains) ?? false)
            || (valueSettable && hasSelRange)
        let notText = role.map(nonTextRoles.contains) ?? false

        var kind: FieldKind = .username
        if secure {
            kind = .password
        } else if textInput {
            let hints = [kAXTitleAttribute, kAXDescriptionAttribute, kAXPlaceholderValueAttribute, kAXHelpAttribute,
                         "AXIdentifier", "AXDOMIdentifier", kAXRoleDescriptionAttribute]
                .compactMap { string(el, $0) }
            var all = hints
            if let labelEl = element(el, kAXTitleUIElementAttribute), let t = string(labelEl, kAXValueAttribute) ?? string(labelEl, kAXTitleAttribute) {
                all.append(t)
            }
            if let classes = copy(el, "AXDOMClassList") as? [String] { all.append(contentsOf: classes) }
            let blob = all.joined(separator: " ")
            if blob.contains(codeRegex) { kind = .totp }
        }
        return FocusedField(pid: pid, bundleID: bundleID, role: role, subrole: subrole, isTextInput: textInput,
                            isSecure: secure, isClearlyNotText: notText && !textInput, isTerminal: terminal,
                            kind: kind, hasElement: true, ref: AXRef(element: el))
    }

    /// The address of the web page the focused field sits in, read through Accessibility: the enclosing web area's `AXURL`, or the
    /// window's `AXDocument` (Safari, Firefox, Chromium). nil in native apps or when the browser does not expose it.
    static func pageURL(of app: NSRunningApplication, field: FocusedField) -> URL? {
        let appEl = AXUIElementCreateApplication(app.processIdentifier)
        AXUIElementSetMessagingTimeout(appEl, 0.4)
        var el = field.ref?.element
        for _ in 0..<14 {
            guard let cur = el else { break }
            if string(cur, kAXRoleAttribute) == "AXWebArea", let u = copy(cur, "AXURL") {
                if let url = u as? URL { return url }
                if let text = u as? String { return URL(string: text) }
            }
            el = element(cur, kAXParentAttribute)
        }
        if let win = element(appEl, kAXFocusedWindowAttribute), let doc = string(win, kAXDocumentAttribute) { return URL(string: doc) }
        return nil
    }

    /// True while `field` is still what the user is looking at: the target app is frontmost and its focused element is the one that
    /// was classified. Checked before every typed chunk; anything else (⌘-Tab, Spotlight, a notification, a focus change) aborts.
    static func isStillFocused(_ field: FocusedField, target: NSRunningApplication) -> Bool {
        guard NSWorkspace.shared.frontmostApplication?.processIdentifier == target.processIdentifier,
              let want = field.ref?.element else { return false }
        let appEl = AXUIElementCreateApplication(target.processIdentifier)
        AXUIElementSetMessagingTimeout(appEl, 0.3)
        guard let now = element(appEl, kAXFocusedUIElementAttribute) else { return false }
        return CFEqual(want, now)
    }

    /// Length of the focused element's AX value, if readable. Used only to confirm a keystroke delivery grew the
    /// field; the value itself is never stored or logged.
    static func focusedValueLength(of app: NSRunningApplication) -> Int? {
        let appEl = AXUIElementCreateApplication(app.processIdentifier)
        AXUIElementSetMessagingTimeout(appEl, 0.3)
        guard let el = element(appEl, kAXFocusedUIElementAttribute) else { return nil }
        guard let v = copy(el, kAXValueAttribute) as? String else { return nil }
        return v.utf16.count
    }

    // MARK: helpers

    private static func copy(_ el: AXUIElement, _ attr: String) -> CFTypeRef? {
        var v: CFTypeRef?
        return AXUIElementCopyAttributeValue(el, attr as CFString, &v) == .success ? v : nil
    }
    private static func element(_ el: AXUIElement, _ attr: String) -> AXUIElement? {
        guard let v = copy(el, attr), CFGetTypeID(v) == AXUIElementGetTypeID() else { return nil }
        return (v as! AXUIElement)
    }
    private static func string(_ el: AXUIElement, _ attr: String) -> String? {
        let s = copy(el, attr) as? String
        return (s?.isEmpty ?? true) ? nil : s
    }
    private static func isSettable(_ el: AXUIElement, _ attr: String) -> Bool {
        var b: DarwinBoolean = false
        return AXUIElementIsAttributeSettable(el, attr as CFString, &b) == .success && b.boolValue
    }
}
