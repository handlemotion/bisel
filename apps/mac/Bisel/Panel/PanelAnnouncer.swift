import AppKit

/// Spoken feedback for VoiceOver. The panel is non-activating and keyboard driven: VoiceOver focus stays in the search
/// field while ↑/↓ moves the selection, so changes the eyes see must be announced explicitly.
@MainActor
enum PanelAnnouncer {
    #if DEBUG
    /// BISEL_DEV_ANNOUNCE_LOG=<path> forces announcements on without VoiceOver and appends each one (fixture text only).
    private static let logPath = ProcessInfo.processInfo.environment["BISEL_DEV_ANNOUNCE_LOG"]
    #endif

    static var isActive: Bool {
        #if DEBUG
        if logPath != nil { return true }
        #endif
        return NSWorkspace.shared.isVoiceOverEnabled
    }

    static func announce(_ text: String, priority: NSAccessibilityPriorityLevel) {
        guard isActive else { return }
        #if DEBUG
        if let logPath, let data = "\(priority.rawValue)\t\(text)\n".data(using: .utf8) {
            if let h = FileHandle(forWritingAtPath: logPath) { h.seekToEndOfFile(); h.write(data); try? h.close() }
            else { FileManager.default.createFile(atPath: logPath, contents: data) }
        }
        #endif
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested,
                             userInfo: [.announcement: text, .priority: priority.rawValue])
    }
}
