import AppKit

/// Snap guides shown while the command panel is dragged (like Raycast): a vertical and a horizontal line through the
/// panel's default position, drawn across the whole screen under the panel. Each line gets brighter as the panel's
/// centre gets closer to it and both turn blue while the panel is locked onto the default spot.
@MainActor
final class DragGuides {
    private var window: NSWindow?
    private let view = GuideView()

    func show(on screen: NSScreen, below panel: NSWindow) {
        hide()
        let w = NSWindow(contentRect: screen.frame, styleMask: .borderless, backing: .buffered, defer: false)
        w.isOpaque = false
        w.backgroundColor = .clear
        w.hasShadow = false
        w.ignoresMouseEvents = true
        w.level = panel.level
        w.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle, .transient]
        w.isReleasedWhenClosed = false
        w.animationBehavior = .none
        view.frame = NSRect(origin: .zero, size: screen.frame.size)
        view.screenOrigin = screen.frame.origin
        w.contentView = view
        w.order(.below, relativeTo: panel.windowNumber)
        window = w
    }

    /// `guide` and `panelCenter` are in screen coordinates.
    func update(guide: CGPoint, panelCenter: CGPoint, locked: Bool) {
        view.guide = guide
        view.panelCenter = panelCenter
        view.locked = locked
        view.needsDisplay = true
    }

    func hide() {
        window?.orderOut(nil)
        window = nil
    }
}

private final class GuideView: NSView {
    var screenOrigin: CGPoint = .zero
    var guide: CGPoint = .zero
    var panelCenter: CGPoint = .zero
    var locked = false

    /// Distance (pt) beyond which a guide is at its dimmest.
    private let range: CGFloat = 480
    private let dimmest: CGFloat = 0.10
    private let brightest: CGFloat = 0.65

    override var isOpaque: Bool { false }

    private func alpha(for distance: CGFloat) -> CGFloat {
        if locked { return 0.95 }
        let t = max(0, 1 - distance / range)
        return dimmest + (brightest - dimmest) * t * t
    }

    override func draw(_ dirtyRect: NSRect) {
        let color: NSColor = locked ? .systemBlue : .white
        let x = guide.x - screenOrigin.x, y = guide.y - screenOrigin.y
        let vertical = NSBezierPath()
        vertical.move(to: NSPoint(x: x, y: 0)); vertical.line(to: NSPoint(x: x, y: bounds.height))
        let horizontal = NSBezierPath()
        horizontal.move(to: NSPoint(x: 0, y: y)); horizontal.line(to: NSPoint(x: bounds.width, y: y))
        for (path, distance) in [(vertical, abs(panelCenter.x - guide.x)), (horizontal, abs(panelCenter.y - guide.y))] {
            path.lineWidth = 1
            color.withAlphaComponent(alpha(for: distance)).setStroke()
            path.stroke()
        }
    }
}
