import AppKit

/// Borderless, non-activating, floating panel (SPEC.md §8). It becomes key so the search field receives typing,
/// but never activates bisel, so the previously frontmost app stays frontmost and receives the fill.
final class CommandPanel: NSPanel {
    var onResignKey: (() -> Void)?
    enum MouseDownResult { case passThrough, consumed }
    /// Decides what a mouse-down at a window-coordinate point means. A click on a row or pill is handled
    /// here (select + default action, like Enter); anything else (the text field) goes to the view hierarchy.
    var handleMouseDown: ((NSPoint) -> MouseDownResult)?

    init() {
        super.init(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 460),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: true)
        isFloatingPanel = true
        level = .floating
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
        hidesOnDeactivate = false
        isOpaque = false
        backgroundColor = .clear
        hasShadow = false  // the design has no shadow or rim: one 1 pt border only
        isMovable = true  // dragged only from the search bar (WindowDragGesture); never by its background
        // Values (password, OTP) are visible in this panel: keep it out of screenshots, recordings and screen sharing
        // made by other apps (SPEC.md §4/§8).
        sharingType = .readOnly
        acceptsMouseMovedEvents = true
        animationBehavior = .none
        isReleasedWhenClosed = false
    }

    /// The drag handle is the search icon at the left of the search bar (the text field stays a normal input):
    /// pressing and dragging inside this strip, `dragBarHeight` tall and `dragHandleWidth` wide, moves the panel.
    var dragBarHeight: CGFloat = 48
    var dragHandleWidth: CGFloat = 40
    /// Called when a drag ends, so the controller can snap the card back to its default spot when it is close.
    var onDragEnded: (() -> Void)?
    var onDragBegan: (() -> Void)?
    /// Maps the origin the pointer asks for to the origin the panel actually takes (snapping to the default spot).
    var dragFilter: ((NSPoint) -> NSPoint)?

    /// A press in the bar becomes a window drag once the pointer moves a few points; a plain click is replayed to
    /// the view hierarchy so the text field still places its caret. (SwiftUI's WindowDragGesture fought the text
    /// field for the same pixels, which made dragging unreliable and made the text scroll.)
    /// Our own drag loop (not `performDrag`) so the controller can snap the panel and draw guides while it moves.
    private func runDrag(from down: NSEvent) {
        let startMouse = convertPoint(toScreen: down.locationInWindow)
        let startOrigin = frame.origin
        onDragBegan?()
        while let next = nextEvent(matching: [.leftMouseDragged, .leftMouseUp], until: .distantFuture,
                                   inMode: .eventTracking, dequeue: true) {
            if next.type == .leftMouseUp { break }
            let m = NSEvent.mouseLocation
            var origin = NSPoint(x: startOrigin.x + m.x - startMouse.x, y: startOrigin.y + m.y - startMouse.y)
            if let f = dragFilter { origin = f(origin) }
            setFrameOrigin(origin)
        }
        onDragEnded?()
    }

    private func trackBarPress(_ down: NSEvent) {
        let start = down.locationInWindow
        while let next = nextEvent(matching: [.leftMouseDragged, .leftMouseUp], until: .distantFuture,
                                   inMode: .eventTracking, dequeue: true) {
            if next.type == .leftMouseUp {
                super.sendEvent(down)
                super.sendEvent(next)
                return
            }
            let p = next.locationInWindow
            if hypot(p.x - start.x, p.y - start.y) > 3 {
                runDrag(from: down)
                return
            }
        }
    }

    override func sendEvent(_ event: NSEvent) {
        if event.type == .leftMouseDown, event.clickCount == 1,
           event.locationInWindow.y >= frame.height - dragBarHeight, event.locationInWindow.x <= dragHandleWidth {
            trackBarPress(event)
            return
        }
        if event.type == .leftMouseDown || event.type == .rightMouseDown || event.type == .otherMouseDown,
           let decide = handleMouseDown {
            switch decide(event.locationInWindow) {
            case .consumed: return
            case .passThrough: break
            }
        }
        super.sendEvent(event)
    }

    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }

    override func resignKey() {
        super.resignKey()
        onResignKey?()
    }

    override func cancelOperation(_ sender: Any?) { /* Esc is handled by the controller's key monitor */ }
}
