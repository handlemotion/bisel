import ApplicationServices
import AppKit
import Foundation
// Drives ONE process (by pid) through the accessibility API: no global events, nothing is sent to any other app.
//   axdrive <pid> tree                      dump identifiers/roles/labels
//   axdrive <pid> get <id>                  print value/title of the element with AXIdentifier == id
//   axdrive <pid> press <id|title:Text>     AXPress
//   axdrive <pid> set <id> <text>           set AXValue (text fields / text views)
//   axdrive <pid> wait <id> [seconds]       wait until it exists
//   axdrive <pid> waitgone <id> [seconds]
//   axdrive <pid> menu <id> <title>         press menu button <id>, then press the menu item titled <title>
func attr(_ e: AXUIElement, _ a: String) -> CFTypeRef? { var v: CFTypeRef?; return AXUIElementCopyAttributeValue(e, a as CFString, &v) == .success ? v : nil }
func str(_ e: AXUIElement, _ a: String) -> String? { attr(e, a) as? String }
func kids(_ e: AXUIElement) -> [AXUIElement] {
    if str(e, kAXRoleAttribute) == "AXApplication" { return (attr(e, kAXWindowsAttribute) as? [AXUIElement]) ?? [] }
    return (attr(e, kAXChildrenAttribute) as? [AXUIElement]) ?? []
}
func walk(_ e: AXUIElement, depth: Int = 0, _ visit: (AXUIElement, Int) -> Bool) {
    if !visit(e, depth) { return }
    for k in kids(e) { walk(k, depth: depth + 1, visit) }
}
func find(_ root: AXUIElement, _ key: String) -> AXUIElement? {
    var hit: AXUIElement?
    walk(root) { e, _ in
        if hit != nil { return false }
        if key.hasPrefix("title:") {
            let t = String(key.dropFirst(6))
            if str(e, kAXTitleAttribute) == t || str(e, kAXDescriptionAttribute) == t || (str(e, kAXValueAttribute) == t && str(e, kAXRoleAttribute) == "AXStaticText") { hit = e }
        } else if str(e, "AXIdentifier") == key { hit = e }
        return hit == nil
    }
    return hit
}
let a = CommandLine.arguments
guard a.count >= 3, let pid = Int32(a[1]) else { print("usage"); exit(2) }
let app = AXUIElementCreateApplication(pid)
func text(_ e: AXUIElement) -> String { str(e, kAXValueAttribute) ?? str(e, kAXTitleAttribute) ?? str(e, kAXDescriptionAttribute) ?? "" }
switch a[2] {
case "tree":
    walk(app) { e, d in
        let id = str(e, "AXIdentifier") ?? ""
        let role = str(e, kAXRoleAttribute) ?? "?"
        let label = text(e).replacingOccurrences(of: "\n", with: "⏎").prefix(60)
        if !(id.isEmpty && label.isEmpty && ["AXGroup", "AXUnknown", "AXSplitGroup", "AXScrollArea"].contains(role)) {
            print(String(repeating: " ", count: d) + role + (id.isEmpty ? "" : " #\(id)") + (label.isEmpty ? "" : " “\(label)”"))
        }
        return d < 14
    }
case "get": if let e = find(app, a[3]) { print(text(e)) } else { print("NOT FOUND"); exit(1) }
case "press":
    guard let e = find(app, a[3]) else { print("NOT FOUND \(a[3])"); exit(1) }
    let r = AXUIElementPerformAction(e, kAXPressAction as CFString); if r != .success { print("press failed \(r.rawValue)"); exit(1) }
case "set":
    guard let e = find(app, a[3]) else { print("NOT FOUND \(a[3])"); exit(1) }
    AXUIElementSetAttributeValue(e, kAXFocusedAttribute as CFString, kCFBooleanTrue)
    let r = AXUIElementSetAttributeValue(e, kAXValueAttribute as CFString, a[4] as CFString); if r != .success { print("set failed \(r.rawValue)"); exit(1) }
case "wait", "waitgone":
    let limit = Double(a.count > 4 ? a[4] : "15") ?? 15
    let end = Date().addingTimeInterval(limit)
    while Date() < end {
        let present = find(app, a[3]) != nil
        if present == (a[2] == "wait") { exit(0) }
        Thread.sleep(forTimeInterval: 0.25)
    }
    print("TIMEOUT \(a[2]) \(a[3])"); exit(1)
case "menu":
    guard let b = find(app, a[3]) else { print("NOT FOUND \(a[3])"); exit(1) }
    _ = AXUIElementPerformAction(b, kAXPressAction as CFString)
    Thread.sleep(forTimeInterval: 0.6)
    var item: AXUIElement?
    walk(app) { e, _ in
        if item != nil { return false }
        if str(e, kAXRoleAttribute) == "AXMenuItem", str(e, kAXTitleAttribute) == a[4] { item = e }
        return item == nil
    }
    guard let item else { print("MENU ITEM NOT FOUND \(a[4])"); exit(1) }
    _ = AXUIElementPerformAction(item, kAXPressAction as CFString)
default: print("unknown"); exit(2)
}
