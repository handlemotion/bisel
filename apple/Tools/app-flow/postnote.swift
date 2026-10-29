import Foundation
// postnote <name> [path]   posts a distributed notification (what the OS does on screen lock) with optional userInfo path
let info: [AnyHashable: Any]? = CommandLine.arguments.count > 2 ? ["path": CommandLine.arguments[2]] : nil
DistributedNotificationCenter.default().postNotificationName(Notification.Name(CommandLine.arguments[1]), object: nil, userInfo: info, deliverImmediately: true)
RunLoop.current.run(until: Date().addingTimeInterval(0.3))
