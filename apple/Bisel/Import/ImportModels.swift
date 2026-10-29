import Foundation
import BiselCore

struct ImportOutcome {
    var items: [Item] = []
    var skipped: [String] = []
    var logins: Int { items.filter { $0.type == .login }.count }
    var notes: Int { items.filter { $0.type == .note }.count }
    var secrets: Int { items.filter { $0.type == .secret }.count }
    var withTOTP: Int { items.filter { $0.totp != nil }.count }
    var passkeys: Int { items.filter { $0.passkey != nil }.count }
}

enum ImportError: LocalizedError {
    case unreadable(String)
    var errorDescription: String? { if case .unreadable(let m) = self { m } else { nil } }
}

enum ImportFormat {
    case onePux, csv
    init?(url: URL) {
        switch url.pathExtension.lowercased() {
        case "1pux": self = .onePux
        case "csv": self = .csv
        default: return nil
        }
    }

    func parse(url: URL) throws -> ImportOutcome {
        switch self {
        case .onePux: try OnePuxImporter.parse(url: url)
        case .csv: try CSVImporter.parse(url: url)
        }
    }
}
