import Foundation
import ZIPFoundation
import BiselCore

/// 1Password `.1pux` = a zip with `export.data` (JSON: accounts → vaults → items). Logins, passwords, notes and API-like
/// categories are mapped; every other field survives as a custom field so nothing is dropped silently. A passkey found
/// anywhere inside an item is kept losslessly in the reserved `passkey` slot (sign-in is M7).
enum OnePuxImporter {
    static let maxExportBytes = 256 * 1024 * 1024
    static let maxTotalBytes = 1024 * 1024 * 1024
    static let maxEntries = 20_000
    static let maxItems = 50_000

    static func parse(url: URL) throws -> ImportOutcome {
        let archive: Archive
        do { archive = try Archive(url: url, accessMode: .read) } catch { throw ImportError.unreadable("Not a valid .1pux archive") }
        // Treat the archive as hostile: bounded entry count and total size, no path tricks, no symlinks. Only `export.data` is ever
        // read; nothing is extracted to disk, so ".." paths could not escape anyway, but they mark a crafted file.
        var entries = 0, total: UInt64 = 0
        for e in archive {
            entries += 1
            total += UInt64(e.uncompressedSize)
            guard entries <= maxEntries, total <= UInt64(maxTotalBytes) else { throw ImportError.unreadable("The archive is too large or has too many files") }
            guard !e.path.hasPrefix("/"), !e.path.split(separator: "/").contains(".."), e.type != .symlink else {
                throw ImportError.unreadable("The archive contains an unsafe path")
            }
        }
        guard let entry = archive["export.data"], entry.type == .file else { throw ImportError.unreadable("export.data is missing from the archive") }
        guard entry.uncompressedSize <= UInt64(maxExportBytes) else { throw ImportError.unreadable("The export is too large") }
        var data = Data()
        _ = try archive.extract(entry, skipCRC32: false) { data.append($0) }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let accounts = root["accounts"] as? [[String: Any]] else { throw ImportError.unreadable("export.data isn't a 1Password export") }
        var out = ImportOutcome()
        for account in accounts {
            for vault in account["vaults"] as? [[String: Any]] ?? [] {
                for raw in vault["items"] as? [[String: Any]] ?? [] {
                    if out.items.count + out.skipped.count >= maxItems { throw ImportError.unreadable("More than \(maxItems) items: refusing to import") }
                    map(raw, into: &out)
                }
            }
        }
        return out
    }

    private static let apiLike: Set<String> = ["112", "114", "102", "110", "109", "100"]   // API credential, SSH key, database, server, router, license

    private static func map(_ raw: [String: Any], into out: inout ImportOutcome) {
        let overview = raw["overview"] as? [String: Any] ?? [:]
        let details = raw["details"] as? [String: Any] ?? [:]
        let title = (overview["title"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "Untitled"
        if let state = raw["state"] as? String, state != "active" { out.skipped.append("\(title): \(state)"); return }
        let category = raw["categoryUuid"] as? String ?? ""

        var urls: [String] = []
        if let u = overview["url"] as? String, !u.isEmpty { urls.append(u) }
        for u in overview["urls"] as? [[String: Any]] ?? [] {
            if let s = u["url"] as? String, !s.isEmpty, !urls.contains(s) { urls.append(s) }
        }
        var item = Item(type: .login, title: title, urls: urls, tags: overview["tags"] as? [String] ?? [])
        if let t = raw["createdAt"] as? Double { item.createdAt = Date(timeIntervalSince1970: t) }
        if let t = raw["updatedAt"] as? Double { item.updatedAt = Date(timeIntervalSince1970: t) }
        if let n = details["notesPlain"] as? String, !n.isEmpty { item.notes = n }

        for f in details["loginFields"] as? [[String: Any]] ?? [] {
            let v = f["value"] as? String ?? ""
            guard !v.isEmpty else { continue }
            switch f["designation"] as? String {
            case "username": item.username = v
            case "password": item.password = v
            default: item.fields.append(CustomField(label: f["name"] as? String ?? "Field", value: v, secret: (f["fieldType"] as? String) == "P"))
            }
        }
        if item.password == nil, let p = details["password"] as? String, !p.isEmpty { item.password = p }

        var extraTOTP: [CustomField] = []
        for section in details["sections"] as? [[String: Any]] ?? [] {
            for f in section["fields"] as? [[String: Any]] ?? [] {
                let label = (f["title"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? (f["id"] as? String) ?? "Field"
                guard let value = f["value"] as? [String: Any], let (kind, payload) = value.first else { continue }
                switch kind {
                case "totp":
                    guard let s = payload as? String, !s.isEmpty else { continue }
                    if item.totp == nil, let p = TOTPSetup.parsed(s) { item.totp = p.params }
                    else { extraTOTP.append(CustomField(label: label, value: s, secret: true)) }
                case "concealed":
                    guard let s = payload as? String, !s.isEmpty else { continue }
                    if apiLike.contains(category) && item.password == nil { item.password = s }
                    else { item.fields.append(CustomField(label: label, value: s, secret: true)) }
                case "string", "email", "phone", "url", "reference", "menu", "gender", "creditCardType":
                    if let s = payload as? String, !s.isEmpty { item.fields.append(CustomField(label: label, value: s)) }
                case "date", "monthYear":
                    if let n = payload as? Double { item.fields.append(CustomField(label: label, value: kind == "date" ? Date(timeIntervalSince1970: n).formatted(date: .abbreviated, time: .omitted) : String(Int(n)))) }
                case "creditCardNumber":
                    if let s = payload as? String, !s.isEmpty { item.fields.append(CustomField(label: label, value: s, secret: true)) }
                case "address":
                    if let a = payload as? [String: Any] {
                        let s = ["street", "city", "zip", "state", "country"].compactMap { a[$0] as? String }.filter { !$0.isEmpty }.joined(separator: ", ")
                        if !s.isEmpty { item.fields.append(CustomField(label: label, value: s)) }
                    }
                case "passkey": break   // handled by the recursive search below, kept whole
                default:
                    if let s = payload as? String, !s.isEmpty { item.fields.append(CustomField(label: label, value: s)) }
                }
            }
        }
        item.fields.append(contentsOf: extraTOTP)
        if let pk = findPasskey(in: raw) { item.passkey = pk }

        switch category {
        case "003": item.type = .note
        case _ where apiLike.contains(category): item.type = .secret
        case "001", "005": item.type = .login
        default:
            // Cards, identities, bank accounts…: no dedicated type in v1; keep every field in a secure note, secrets stay marked.
            if item.password == nil && item.username == nil { item.type = .note }
        }
        if item.type == .note { item.password = nil; item.username = nil; item.totp = nil }
        out.items.append(item)
    }

    /// First value stored under a `passkey` key anywhere in the item, converted to JSON without loss.
    private static func findPasskey(in any: Any) -> JSONValue? {
        if let d = any as? [String: Any] {
            if let v = d["passkey"], !(v is NSNull), let j = jsonValue(v) { return j }
            for v in d.values { if let j = findPasskey(in: v) { return j } }
        } else if let a = any as? [Any] {
            for v in a { if let j = findPasskey(in: v) { return j } }
        }
        return nil
    }

    private static func jsonValue(_ any: Any) -> JSONValue? {
        guard JSONSerialization.isValidJSONObject(["v": any]),
              let data = try? JSONSerialization.data(withJSONObject: ["v": any]),
              let wrapper = try? JSONDecoder().decode([String: JSONValue].self, from: data) else { return nil }
        return wrapper["v"]
    }
}
