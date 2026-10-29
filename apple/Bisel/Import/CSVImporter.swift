import Foundation
import SwiftCSV
import BiselCore

/// Generic CSV with a header row. Recognises the usual column names of 1Password, Bitwarden, Chrome/Edge, Safari,
/// LastPass and KeePass exports; unknown columns are ignored (listed as skipped columns once, never silently per row).
enum CSVImporter {
    private static let aliases: [String: [String]] = [
        "title": ["title", "name", "login_name", "account"],
        "url": ["url", "website", "login_uri", "uri", "web site", "login url", "web_site"],
        "username": ["username", "login_username", "user", "login", "email", "user name", "login name"],
        "password": ["password", "login_password", "pass"],
        "notes": ["notes", "note", "extra", "comments", "notesplain"],
        "totp": ["totp", "login_totp", "otp", "otpauth", "one-time password", "otpauth_url", "onetimepassword"],
        "tags": ["tags", "grouping", "folder", "group", "category"],
        "type": ["type"],
    ]

    static let maxBytes = 50 * 1024 * 1024
    static let maxRows = 100_000
    static let maxField = 64 * 1024

    static func parse(url: URL) throws -> ImportOutcome {
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= maxBytes else { throw ImportError.unreadable("The CSV is larger than 50 MB") }
        let text: String
        do { text = try String(contentsOf: url, encoding: .utf8) } catch { throw ImportError.unreadable("The file isn't UTF-8 text") }
        let firstLine = text.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        let delimiter: Character = firstLine.contains(",") ? "," : (firstLine.contains(";") ? ";" : (firstLine.contains("\t") ? "\t" : ","))
        let csv: CSV<Named>
        do { csv = try CSV<Named>(string: text, delimiter: .character(delimiter), loadColumns: false) }
        catch { throw ImportError.unreadable("The CSV couldn't be parsed: \(error.localizedDescription)") }

        var column: [String: String] = [:]    // canonical field -> actual header
        for header in csv.header {
            let h = header.trimmingCharacters(in: .whitespaces).lowercased()
            for (field, names) in aliases where column[field] == nil && names.contains(h) { column[field] = header }
        }
        guard column["password"] != nil || column["username"] != nil || column["notes"] != nil else {
            throw ImportError.unreadable("No username, password or notes column found. Headers: \(csv.header.joined(separator: ", "))")
        }
        var out = ImportOutcome()
        guard csv.rows.count <= maxRows else { throw ImportError.unreadable("More than \(maxRows) rows: refusing to import") }
        for (i, row) in csv.rows.enumerated() {
            func v(_ f: String) -> String {
                let s = column[f].flatMap { row[$0] }?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                return s.count > maxField ? String(s.prefix(maxField)) : s
            }
            let title = v("title")
            let user = v("username"), pass = v("password"), notes = v("notes"), url = v("url"), totp = v("totp")
            if title.isEmpty && user.isEmpty && pass.isEmpty && notes.isEmpty { out.skipped.append("Row \(i + 2): empty"); continue }
            let type = v("type").lowercased()
            let name = title.isEmpty ? (URL(string: url)?.host() ?? (user.isEmpty ? "Untitled" : user)) : title
            var item = Item(type: .login, title: name, urls: url.isEmpty ? [] : [url])
            if !user.isEmpty { item.username = user }
            if !pass.isEmpty { item.password = pass }
            if !notes.isEmpty { item.notes = notes }
            if !totp.isEmpty {
                if let p = OTPAuth.parse(totp) { item.totp = p.params } else { out.skipped.append("\(name): one-time code not understood (kept out)") }
            }
            let tags = v("tags").split(whereSeparator: { ",;".contains($0) }).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            item.tags = tags
            if pass.isEmpty && user.isEmpty && item.totp == nil || type == "securenote" || type == "note" || type == "2" {
                item.type = .note; item.username = nil; item.password = nil; item.totp = nil
            }
            out.items.append(item)
        }
        return out
    }
}
