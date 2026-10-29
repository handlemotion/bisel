import SwiftUI
import BiselCore

/// Item list + detail + create/edit.
struct VaultBrowser: View {
    let service: VaultService
    @Environment(\.theme) private var theme
    @State private var query = ""
    @State private var selection: String?
    @State private var editing: ItemDraft?

    private var filtered: [ItemRow] {
        let terms = query.split(whereSeparator: \.isWhitespace).map(String.init)
        if terms.isEmpty { return service.rows }
        return service.rows.filter { r in
            let hay = ([r.title, r.username, r.domain] + r.urls + r.tags).joined(separator: " ")
            return terms.allSatisfy { hay.localizedStandardContains($0) }
        }
    }

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                HStack(spacing: theme.spacing.s) {
                    Image(systemName: "magnifyingglass").foregroundStyle(theme.colors.placeholder.color)
                    TextField("Search", text: $query).textFieldStyle(.plain).accessibilityIdentifier("browser-search")
                    Menu {
                        Button("Login", systemImage: "person.crop.square") { editing = ItemDraft(type: .login) }
                        Button("Secure note", systemImage: "note.text") { editing = ItemDraft(type: .note) }
                        Button("Secret", systemImage: "key") { editing = ItemDraft(type: .secret) }
                    } label: { Image(systemName: "plus") }
                    .menuStyle(.borderlessButton).fixedSize().help("New item").accessibilityIdentifier("browser-add")
                }
                .padding(theme.spacing.m)
                Divider()
                if filtered.isEmpty {
                    ContentUnavailableView(service.rows.isEmpty ? "No items yet" : "No matches",
                                           systemImage: service.rows.isEmpty ? "tray" : "magnifyingglass",
                                           description: Text(service.rows.isEmpty ? "Add a login with +, or import from 1Password or a CSV file." : ""))
                } else {
                    List(filtered, selection: $selection) { r in
                        HStack(spacing: theme.spacing.m) {
                            SiteIcon(title: r.title, domain: r.domain, size: 28)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(r.title).font(theme.font(theme.fonts.row)).lineLimit(1)
                                if !r.username.isEmpty || !r.domain.isEmpty {
                                    Text(r.username.isEmpty ? r.domain : r.username)
                                        .font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.secondaryText.color).lineLimit(1)
                                }
                            }
                        }
                        .tag(r.id)
                        .accessibilityIdentifier("row-\(r.title)")
                    }
                    .listStyle(.sidebar).scrollContentBackground(.hidden)
                    .accessibilityIdentifier("browser-list")
                }
                if service.undecryptable > 0 {
                    Text("\(service.undecryptable) item(s) could not be decrypted and are hidden")
                        .font(theme.font(theme.fonts.caption)).foregroundStyle(theme.colors.warning.color).padding(theme.spacing.s)
                }
            }
            .frame(width: 300)
            Divider()
            Group {
                if let id = selection, let row = service.rows.first(where: { $0.id == id }) {
                    ItemDetail(row: row, service: service, onEdit: { editing = ItemDraft($0) }, onDeleted: { selection = nil })
                        .id(row.id)
                } else {
                    ContentUnavailableView("Select an item", systemImage: "key.viewfinder")
                }
            }
            .frame(maxWidth: .infinity)
        }
        .sheet(item: $editing) { draft in
            ItemEditor(draft: draft, service: service, onSaved: { saved in editing = nil; selection = saved.id }, onCancel: { editing = nil })
        }
        .onChange(of: service.rows) { _, rows in
            if let s = selection, !rows.contains(where: { $0.id == s }) { selection = nil }
        }
    }
}
