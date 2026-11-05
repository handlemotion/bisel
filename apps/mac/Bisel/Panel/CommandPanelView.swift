import SwiftUI

/// The command panel: ONE fixed-size opaque card (so the window never resizes and the input can never move).
///
///  ┌ top bar: magnifier + query ───────────────────────────┐
///  ├ list column (206) ─────────┬ detail pane ─────────────┤
///  │ 48 pt rows, icon + title   │ icon, title, username,   │
///  │ 1 pt separators            │ domain, tags, pill row   │
///
/// Every number below is a theme token (`theme.card`, `theme.spacing`, `theme.fonts`, `theme.colors`, `theme.radii`).
struct CommandPanelView: View {
    @Bindable var model: CommandPanelModel
    @Environment(\.theme) private var theme
    @FocusState private var searchFocused: Bool
    /// Filling needs the Accessibility permission (copying does not): while it is off, a pill floats over the detail pane.
    @State private var access = AppModel.shared.accessibility

    @Environment(\.accessibilityPreferences) private var a11y
    @AppStorage(PanelMaterial.defaultsKey) private var materialRaw = PanelMaterial.glass.rawValue
    private var reduceMotion: Bool { a11y.reduceMotion }
    private var glass: Bool { materialRaw != PanelMaterial.solid.rawValue && !a11y.reduceTransparency }

    /// The open/close scale anchors at the screen position setting's spot, like the card→pill morph.
    private var anchorPoint: UnitPoint {
        switch PanelPosition.current {
        case .center: .center
        case .bottomCenter: .bottom
        case .bottomRight: .bottomTrailing
        case .topRight: .topTrailing
        }
    }

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: theme.radii.card, style: .continuous)
        VStack(spacing: 0) {
            cardContent
                .frame(width: theme.card.width, height: theme.card.height)
                .background { CardFill() }
                .clipShape(shape)
                .overlay(shape.strokeBorder(theme.borderColor(glass: glass), lineWidth: theme.card.hairline).allowsHitTesting(false))
                // Open: scale 0.96 → 1 + fade from the anchor, driven by the controller.
                .scaleEffect(model.presented || reduceMotion ? 1 : 0.96, anchor: anchorPoint)
            if !access.trusted && model.isUnlocked { accessTab }
        }
        .panelMaterial()
        .opacity(model.presented ? 1 : 0)
        // The card is pinned to the top of the window; while Fill is off the window is taller by the tab's height.
        .frame(width: theme.card.width, height: theme.card.height + Self.accessTabHeight(theme, trusted: access.trusted), alignment: .top)
        .coordinateSpace(.named("panelRoot"))
        .environment(\.colorScheme, theme.colorScheme)
        .foregroundStyle(theme.colors.text.color)
        .onChange(of: model.focusToken, initial: true) { searchFocused = true }
    }

    /// Room the "Fill is off" tab takes below the card (the controller grows the window by this much), 0 once Fill works.
    static func accessTabHeight(_ theme: Theme, trusted: Bool) -> CGFloat { trusted ? 0 : theme.spacing.l * 2 }

    private var cardContent: some View {
        VStack(spacing: 0) {
            topBar
            Hairline()
            if model.boxIsEmpty {
                emptyBoxState
            } else if model.isUnlocked, model.mode == .search, model.results.isEmpty {
                noMatchesState
            } else if model.isUnlocked {
                HStack(spacing: 0) {
                    PanelList(model: model).frame(width: theme.card.listWidth)
                    Hairline(axis: .vertical)
                    DetailPane(model: model)
                }
            } else {
                BoxLockedState { model.activate(.plain) }
            }
        }
    }

    // MARK: top bar

    private var topBar: some View {
        HStack(spacing: theme.spacing.s) {
            Image("IconSearch")
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: theme.card.searchGlyph, height: theme.card.searchGlyph)
                .frame(width: theme.card.searchIconBox, height: theme.card.searchIconBox)
                .accessibilityHidden(true)
            TextField("", text: $model.query,
                      prompt: Text("Search logins").foregroundStyle(theme.dimColor(theme.colors.placeholder, glass: glass)))
                .textFieldStyle(.plain)
                .font(theme.font(theme.fonts.search))
                .focused($searchFocused)
                .autocorrectionDisabled()
                .accessibilityLabel(Text("Search logins"))
                .accessibilityHint(Text("Type to filter. Up and Down choose a login, Return copies its password, Command K shows more actions."))
                .accessibilityAddTraits(.isSearchField)
                .accessibilityInputLabels([Text("Search logins"), Text("Search")])
                .accessibilityIdentifier("panel.search")
        }
        .padding(.horizontal, theme.spacing.l)
        .frame(height: theme.card.topBarHeight)
        // The whole bar is the drag handle (handled in CommandPanel.sendEvent); double-click empty space re-centers.
        .background {
            Color.clear
                .contentShape(Rectangle())
                .onTapGesture(count: 2) { model.resetPosition?() }
        }
    }

    /// Non-blocking: everything but Fill works, so a solid tab hanging off the card's bottom edge, not a screen of its own.
    private var accessTab: some View {
        let shape = UnevenRoundedRectangle(bottomLeadingRadius: theme.radii.field, bottomTrailingRadius: theme.radii.field,
                                           style: .continuous)
        return Button { AccessibilityInspector.requestAccess() } label: {
            HStack(spacing: theme.spacing.xs + 2) {
                Image(systemName: "exclamationmark.triangle.fill")
                Text("Fill is off. Allow Accessibility")
            }
            .font(theme.font(theme.fonts.detail, weight: .semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, theme.spacing.l)
            .frame(height: Self.accessTabHeight(theme, trusted: false) - theme.spacing.xs)
            .background(Color.orange, in: shape)
            .contentShape(shape)
        }
        .buttonStyle(.plain)
        .accessibilityHint(Text("Opens System Settings, where you turn on Accessibility for Bisel"))
        .accessibilityIdentifier("panel.accessPill")
    }

    /// Unlocked with nothing in the box: the whole card, like the locked state, instead of an empty list and detail.
    private var emptyBoxState: some View {
        VStack(spacing: theme.spacing.s) {
            Image("EmptyTray").renderingMode(.template).resizable().scaledToFit()
                .frame(width: theme.card.rowHeight * 2.75)
                .foregroundStyle(theme.colors.text.color)
                .padding(.bottom, theme.spacing.l)
                .accessibilityHidden(true)
            Text("Your box is empty").font(theme.font(theme.fonts.detailTitle / 1.5, weight: .semibold))
            Text("Press Return to import passwords")
                .font(theme.font(theme.fonts.detail)).foregroundStyle(theme.colors.secondaryText.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { model.activate(.plain) }
        .accessibilityIdentifier("panel.empty")
    }

    /// A search with no results: the whole card, like the empty box, naming what was typed.
    private var noMatchesState: some View {
        VStack(spacing: theme.spacing.s) {
            Image("EmptyTray").renderingMode(.template).resizable().scaledToFit()
                .frame(width: theme.card.rowHeight * 2.75)
                .foregroundStyle(theme.colors.text.color)
                .padding(.bottom, theme.spacing.l)
                .accessibilityHidden(true)
            Text("No matches for “\(model.query)”")
                .font(theme.font(theme.fonts.detailTitle / 1.5, weight: .semibold))
                .lineLimit(1)
                .truncationMode(.middle)
            Text("Try a site, a name or a username")
                .font(theme.font(theme.fonts.detail)).foregroundStyle(theme.colors.secondaryText.color)
        }
        .padding(.horizontal, theme.spacing.l * 2)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("panel.noMatches")
    }
}

// MARK: - list column

/// The list column. Every row has the same height, so the list is plain arithmetic: the content is as tall as all its rows and
/// only the rows around the visible part exist. A jump to any row costs the same, wherever it is, and a selection change touches
/// a screenful of rows. (A `LazyVStack` lays out every row between here and there to reach a far one: 700 ms at 5,000 items.)
private struct PanelList: View {
    @Bindable var model: CommandPanelModel
    @Environment(\.theme) private var theme
    @State private var position = ScrollPosition()
    /// First row that exists; moves in steps as the list scrolls, so most frames of a scroll change nothing.
    @State private var firstRow = 0
    @State private var listAtEnd = false
    @State private var listScrolled = false

    /// Rows kept beyond each edge of the visible part, and the step `firstRow` moves in.
    private static let overscan = 6, step = 3

    private var pitch: CGFloat { theme.card.rowHeight + theme.card.hairline }
    private var gap: CGFloat { theme.spacing.s }
    private var viewport: CGFloat { model.listFrame.height > 0 ? model.listFrame.height : theme.card.height }
    private var rowCount: Int { model.mode == .search ? model.results.count : model.actions.count }
    /// Same gap above the first island as at its sides, and below the last.
    private func contentHeight(_ count: Int) -> CGFloat { gap * 2 + CGFloat(count) * pitch }

    private func start(atOffset offset: CGFloat) -> Int {
        max(Int(max(offset - gap, 0) / pitch) / Self.step * Self.step - Self.overscan, 0)
    }

    /// The rows that exist, given the number of rows in the list.
    private func window(_ count: Int) -> Range<Int> {
        let size = Int(viewport / pitch) + 2 * Self.overscan + Self.step + 2
        let lower = min(firstRow, max(count - size, 0))
        return lower..<min(lower + size, count)
    }

    var body: some View {
        let count = rowCount
        let window = window(count)
        ScrollView(.vertical) {
            rows(window)
                .frame(width: theme.card.listWidth)  // exactly the column width: long titles truncate, never widen the content
                .padding(.top, gap + CGFloat(window.lowerBound) * pitch)
                .frame(height: contentHeight(count), alignment: .top)
        }
        .scrollPosition($position)
        .scrollBounceBehavior(.basedOnSize, axes: .horizontal)
        .scrollIndicators(.never)
        .mask { overflowFade }
        .onScrollGeometryChange(for: CGFloat.self) { $0.contentOffset.y + $0.contentInsets.top } action: { _, new in
            model.scrollOffset = new
            let first = start(atOffset: new)
            if first != firstRow { firstRow = first }
            let scrolled = new > 1
            if scrolled != listScrolled { listScrolled = scrolled }
        }
        // State, not the model's offset: a keyboard scroll to the last row lands after the render its selection caused.
        .onScrollGeometryChange(for: Bool.self) { $0.visibleRect.maxY >= $0.contentSize.height - 1 } action: { _, new in
            listAtEnd = new
        }
        .onChange(of: model.selected) { _, new in
            defer { model.pointerDriven = false }
            guard !model.pointerDriven, model.results.indices.contains(new) else { return }
            model.lastKeyboardAt = .now   // typing and reopening move the list too: the pointer must not take over
            reveal(new, of: model.results.count)
        }
        .onChange(of: model.actionIndex) { _, new in
            defer { model.pointerDriven = false }
            guard !model.pointerDriven else { return }
            reveal(new, of: model.actions.count)
        }
        // The short actions list took the offset with it: back in the list, the selected login is where the person left it.
        .onChange(of: model.mode) { _, new in
            if new == .search, model.results.indices.contains(model.selected) { reveal(model.selected, of: model.results.count) }
        }
        .onGeometryChange(for: CGRect.self) { $0.frame(in: .named("panelRoot")) } action: {
            model.listFrame = $0
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(model.mode == .search ? Text("Logins") : Text("Actions"))
        .accessibilityIdentifier("panel.list")
    }

    /// Scrolls just far enough to show row `index`; the first and last rows take the gap beside them along.
    private func reveal(_ index: Int, of count: Int) {
        let top = gap + CGFloat(index) * pitch
        let offset = model.scrollOffset
        let target: CGFloat
        if index == 0 { target = 0 }
        else if index == count - 1 { target = contentHeight(count) - viewport }
        else if top < offset { target = top }
        else if top + pitch > offset + viewport { target = top + pitch - viewport }
        else { return }
        let y = max(target, 0)
        guard abs(y - offset) > 0.5 else { return }
        firstRow = start(atOffset: y)   // now, not when the scroll reports back: a far jump must not show an empty column
        position.scrollTo(y: y)
    }

    /// Soft fades where list content runs past the edges: top once scrolled, bottom while more rows remain below.
    private var overflowFade: some View {
        VStack(spacing: 0) {
            LinearGradient(colors: [.clear, .black], startPoint: .top, endPoint: .bottom)
                .frame(height: listScrolled ? theme.spacing.l * 2 : 0)
            Rectangle()
            LinearGradient(colors: [.black, .clear], startPoint: .top, endPoint: .bottom)
                .frame(height: listAtEnd ? 0 : theme.spacing.l * 2)
        }
    }

    @ViewBuilder private func rows(_ window: Range<Int>) -> some View {
        VStack(spacing: 0) {
            switch model.mode {
            case .search:
                // Identified by position: a new search rebinds the rows on screen instead of building them again.
                ForEach(window, id: \.self) { i in resultRow(i, model.results[i]) }
            case .actions:
                let actions = model.actions
                ForEach(window, id: \.self) { i in actionRow(i, actions[i]) }
            }
        }
    }

    private func resultRow(_ i: Int, _ r: VaultSearchResult) -> some View {
        ListRow(selected: i == model.selected) {
            SiteIcon(title: r.title, domain: r.domain)
            Text(r.title).font(theme.font(theme.fonts.row)).lineLimit(1)
        }
        .trackFrame(id: "row.\(i)", model: model)
        // One element per login: title, then "user, site, 3 of 12", selected state, press = select.
        // Custom actions give VoiceOver / Voice Control the same routes as the keys.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(r.title)
        .accessibilityValue(model.spokenDescription(ofResultAt: i))
        .accessibilityAddTraits(i == model.selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityInputLabels([r.title, r.domain].filter { !$0.isEmpty })
        .accessibilityAction { model.selectResult(at: i) }
        .accessibilityAction(named: Text("Copy password")) { model.activateResult(at: i, .plain) }
        .accessibilityAction(named: Text("Copy username")) { model.activateResult(at: i, .shift) }
        .accessibilityAction(named: Text("Copy one-time code")) { model.activateResult(at: i, .command) }
        .accessibilityAction(named: Text("Fill focused field")) { model.activateResult(at: i, .option) }
        .accessibilityIdentifier("panel.row.\(r.id)")
    }

    private func actionRow(_ i: Int, _ a: PanelAction) -> some View {
        ListRow(selected: i == model.actionIndex) {
            Image(systemName: a.symbol)
                .font(theme.font(theme.fonts.pillIcon))
                .foregroundStyle(theme.colors.secondaryText.color)
                .frame(width: theme.card.iconSize, height: theme.card.iconSize)
            Text(a.title).font(theme.font(theme.fonts.row)).lineLimit(1)
            Spacer(minLength: 0)
            if let k = a.shortcut { Keycap(k) }
        }
        .trackFrame(id: "action.\(i)", model: model)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(a.title)
        .accessibilityValue(model.spokenDescription(ofActionAt: i))
        .accessibilityAddTraits(i == model.actionIndex ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction { model.activateAction(at: i) }
    }
}

// MARK: - rows

/// 48 pt row: padding 12, gap 12, full-width selection, 1 pt separator below.
private struct ListRow<Content: View>: View {
    let selected: Bool
    @ViewBuilder var content: Content
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass

    var body: some View {
        VStack(spacing: 0) {
            // "Island" row: the hover/selection fill is an inset rounded shape, not a full-width bar. The row keeps its
            // 48 pt + 1 pt pitch, so reported row frames meet with no gap for the pointer to fall through.
            HStack(spacing: theme.spacing.m) { content; Spacer(minLength: 0) }
                .padding(.horizontal, theme.spacing.s)
                .frame(height: theme.card.rowHeight - theme.spacing.xs)
                .background(RoundedRectangle(cornerRadius: theme.radii.field, style: .continuous)
                    .fill(selected ? theme.selectionFill(glass: glass) : .clear))
                .padding(.horizontal, theme.spacing.s)
                .frame(height: theme.card.rowHeight)
                .contentShape(Rectangle())
            Color.clear.frame(height: theme.card.hairline)
        }
    }
}

private extension View {
    /// Reports this view's frame (panel space) so the pointer logic can map positions to rows, for as long as it exists.
    func trackFrame(id: String, model: CommandPanelModel) -> some View {
        onGeometryChange(for: CGRect.self) { $0.frame(in: .named("panelRoot")) } action: { model.rowFrames[id] = $0 }
            .onDisappear { model.rowFrames[id] = nil }
    }
    func trackValue(_ id: ValueRowID, model: CommandPanelModel) -> some View {
        onGeometryChange(for: CGRect.self) { $0.frame(in: .named("panelRoot")) } action: { model.valueFrames[id] = $0 }
    }
    func trackPill(_ id: PillID, model: CommandPanelModel) -> some View {
        onGeometryChange(for: CGRect.self) { $0.frame(in: .named("panelRoot")) } action: { model.pillFrames[id] = $0 }
    }
}

// MARK: - icon

/// Rounded-square icon: monogram immediately, the site icon swaps in when it is cached/loaded.
struct SiteIcon: View {
    let title: String
    let domain: String
    var size: Double?
    @Environment(\.theme) private var theme
    /// Tied to its domain: a list row is reused for another login, and must never show the last one's icon.
    @State private var loaded: (domain: String, image: NSImage)?
    private let store = IconStore.shared

    private var image: NSImage? {
        guard store.enabled else { return nil }
        if let loaded, loaded.domain == domain { return loaded.image }
        return store.cached(domain)
    }

    var body: some View {
        let side = size ?? theme.card.iconSize
        let shape = RoundedRectangle(cornerRadius: theme.radii.icon, style: .continuous)
        ZStack {
            if let image {
                shape.fill(theme.colors.iconTile.color)
                Image(nsImage: image).resizable().interpolation(.high).scaledToFill()
            } else {
                shape.fill(theme.colors.accent.color.opacity(0.18))
                Text(String(title.prefix(1)).uppercased())
                    .font(theme.font(side * 0.5, weight: .semibold))
                    .foregroundStyle(theme.colors.accent.color)
            }
        }
        .frame(width: side, height: side)
        .clipShape(shape)
        .accessibilityHidden(true)  // decorative: the login's name is read next to it
        .task(id: "\(domain)|\(store.generation)|\(store.enabled)") {
            guard store.enabled else { loaded = nil; return }
            if store.cached(domain) != nil { return }
            loaded = nil
            let wanted = domain
            let image = await store.load(wanted)
            if !Task.isCancelled { loaded = image.map { (wanted, $0) } }
        }
    }
}

// MARK: - detail

private struct DetailPane: View {
    @Bindable var model: CommandPanelModel
    @Environment(\.theme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let r = model.selectedResult {
                // Block 1: icon (left) and the "more actions" menu (right), then the title
                HStack(spacing: 0) {
                    SiteIcon(title: r.title, domain: r.domain)
                    Spacer(minLength: 0)
                    MoreActionsMenu(model: model, item: r)
                }
                Text(r.title)
                    .font(theme.font(theme.fonts.detailTitle))
                    .lineLimit(1)
                    .frame(height: theme.fonts.detailTitle, alignment: .leading)
                    .padding(.top, theme.card.iconTitleGap)
                    .accessibilityAddTraits(.isHeader)
                    .accessibilityIdentifier("panel.detail.title")
                // Block 2: Values
                Text("Values")
                    .font(theme.font(theme.fonts.valuesLabel))
                    .accessibilityHidden(true)  // the card below carries the "Values" label
                    .padding(.top, theme.card.blockGap)
                ValuesCard(model: model, item: r)
                    .padding(.top, theme.card.valuesLabelGap)
                Spacer(minLength: 0)
                ShortcutLegend(item: r)
            } else {
                Spacer()
            }
        }
        .padding(theme.spacing.l)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// "···" at the top right of the detail pane: every action for the selected item in a native menu.
private struct MoreActionsMenu: View {
    @Bindable var model: CommandPanelModel
    let item: VaultSearchResult
    @Environment(\.theme) private var theme

    var body: some View {
        Menu {
            let available = model.availableActions(for: item)
            ForEach(available.filter { [.copyPassword, .copyUsername, .copyTOTP].contains($0) }) { actionButton($0) }
            Divider()
            ForEach(available.filter { [.fill, .fillUserTabPassword, .fillUsername, .fillPassword, .fillTOTP].contains($0) }) { actionButton($0) }
            if available.contains(.openURL) {
                Divider()
                actionButton(.openURL)
            }
            if available.contains(.moveToTrash) {
                Divider()
                Button(role: .destructive) { model.perform(.moveToTrash, on: item) } label: {
                    Label(PanelAction.moveToTrash.title, systemImage: PanelAction.moveToTrash.symbol)
                }
            }
        } label: {
            Image(systemName: "ellipsis")
                .font(theme.font(theme.fonts.pillIcon))
                .foregroundStyle(theme.colors.secondaryText.color)
                .frame(width: theme.card.iconSize, height: theme.card.iconSize)
                .contentShape(Rectangle())
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
        .accessibilityLabel(Text("More actions"))
        .accessibilityHint(Text("Shows copy, fill and open actions for \(item.title). Command K does the same from the keyboard."))
        .accessibilityInputLabels([Text("More actions"), Text("More"), Text("Actions")])
        .accessibilityIdentifier("panel.more")
    }

    private func actionButton(_ a: PanelAction) -> some View {
        Button { model.perform(a, on: item) } label: { Label(a.title, systemImage: a.symbol) }
    }
}

/// Quiet legend of the keyboard shortcuts at the bottom of the detail pane (replaces the old action pills).
private struct ShortcutLegend: View {
    let item: VaultSearchResult
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass
    private var items: [(key: String, label: String, spoken: String)] {
        var out = [("↩", String(localized: "Copy password"), String(localized: "Return copies the password")),
                   ("⇧↩", String(localized: "Username"), String(localized: "Shift Return copies the username"))]
        if item.hasTOTP { out.append(("⌘↩", String(localized: "OTP"), String(localized: "Command Return copies the one-time code"))) }
        out += [("⌥↩", String(localized: "Fill"), String(localized: "Option Return fills the focused field")),
                ("⌘K", String(localized: "More"), String(localized: "Command K shows more actions"))]
        return out
    }

    var body: some View {
        let dim = theme.dimColor(theme.colors.valueLabel, glass: glass)
        HStack(spacing: theme.spacing.l) {
            ForEach(items, id: \.key) { item in
                HStack(spacing: theme.spacing.s) {
                    keycap(item.key)
                    Text(item.label)
                }
            }
        }
        .font(theme.font(theme.fonts.valuesLabel))
        .foregroundStyle(dim)
        .lineLimit(1)
        .padding(.top, theme.spacing.m)
        // One quiet element that reads the shortcuts in words (the glyphs ↩ ⇧ ⌘ ⌥ are not spoken usefully).
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("Keyboard shortcuts"))
        .accessibilityValue(items.map(\.spoken).joined(separator: ". "))
    }

    /// A small filled key: equal minimum size so single glyphs (↩) and chords (⌘K) line up, hairline edge like a key.
    private func keycap(_ key: String) -> some View {
        let shape = RoundedRectangle(cornerRadius: theme.radii.badge, style: .continuous)
        return Text(key)
            .font(theme.font(theme.fonts.valuesLabel, weight: .medium))
            .foregroundStyle(theme.colors.secondaryText.color)
            .padding(.horizontal, theme.spacing.xs)
            .frame(minWidth: theme.spacing.l + theme.spacing.xs, minHeight: theme.spacing.l + theme.spacing.xs / 2)
            .background(shape.fill(theme.hoverFill(glass: glass)))
            .overlay(shape.strokeBorder(theme.borderColor(glass: glass), lineWidth: theme.card.hairline))
    }
}

/// Bordered card of 40 pt rows: label left (dim), value right. Password and unrevealed OTP are masked, always.
private struct ValuesCard: View {
    @Bindable var model: CommandPanelModel
    let item: VaultSearchResult
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: theme.radii.valuesCard, style: .continuous)
        // Only the rows the item has: no OTP row for an item without a one-time code, no Password row without a password.
        let rows = ValueRowID.allCases.filter { ($0 != .otp || item.hasTOTP) && ($0 != .password || item.hasPassword) }
        VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.element.id) { i, row in
                ValueRow(model: model, item: item, row: row)
                    .trackValue(row, model: model)
                if i < rows.count - 1 { Hairline() }
            }
        }
        .clipShape(shape)
        .overlay(shape.strokeBorder(theme.borderColor(glass: glass), lineWidth: theme.card.hairline).allowsHitTesting(false))
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text("Values"))
    }
}

private struct ValueRow: View {
    @Bindable var model: CommandPanelModel
    let item: VaultSearchResult
    let row: ValueRowID
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass

    @Environment(\.accessibilityPreferences) private var a11y
    private var reduceMotion: Bool { a11y.reduceMotion }

    var body: some View {
        // The code's remaining time changes the spoken value; refresh it every 5 s, not per frame, so a focused
        // VoiceOver cursor is not interrupted. Other rows never re-render for it.
        if row == .otp {
            TimelineView(.periodic(from: .now, by: 5)) { ctx in content(now: ctx.date) }
        } else {
            content(now: .now)
        }
    }

    /// What VoiceOver reads after the row's name. Passwords are NEVER put in the accessibility tree (any assistive
    /// client could read it), and the live one-time code is only spoken on request ("Read code" action).
    private func spokenValue(now: Date) -> String {
        if let flash = model.flashes[row] { return flash.text }
        switch row {
        case .username, .website: return model.displayValue(row, for: item)
        case .password: return String(localized: "Hidden")
        case .otp:
            guard model.isOTPRevealed(for: item) else { return String(localized: "Hidden") }
            let period = Double(max(model.otpPeriod(for: item), 1))
            let left = Int((period - now.timeIntervalSince1970.truncatingRemainder(dividingBy: period)).rounded(.up))
            let rounded = max(5, (left + 4) / 5 * 5)
            return String(localized: "6 digits, about \(rounded) seconds left")
        }
    }

    /// Voice Control names: "Click Password", "Click Copy password", …
    private var inputLabels: [String] {
        switch row {
        case .otp: [row.spokenLabel, String(localized: "OTP"), String(localized: "Copy one-time code")]
        case .username: [row.label, String(localized: "Copy username")]
        case .password: [row.label, String(localized: "Copy password")]
        case .website: [row.label, String(localized: "Copy website")]
        }
    }

    private func content(now: Date) -> some View {
        let flash = model.flashes[row]
        let ok = flash.map { !$0.isError } ?? false
        return HStack(spacing: theme.spacing.m) {
            Text(row.label)
                .font(theme.font(theme.fonts.value))
                .foregroundStyle(theme.dimColor(theme.colors.valueLabel, glass: glass))
            Spacer(minLength: theme.spacing.m)
            // Value and feedback share one trailing-aligned slot, so cross-fading never moves or resizes the row.
            ZStack(alignment: .trailing) {
                HStack(spacing: theme.spacing.s) {
                    Text(model.displayValue(row, for: item))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if row == .otp, model.isOTPRevealed(for: item) {
                        CountdownRing(period: model.otpPeriod(for: item))
                    }
                }
                .font(theme.font(theme.fonts.value))
                .opacity(flash == nil ? 1 : 0)
                if let flash {
                    HStack(spacing: theme.spacing.xs) {
                        if ok {
                            Image(systemName: "checkmark")
                                .foregroundStyle(theme.colors.success.color)
                                .symbolEffect(.bounce, options: .speed(1.6), value: reduceMotion ? nil : flash)
                        }
                        Text(flash.text)
                            .foregroundStyle(flash.isError ? theme.colors.warning.color : theme.colors.text.color)
                    }
                    .font(theme.font(theme.fonts.value, weight: .medium))
                    .lineLimit(1)
                    .transition(.opacity.combined(with: .scale(scale: reduceMotion ? 1 : 0.96, anchor: .trailing)))
                }
            }
        }
        .padding(theme.spacing.m)
        .frame(height: theme.card.valueRowHeight)
        .background(ok ? theme.colors.success.color.opacity(0.10)
                       : (model.hoveredValue == row ? theme.hoverFill(glass: glass) : .clear))
        .animation(reduceMotion ? .easeOut(duration: 0.1) : .smooth(duration: 0.15), value: flash)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(row.spokenLabel)
        .accessibilityValue(spokenValue(now: now))
        .accessibilityHint(row == .otp && !model.isOTPRevealed(for: item) ? Text("Touch ID reveals it") : Text("Activate to copy"))
        .accessibilityAddTraits(.isButton)
        .accessibilityInputLabels(inputLabels)
        .accessibilityAction { model.activateValue(row) }
        .accessibilityAction(named: Text("Read code aloud")) { model.speakOTP() }
        .accessibilityIdentifier("panel.value.\(row.rawValue)")
    }
}

/// Live countdown ring: full at the start of the TOTP period, draining to empty at the boundary (when the code
/// changes). The arc is green while fresh, shifts through yellow to red as it expires (smoothly interpolated between
/// the theme's success / warning / danger colors: green ≥ 50 % left, yellow at 25 %, red at ≤ 10 %). Wall-clock driven.
private struct CountdownRing: View {
    let period: Int
    @Environment(\.theme) private var theme
    @Environment(\.accessibilityPreferences) private var a11y

    var body: some View {
        // Reduce Motion: the ring steps once a second instead of draining continuously.
        TimelineView(.periodic(from: .now, by: a11y.reduceMotion ? 1 : 0.1)) { ctx in
            let t = ctx.date.timeIntervalSince1970
            let remaining = 1 - t.truncatingRemainder(dividingBy: Double(period)) / Double(period)
            let seconds = Int((remaining * Double(period)).rounded(.up))
            // Differentiate Without Color: the state must not rest on green → red alone. Add the seconds as a number
            // and switch the arc to a dashed stroke in the last quarter.
            HStack(spacing: theme.spacing.xs) {
                if a11y.differentiateWithoutColor {
                    Text(verbatim: "\(seconds)")
                        .font(theme.font(theme.fonts.caption, weight: .medium).monospacedDigit())
                        .foregroundStyle(theme.colors.secondaryText.color)
                }
                ZStack {
                    Circle().stroke(theme.colors.ring.color, lineWidth: theme.card.ringStroke)
                    Circle().trim(from: 0, to: remaining)
                        .stroke(tint(remaining), style: arcStyle(lowTime: remaining < 0.25))
                        .rotationEffect(.degrees(-90))
                }
                .padding(theme.card.ringStroke / 2)
                .frame(width: theme.card.ringSize, height: theme.card.ringSize)
            }
        }
        .accessibilityHidden(true)  // the row's spoken value carries the remaining time
    }

    private func arcStyle(lowTime: Bool) -> StrokeStyle {
        if a11y.differentiateWithoutColor && lowTime {
            return StrokeStyle(lineWidth: theme.card.ringStroke, lineCap: .butt, dash: [2.2, 2.2])
        }
        return StrokeStyle(lineWidth: theme.card.ringStroke, lineCap: .round)
    }

    private func tint(_ f: Double) -> Color {
        let g = NSColor(theme.colors.success.color), y = NSColor(theme.colors.warning.color), r = NSColor(theme.colors.danger.color)
        let c: NSColor
        if f >= 0.5 { c = g }
        else if f >= 0.25 { c = g.blended(withFraction: (0.5 - f) / 0.25, of: y) ?? y }
        else if f >= 0.10 { c = y.blended(withFraction: (0.25 - f) / 0.15, of: r) ?? r }
        else { c = r }
        return Color(nsColor: c)
    }
}

private struct PillButton: View {
    let pill: PillID
    let hovered: Bool
    var copied = false
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass

    var body: some View {
        let fg = pill.isPrimary ? theme.colors.pillPrimaryText.color : theme.colors.pillSecondaryText.color
        HStack(spacing: theme.spacing.xs) {
            if copied {
                Image(systemName: "checkmark").font(theme.font(theme.fonts.pillIcon, weight: .semibold))
                Text("Copied").font(theme.font(theme.fonts.pill, weight: .medium))
            } else if let asset = pill.asset {
                Image(asset).renderingMode(.template).resizable().scaledToFit()
                    .frame(width: theme.fonts.pillIcon, height: theme.fonts.pillIcon)
            } else {
                Image(systemName: pill.symbol).font(theme.font(theme.fonts.pillIcon))  // placeholder until a Figma icon exists
            }
            if !copied { Text(pill.label).font(theme.font(theme.fonts.pill, weight: .medium)) }
            if let key = pill.key, !copied {
                Text(key)
                    .font(theme.font(theme.fonts.caption, weight: .semibold))
                    .padding(.horizontal, theme.spacing.xs)
                    .background(fg.opacity(0.14), in: RoundedRectangle(cornerRadius: theme.radii.badge, style: .continuous))
            }
        }
        .foregroundStyle(fg)
        .padding(.leading, theme.card.pillLeading)
        .padding(.trailing, theme.card.pillTrailing)
        .frame(height: theme.card.pillHeight)
        .background(pill.isPrimary ? theme.colors.pillPrimary.color : theme.pillSecondaryFill(glass: glass), in: Capsule())
        .opacity(hovered ? 0.8 : 1)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("panel.pill.\(pill.rawValue)")
    }
}

/// Left-to-right wrapping layout for the pill row.
private struct FlowLayout: Layout {
    var spacing: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        arrange(width: proposal.width ?? .infinity, subviews).size
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let a = arrange(width: bounds.width, subviews)
        for (i, f) in a.frames.enumerated() {
            subviews[i].place(at: CGPoint(x: bounds.minX + f.minX, y: bounds.minY + f.minY), proposal: .unspecified)
        }
    }

    private func arrange(width: CGFloat, _ subviews: Subviews) -> (size: CGSize, frames: [CGRect]) {
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0, maxW: CGFloat = 0
        var frames: [CGRect] = []
        for s in subviews {
            let sz = s.sizeThatFits(.unspecified)
            if x > 0, x + sz.width > width { x = 0; y += rowH + spacing; rowH = 0 }
            frames.append(CGRect(x: x, y: y, width: sz.width, height: sz.height))
            x += sz.width + spacing
            rowH = max(rowH, sz.height)
            maxW = max(maxW, x - spacing)
        }
        return (CGSize(width: maxW, height: y + rowH), frames)
    }
}

/// A small rounded keycap.
struct Keycap: View {
    let key: String
    @Environment(\.theme) private var theme
    init(_ key: String) { self.key = key }

    var body: some View {
        Text(key)
            .font(theme.font(theme.fonts.caption, weight: .semibold))
            .foregroundStyle(theme.colors.secondaryText.color)
            .padding(.horizontal, theme.spacing.xs + 1)
            .frame(minWidth: theme.spacing.m * 1.5, minHeight: theme.spacing.m * 1.5)
            .background(theme.colors.badge.color, in: RoundedRectangle(cornerRadius: theme.radii.badge, style: .continuous))
    }
}
