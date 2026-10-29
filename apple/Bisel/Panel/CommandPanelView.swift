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

    @Environment(\.accessibilityPreferences) private var a11y
    @AppStorage(PanelMaterial.defaultsKey) private var materialRaw = PanelMaterial.glass.rawValue
    private var reduceMotion: Bool { a11y.reduceMotion }
    private var glass: Bool { materialRaw != PanelMaterial.solid.rawValue && !a11y.reduceTransparency }

    /// Where the card sits inside the (fixed-size, transparent) window: matches the screen position setting, so the
    /// open/close scale and the card→pill morph anchor at the same spot.
    private var anchor: Alignment {
        switch PanelPosition.current {
        case .center: .center
        case .bottomCenter: .bottom
        case .bottomRight: .bottomTrailing
        case .topRight: .topTrailing
        }
    }
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
        cardContent
            .frame(width: theme.card.width, height: theme.card.height)
            .background { CardFill() }
            .clipShape(shape)
            .overlay(shape.strokeBorder(theme.borderColor(glass: glass), lineWidth: theme.card.hairline).allowsHitTesting(false))
            .panelMaterial()
            // Open: scale 0.96 → 1 + fade from the anchor, driven by the controller. The window never resizes.
            .scaleEffect(model.presented || reduceMotion ? 1 : 0.96, anchor: anchorPoint)
            .opacity(model.presented ? 1 : 0)
            .frame(width: theme.card.width, height: theme.card.height, alignment: anchor)
            .coordinateSpace(.named("panelRoot"))
            .environment(\.colorScheme, theme.colorScheme)
            .foregroundStyle(theme.colors.text.color)
            .onChange(of: model.focusToken, initial: true) { searchFocused = true }
    }

    private var cardContent: some View {
        VStack(spacing: 0) {
            topBar
            Hairline()
            if model.isUnlocked {
                HStack(spacing: 0) {
                    listColumn.frame(width: theme.card.listWidth)
                    Hairline(axis: .vertical)
                    DetailPane(model: model)
                }
            } else {
                lockedState
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
        .padding(theme.spacing.m)
        .frame(height: theme.card.topBarHeight)
        // The whole bar is the drag handle (handled in CommandPanel.sendEvent); double-click empty space re-centers.
        .background {
            Color.clear
                .contentShape(Rectangle())
                .onTapGesture(count: 2) { model.resetPosition?() }
        }
    }

    // MARK: list column

    private var listColumn: some View {
        ScrollViewReader { proxy in
            ScrollView(.vertical) {
                LazyVStack(spacing: 0) { rows }
                    .frame(width: theme.card.listWidth)  // exactly the column width: long titles truncate, never widen the content
                    .padding(.top, theme.spacing.s)  // same gap above the first island as at its sides
            }
            .scrollBounceBehavior(.basedOnSize, axes: .horizontal)
            .scrollIndicators(.never)
            .mask { overflowFade }
            .onScrollGeometryChange(for: CGFloat.self) { $0.contentOffset.y + $0.contentInsets.top } action: { _, new in
                model.scrollOffset = new
            }
            .onChange(of: model.selected) { _, new in
                defer { model.pointerDriven = false }
                guard !model.pointerDriven, model.results.indices.contains(new) else { return }
                proxy.scrollTo(model.results[new].id)
            }
            .onChange(of: model.actionIndex) { _, new in
                defer { model.pointerDriven = false }
                if !model.pointerDriven { proxy.scrollTo("action.\(new)") }
            }
        }
        .onGeometryChange(for: CGRect.self) { $0.frame(in: .named("panelRoot")) } action: {
            model.listFrame = $0
            model.listTopInset = theme.spacing.s
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(model.mode == .search ? Text("Logins") : Text("Actions"))
        .accessibilityIdentifier("panel.list")
    }

    /// Soft fades where list content runs past the edges: top once scrolled, bottom while more rows remain below.
    private var overflowFade: some View {
        let rowCount = model.mode == .search ? model.results.count : model.actions.count
        let contentHeight = CGFloat(rowCount) * (theme.card.rowHeight + theme.card.hairline) + theme.spacing.s
        let viewport = model.listFrame.height
        let fadeTop = model.scrollOffset > 1
        let fadeBottom = viewport > 0 && model.scrollOffset + viewport < contentHeight - 1
        return VStack(spacing: 0) {
            LinearGradient(colors: [.clear, .black], startPoint: .top, endPoint: .bottom)
                .frame(height: fadeTop ? theme.spacing.l * 2 : 0)
            Rectangle()
            LinearGradient(colors: [.black, .clear], startPoint: .top, endPoint: .bottom)
                .frame(height: fadeBottom ? theme.spacing.l * 2 : 0)
        }
    }

    @ViewBuilder private var rows: some View {
        switch model.mode {
        case .search:
            if model.results.isEmpty {
                Text("No matches")
                    .accessibilityAddTraits(.isStaticText)
                    .font(theme.font(theme.fonts.row))
                    .foregroundStyle(theme.colors.tertiaryText.color)
                    .frame(maxWidth: .infinity, minHeight: theme.card.rowHeight * 2)
            } else {
                ForEach(Array(model.results.enumerated()), id: \.element.id) { i, r in
                    ListRow(selected: i == model.selected) {
                        SiteIcon(title: r.title, domain: r.domain)
                        Text(r.title).font(theme.font(theme.fonts.row)).lineLimit(1)
                    }
                    .id(r.id)
                    // One element per login: title, then "user, site, 3 of 12", selected state, press = select.
                    // Custom actions give VoiceOver / Voice Control the same routes as the keys.
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(r.title)
                    .accessibilityValue(model.spokenDescription(ofResultAt: i))
                    .accessibilityAddTraits(i == model.selected ? [.isButton, .isSelected] : .isButton)
                    .accessibilityInputLabels([Text(verbatim: r.title), Text(verbatim: r.domain)].filter { _ in true })
                    .accessibilityAction { model.selectResult(at: i) }
                    .accessibilityAction(named: Text("Copy password")) { model.activateResult(at: i, .plain) }
                    .accessibilityAction(named: Text("Copy username")) { model.activateResult(at: i, .shift) }
                    .accessibilityAction(named: Text("Copy one-time code")) { model.activateResult(at: i, .command) }
                    .accessibilityAction(named: Text("Fill focused field")) { model.activateResult(at: i, .option) }
                    .accessibilityIdentifier("panel.row.\(r.id)")
                }
            }
        case .actions:
            ForEach(Array(model.actions.enumerated()), id: \.element.id) { i, a in
                ListRow(selected: i == model.actionIndex) {
                    Image(systemName: a.symbol)
                        .font(theme.font(theme.fonts.pillIcon))
                        .foregroundStyle(theme.colors.secondaryText.color)
                        .frame(width: theme.card.iconSize, height: theme.card.iconSize)
                    Text(a.title).font(theme.font(theme.fonts.row)).lineLimit(1)
                    Spacer(minLength: 0)
                    if let k = a.shortcut { Keycap(k) }
                }
                .id("action.\(i)")
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(a.title)
                .accessibilityValue(model.spokenDescription(ofActionAt: i))
                .accessibilityAddTraits(i == model.actionIndex ? [.isButton, .isSelected] : .isButton)
                .accessibilityAction { model.activateAction(at: i) }
            }
        }
    }

    private var lockedState: some View {
        VStack(spacing: theme.spacing.s) {
            Image(systemName: "touchid").font(.system(size: 28)).foregroundStyle(theme.colors.accent.color)
            Text("Vault locked").font(theme.font(theme.fonts.detailTitle / 1.5, weight: .semibold))
            Text("Press Return to unlock with Touch ID")
                .font(theme.font(theme.fonts.detail)).foregroundStyle(theme.colors.secondaryText.color)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { model.activate(.plain) }
        .accessibilityIdentifier("panel.locked")
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
            // 48 pt + 1 pt pitch so the pointer hit-testing arithmetic is unchanged.
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
    /// Reports this view's frame (panel space) so the pointer logic can map positions to rows.
    func trackFrame(id: String, model: CommandPanelModel) -> some View {
        onGeometryChange(for: CGRect.self) { $0.frame(in: .named("panelRoot")) } action: { model.rowFrames[id] = $0 }
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
    @State private var image: NSImage?
    private let store = IconStore.shared

    var body: some View {
        let side = size ?? theme.card.iconSize
        let shape = RoundedRectangle(cornerRadius: theme.radii.icon, style: .continuous)
        ZStack {
            if store.enabled, let image {
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
        .task(id: "\(domain)|\(store.generation)|\(store.enabled)|\(store.loadedCount)") {
            guard store.enabled else { image = nil; return }
            if let hit = store.cached(domain) { image = hit; return }
            image = nil
            image = await store.load(domain)
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
                ShortcutLegend()
            } else {
                Spacer()
            }
        }
        .padding(theme.spacing.l)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(model.selectedResult.map { Text("Details for \($0.title)") } ?? Text("Details"))
    }
}

/// "···" at the top right of the detail pane: every action for the selected item in a native menu.
private struct MoreActionsMenu: View {
    @Bindable var model: CommandPanelModel
    let item: VaultSearchResult
    @Environment(\.theme) private var theme

    var body: some View {
        Menu {
            actionButton(.copyPassword); actionButton(.copyUsername); actionButton(.copyTOTP)
            Divider()
            actionButton(.fill); actionButton(.fillUserTabPassword)
            actionButton(.fillUsername); actionButton(.fillPassword); actionButton(.fillTOTP)
            Divider()
            actionButton(.openURL)
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
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass
    private var items: [(key: String, label: String, spoken: String)] {
        [("↩", String(localized: "Copy password"), String(localized: "Return copies the password")),
         ("⇧↩", String(localized: "Username"), String(localized: "Shift Return copies the username")),
         ("⌘↩", String(localized: "OTP"), String(localized: "Command Return copies the one-time code")),
         ("⌥↩", String(localized: "Fill"), String(localized: "Option Return fills the focused field")),
         ("⌘K", String(localized: "More"), String(localized: "Command K shows more actions"))]
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
        VStack(spacing: 0) {
            ForEach(Array(ValueRowID.allCases.enumerated()), id: \.element.id) { i, row in
                ValueRow(model: model, item: item, row: row)
                    .trackValue(row, model: model)
                if i < ValueRowID.allCases.count - 1 { Hairline() }
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

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let flash = model.flashes[row]
        let ok = flash.map { !$0.isError } ?? false
        HStack(spacing: theme.spacing.m) {
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
                                .symbolEffect(.bounce, options: .speed(1.6), value: flash)
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
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("panel.value.\(row.rawValue)")
    }
}

/// Live countdown ring: full at the start of the TOTP period, draining to empty at the boundary (when the code
/// changes). The arc is green while fresh, shifts through yellow to red as it expires (smoothly interpolated between
/// the theme's success / warning / danger colors: green ≥ 50 % left, yellow at 25 %, red at ≤ 10 %). Wall-clock driven.
private struct CountdownRing: View {
    let period: Int
    @Environment(\.theme) private var theme

    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.1)) { ctx in
            let t = ctx.date.timeIntervalSince1970
            let remaining = 1 - t.truncatingRemainder(dividingBy: Double(period)) / Double(period)
            ZStack {
                Circle().stroke(theme.colors.ring.color, lineWidth: theme.card.ringStroke)
                Circle().trim(from: 0, to: remaining)
                    .stroke(tint(remaining), style: StrokeStyle(lineWidth: theme.card.ringStroke, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .padding(theme.card.ringStroke / 2)
            .frame(width: theme.card.ringSize, height: theme.card.ringSize)
        }
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
