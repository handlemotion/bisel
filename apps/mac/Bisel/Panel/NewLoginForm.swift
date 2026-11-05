import SwiftUI
import BiselCore

/// The detail pane for a login that does not exist yet: same blocks as `DetailPane`, with the title and the Values rows as
/// inputs. Return saves and Esc leaves (the controller's key monitor, `CommandPanelModel.activate` and `escape`).
/// The password reads in the clear, like in the detail pane: not under "Require Touch ID" until a fresh check, and not for
/// VoiceOver, which gets the `SecureField`, since a shown field is kept out of the accessibility tree and could not be edited.
/// The one-time code's setup key stays masked.
struct NewLoginForm: View {
    @Bindable var model: CommandPanelModel
    @Bindable var editor: ItemEditorModel
    @Environment(\.theme) private var theme
    @Environment(\.glassMode) private var glass
    @FocusState private var focus: String?
    @State private var passwordShown = !SecuritySettings.requireTouchID && !PanelAnnouncer.isActive

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: theme.radii.valuesCard, style: .continuous)
        VStack(alignment: .leading, spacing: 0) {
            // No domain: the icon store would fetch one for every keystroke of a half-typed address.
            SiteIcon(title: editor.draft.title, domain: "")
            input(editor.draft.title, "Title", alignment: .leading) {
                TextField("", text: $editor.draft.title).focused($focus, equals: Self.title)
            }
            .font(theme.font(theme.fonts.detailTitle))
            .frame(height: theme.fonts.detailTitle)
            .frame(maxWidth: .infinity, alignment: .leading)
            .trackText(Self.title, model: model)
            .padding(.top, theme.card.iconTitleGap)
            .accessibilityLabel(Text("Title"))
            Text("Values")
                .font(theme.font(theme.fonts.valuesLabel))
                .accessibilityHidden(true)
                .padding(.top, theme.card.blockGap)
            VStack(spacing: 0) {
                row(.otp) {
                    input(editor.draft.totp, "Optional") { SecureField("", text: $editor.draft.totp).focused($focus, equals: ValueRowID.otp.rawValue) }
                }
                Hairline()
                row(.username) {
                    input(editor.draft.username, "Optional") { TextField("", text: $editor.draft.username).focused($focus, equals: ValueRowID.username.rawValue) }
                }
                Hairline()
                row(.password) {
                    input(editor.draft.password, "Optional") {
                        if passwordShown {
                            TextField("", text: $editor.draft.password).focused($focus, equals: ValueRowID.password.rawValue)
                                .accessibilityHidden(true)   // SPEC.md §4: a password is never in the accessibility tree
                        } else {
                            SecureField("", text: $editor.draft.password).focused($focus, equals: ValueRowID.password.rawValue)
                        }
                    }
                } accessory: {
                    if !PanelAnnouncer.isActive {
                        iconButton(.reveal, symbol: passwordShown ? "eye.slash" : "eye",
                                   label: passwordShown ? "Hide password" : "Show password") { togglePassword() }
                    }
                    iconButton(.generate, symbol: "arrow.clockwise", label: "Generate a new password") { editor.generatePassword() }
                }
                Hairline()
                row(.website) {
                    input(website.wrappedValue, "example.com") { TextField("", text: website).focused($focus, equals: ValueRowID.website.rawValue) }
                }
            }
            .clipShape(shape)
            .overlay(shape.strokeBorder(theme.borderColor(glass: glass), lineWidth: theme.card.hairline).allowsHitTesting(false))
            .accessibilityElement(children: .contain)
            .accessibilityLabel(Text("Values"))
            .padding(.top, theme.card.valuesLabelGap)
            Spacer(minLength: 0)
            HStack(spacing: theme.spacing.s) {
                if let problem {
                    Text(problem)
                        .font(theme.font(theme.fonts.value))
                        .foregroundStyle(theme.colors.warning.color)
                        .lineLimit(2)
                        .accessibilityIdentifier("panel.new.problem")
                }
                Spacer(minLength: 0)
                Button("Cancel") { model.closeNewLogin() }
                    .buttonStyle(PillButtonStyle(primary: false, hovered: model.hoveredFormButton == .cancel))
                    .trackButton(.cancel, model: model)
                Button("Save") { model.saveNewLogin() }
                    .buttonStyle(PillButtonStyle(hovered: model.hoveredFormButton == .save))
                    .disabled(!editor.canSave)
                    .trackButton(.save, model: model)
                    .accessibilityIdentifier("panel.new.save")
            }
            .padding(.top, theme.spacing.m)
        }
        .disabled(editor.state == .saving)
        .padding(theme.spacing.l)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { focus = editor.draft.title.isEmpty ? Self.title : ValueRowID.username.rawValue }
        .onChange(of: model.formFocus) { _, id in
            guard let id else { return }
            focus = id
            model.formFocus = nil
        }
    }

    private static let title = "title"

    private func row<Content: View>(_ id: ValueRowID, @ViewBuilder field: () -> Content) -> some View {
        labeled(id) { field().accessibilityLabel(Text(id.spokenLabel)) }
    }

    private func row<Content: View, Accessory: View>(_ id: ValueRowID, @ViewBuilder field: () -> Content,
                                                     @ViewBuilder accessory: () -> Accessory) -> some View {
        labeled(id) {
            field().accessibilityLabel(Text(id.spokenLabel))
            // Into the row's padding by the glyph's inset in its hover box: the last glyph ends where the other rows' values do.
            HStack(spacing: theme.spacing.xs) { accessory() }
                .padding(.trailing, -(theme.spacing.xs + 1))
        }
    }

    private func labeled<Content: View>(_ id: ValueRowID, @ViewBuilder content: () -> Content) -> some View {
        HStack(spacing: theme.spacing.m) {
            Text(id.label)
                .foregroundStyle(theme.dimColor(theme.colors.valueLabel, glass: glass))
                .accessibilityHidden(true)   // the field carries the name
            content()
        }
        .font(theme.font(theme.fonts.value))
        .padding(.horizontal, theme.spacing.m)
        .frame(height: theme.card.valueRowHeight)
        .trackText(id.rawValue, model: model)   // the whole row: label and gap included
    }

    /// A plain field with its placeholder drawn here: SwiftUI drops a `prompt`'s color on a field without focus.
    private func input<Field: View>(_ value: String, _ placeholder: LocalizedStringKey, alignment: Alignment = .trailing,
                                    @ViewBuilder field: () -> Field) -> some View {
        ZStack(alignment: alignment) {
            if value.isEmpty {
                Text(placeholder)
                    .foregroundStyle(theme.dimColor(theme.colors.placeholder, glass: glass))
                    .opacity(theme.increaseContrast ? 1 : 0.55)   // quieter than the row labels beside it
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }
            field()
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                .multilineTextAlignment(alignment == .trailing ? .trailing : .leading)
        }
    }

    private func iconButton(_ id: CommandPanelModel.FormButton, symbol: String, label: LocalizedStringKey,
                            action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(theme.font(theme.fonts.caption))
                .foregroundStyle(theme.colors.secondaryText.color)
                .frame(width: theme.spacing.l + theme.spacing.xs, height: theme.spacing.l + theme.spacing.xs)
                .background(RoundedRectangle(cornerRadius: theme.radii.badge, style: .continuous)
                    .fill(model.hoveredFormButton == id ? theme.hoverFill(glass: glass) : .clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .trackButton(id, model: model)
        .help(Text(label))
        .accessibilityLabel(Text(label))
    }

    /// Showing asks for Touch ID under the strict setting, as any reveal does. The swap of fields must not cost the caret.
    private func togglePassword() {
        Task {
            if !passwordShown, SecuritySettings.requireTouchID {
                guard (try? await BiometricGate.authenticate(reason: String(localized: "Show password"))) != nil else { return }
            }
            let wasFocused = focus == ValueRowID.password.rawValue
            passwordShown.toggle()
            if wasFocused {
                await Task.yield()
                focus = ValueRowID.password.rawValue
            }
        }
    }

    /// A login has one address here; a blank field is none at all.
    private var website: Binding<String> {
        Binding(get: { editor.draft.urls.first ?? "" }, set: { editor.draft.urls = $0.isEmpty ? [] : [$0] })
    }

    /// Why Return did not save. Empties itself once the field is fixed: `issues` is live.
    private var problem: String? {
        switch editor.state {
        case .failed(.other(let text)): return text
        case .failed(.invalid):
            guard let issue = editor.issues.first else { return nil }
            switch (issue.field, issue.code) {
            case (.title, .required): return String(localized: "Give this login a title")
            case (.title, .tooLong): return String(localized: "That title is too long")
            case (.urls, .unsupportedURLScheme): return String(localized: "The website has to be an http or https address")
            case (.urls, _): return String(localized: "That website is not a valid address")
            case (.totp, _): return String(localized: "That one-time code setup key is not valid")
            default: return String(localized: "This login can’t be saved as it is")
            }
        default: return nil
        }
    }
}

private extension View {
    /// The panel's pointer polling needs the frame: `.onHover` is unreliable there.
    func trackButton(_ id: CommandPanelModel.FormButton, model: CommandPanelModel) -> some View {
        onGeometryChange(for: CGRect.self) { $0.frame(in: .named("panelRoot")) } action: { model.formButtonFrames[id] = $0 }
            .onDisappear { model.formButtonFrames[id] = nil }
    }
}
