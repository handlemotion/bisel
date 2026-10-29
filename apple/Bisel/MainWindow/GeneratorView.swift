import SwiftUI

/// Generator controls. `onUse` is set when embedded in the editor ("Use password"); standalone it offers Copy.
struct GeneratorView: View {
    var onUse: ((String) -> Void)?
    @Environment(\.theme) private var theme
    @State private var gen = PasswordGenerator()
    @State private var value = ""
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: theme.spacing.m) {
            Text(value)
                .font(theme.font(theme.fonts.value + 2, weight: .medium).monospaced())
                .textSelection(.disabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(theme.spacing.m)
                .background(RoundedRectangle(cornerRadius: theme.radii.field).fill(theme.colors.field.color))
                .accessibilityIdentifier("generated-password")
            HStack {
                Text("Length \(gen.length)").frame(width: 80, alignment: .leading)
                Slider(value: Binding(get: { Double(gen.length) }, set: { gen.length = Int($0); regenerate() }), in: 8...64, step: 1)
            }
            Toggle("Lowercase (a–z)", isOn: $gen.lower)
            Toggle("Uppercase (A–Z)", isOn: $gen.upper)
            Toggle("Digits (0–9)", isOn: $gen.digits)
            Toggle("Symbols (!@#…)", isOn: $gen.symbols)
            Toggle("Avoid look-alike characters", isOn: $gen.avoidAmbiguous)
            HStack {
                Button("Regenerate", systemImage: "arrow.clockwise") { regenerate() }.accessibilityIdentifier("generator-regenerate")
                Spacer()
                if let onUse {
                    Button("Use password") { onUse(value) }.buttonStyle(.borderedProminent).accessibilityIdentifier("generator-use")
                } else {
                    Button(copied ? "Copied" : "Copy", systemImage: "doc.on.doc") {
                        SecureClipboard.shared.copySecret(value)
                        copied = true
                        Task { try? await Task.sleep(for: .seconds(1.2)); copied = false }
                    }.buttonStyle(.borderedProminent)
                }
            }
        }
        .onChange(of: gen) { _, _ in regenerate() }
        .onAppear { if value.isEmpty { regenerate() } }
    }

    private func regenerate() { value = gen.generate() }
}
