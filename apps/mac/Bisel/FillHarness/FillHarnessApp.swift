import SwiftUI

/// Test target for the fill engine: a plain native SwiftUI window with a username field, a secure password
/// field and a one-time-code field. Used for the "native SwiftUI app" row of FILL-MATRIX.md and by the UI flow
/// test. It shows lengths/values of FAKE dev-fixture data only. Never shipped.
@main
struct FillHarnessApp: App {
    var body: some Scene {
        WindowGroup { HarnessView() }
            .defaultSize(width: 420, height: 300)
    }
}

struct HarnessView: View {
    @State private var username = ""
    @State private var password = ""
    @State private var code = ""
    @FocusState private var focus: Field?
    enum Field { case username, password, code }

    var body: some View {
        Form {
            TextField("Username", text: $username)
                .focused($focus, equals: .username)
                .accessibilityIdentifier("harness.username")
            SecureField("Password", text: $password)
                .focused($focus, equals: .password)
                .accessibilityIdentifier("harness.password")
            TextField("Verification code", text: $code)
                .focused($focus, equals: .code)
                .accessibilityIdentifier("harness.code")
            Text("username=\(username)  password.count=\(password.count)  code=\(code)")
                .font(.caption.monospaced())
                .accessibilityIdentifier("harness.readout")
        }
        .formStyle(.grouped)
        .padding()
        .onAppear { focus = .username }
    }
}
