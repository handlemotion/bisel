import XCTest

/// Flow tests on the real app against a real local server (`wrangler dev`, fresh D1). They need:
///   BISEL_TEST_SERVER  (default http://localhost:8790)   BISEL_TEST_TOKEN  (default dev-bootstrap-token)
/// passed as TEST_RUNNER_BISEL_TEST_SERVER / TEST_RUNNER_BISEL_TEST_TOKEN to xcodebuild, and an un-bootstrapped server.
/// Biometrics are bypassed by the Debug-only BISEL_DEV_SKIP_BIOMETRIC. Only Bisel's own windows are driven.
final class BiselFlowUITests: XCTestCase {
    private let server = ProcessInfo.processInfo.environment["BISEL_TEST_SERVER"] ?? "http://localhost:8790"
    private let token = ProcessInfo.processInfo.environment["BISEL_TEST_TOKEN"] ?? "dev-bootstrap-token"
    private var dirs: [URL] = []

    override func setUp() { continueAfterFailure = false }
    override func tearDown() { dirs.forEach { try? FileManager.default.removeItem(at: $0) } }

    private func freshDir() -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("bisel-ui-\(UUID().uuidString)")
        dirs.append(d)
        return d
    }

    private func launch(_ dir: URL, extra: [String: String] = [:]) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment = ["BISEL_DATA_DIR": dir.path, "BISEL_DEV_SKIP_BIOMETRIC": "1"].merging(extra) { $1 }
        app.launch()
        return app
    }

    private func type(_ app: XCUIApplication, _ id: String, _ text: String, secure: Bool = false) {
        let field = secure ? app.secureTextFields[id] : app.textFields[id]
        XCTAssertTrue(field.waitForExistence(timeout: 10), "missing field \(id)")
        field.click()
        field.typeText(text)
    }

    @discardableResult
    private func exists(_ el: XCUIElement, _ timeout: TimeInterval = 10, _ msg: String = "") -> Bool {
        let ok = el.waitForExistence(timeout: timeout)
        XCTAssertTrue(ok, "expected \(el) \(msg)")
        return ok
    }

    /// Set-up → recovery phrase gate → unlocked vault. Returns the phrase.
    private func onboard(_ app: XCUIApplication) -> String {
        exists(app.textFields["setup-server"], 20, "setup screen on first run")
        type(app, "setup-server", server)
        type(app, "setup-token", token, secure: true)
        // device name is pre-filled
        app.buttons["setup-go"].click()
        exists(app.staticTexts["phrase-word-24"], 30, "24-word phrase")
        let words = (1...24).map { app.staticTexts["phrase-word-\($0)"].label }
        XCTAssertFalse(app.buttons["phrase-continue"].isEnabled, "Continue must be gated behind the confirmation")
        app.checkBoxes["phrase-stored"].click()
        XCTAssertTrue(app.buttons["phrase-continue"].isEnabled)
        app.buttons["phrase-continue"].click()
        exists(app.buttons["nav-Box"].firstMatch.exists ? app.buttons["nav-Box"] : app.staticTexts["Box"], 15, "vault after set-up")
        return words.joined(separator: " ")
    }

    private func addLogin(_ app: XCUIApplication, title: String, user: String, password: String) {
        app.menuButtons["browser-add"].click()
        app.menuItems["Login"].click()
        type(app, "editor-title", title)
        type(app, "editor-username", user)
        type(app, "editor-password", password, secure: true)
        app.buttons["editor-save"].click()
        exists(app.staticTexts["detail-title"], 10, "detail after save")
    }

    func testOnboardingAddEditLockUnlockPersistRecoverImport() throws {
        // 1. onboarding against the real server
        let dir1 = freshDir()
        var app = launch(dir1)
        let phrase = onboard(app)
        XCTAssertEqual(phrase.split(separator: " ").count, 24)

        // 2. add an item; it appears in the list and the detail shows the username
        addLogin(app, title: "Acme Flow Test", user: "flow.user@acme.test", password: "Fl0w-Pass-123")
        exists(app.staticTexts["row-Acme Flow Test"].firstMatch.exists ? app.staticTexts["row-Acme Flow Test"] : app.cells.containing(.staticText, identifier: "row-Acme Flow Test").firstMatch)
        XCTAssertEqual(app.staticTexts["value-user"].label, "flow.user@acme.test")
        // password is masked until revealed (no extra prompt in the default mode)
        XCTAssertNotEqual(app.staticTexts["value-pass"].label, "Fl0w-Pass-123")
        app.buttons["reveal-pass"].click()
        XCTAssertEqual(app.staticTexts["value-pass"].label, "Fl0w-Pass-123")

        // 3. sync indicator reaches "Synced"
        let status = app.staticTexts["sync-status"]
        exists(status)
        let deadline = Date().addingTimeInterval(25)
        while !status.label.hasPrefix("Synced") && Date() < deadline { Thread.sleep(forTimeInterval: 0.5) }
        XCTAssertTrue(status.label.hasPrefix("Synced"), "sync status was: \(status.label)")

        // 4. lock → unlock
        app.buttons["lock-button"].click()
        exists(app.buttons["unlock-button"], 10, "locked screen")
        XCTAssertFalse(app.staticTexts["detail-title"].exists, "no vault content while locked")
        app.buttons["unlock-button"].click()
        exists(app.buttons["lock-button"], 10, "unlocked again")

        // 5. relaunch: still configured, starts locked, data persisted
        app.terminate()
        app = launch(dir1)
        app.activate()
        exists(app.buttons["unlock-button"], 20, "locked on relaunch")
        app.buttons["unlock-button"].click()
        exists(app.buttons["lock-button"])
        exists(app.staticTexts["Acme Flow Test"].firstMatch, 10, "item persisted across relaunch")
        app.terminate()

        // 6. recovery on a fresh store from the phrase (items come back from the server)
        let dir2 = freshDir()
        app = launch(dir2)
        exists(app.textFields["setup-server"], 20)
        app.radioButtons["Recover"].click()
        type(app, "setup-server", server)
        let phraseField = app.textViews["setup-phrase"]
        exists(phraseField)
        phraseField.click()
        phraseField.typeText(phrase)
        app.buttons["setup-go"].click()
        exists(app.buttons["lock-button"], 30, "vault after recovery")
        exists(app.staticTexts["Acme Flow Test"].firstMatch, 20, "item restored from server after recovery")

        // 7. import a generated fake 1pux
        if let path = ProcessInfo.processInfo.environment["BISEL_TEST_1PUX"] {
            app.buttons["nav-Import"].click()
            type(app, "import-debug-path", path + "\n")
            exists(app.staticTexts["import-summary"], 10)
            app.buttons["import-run"].click()
            exists(app.staticTexts["import-done"], 30)
            app.buttons["nav-Box"].click()
            exists(app.staticTexts["Acme Mail (FAKE)"].firstMatch, 10, "imported login in list")
        }
        app.terminate()
    }
}
