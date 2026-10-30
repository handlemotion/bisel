import XCTest

/// Flow tests on the real app (BiselDev build: software keys, Debug hooks) with a throwaway store. No server: "Create a box"
/// makes a local-only box, which is the first-run path. Run with
///   cd apple && xcodegen generate --spec project.dev.yml
///   xcodebuild test -project BiselDev.xcodeproj -scheme Bisel -only-testing:BiselUITests -destination 'platform=macOS' \
///     CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM=
/// Each test launches with its own BISEL_DATA_DIR and the Debug-only BISEL_DEV_SKIP_BIOMETRIC, and only drives Bisel's own windows.
/// Identifiers a test needs that the views do not have yet are listed in NEEDED-IDS.md; those steps use labels and say so.
final class BiselFlowUITests: XCTestCase {
    private var dirs: [URL] = []
    private var apps: [XCUIApplication] = []

    override func setUp() { continueAfterFailure = false }
    override func tearDown() {
        apps.forEach { $0.terminate() }
        dirs.forEach { try? FileManager.default.removeItem(at: $0) }
        apps = []; dirs = []
    }

    private func freshDir() -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("bisel-ui-\(UUID().uuidString)")
        dirs.append(d)
        return d
    }

    private func launch(_ dir: URL) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment = ["BISEL_DATA_DIR": dir.path, "BISEL_DEV_SKIP_BIOMETRIC": "1"]
        app.launch()
        apps.append(app)
        return app
    }

    @discardableResult
    private func exists(_ el: XCUIElement, _ timeout: TimeInterval = 10, _ msg: String = "") -> Bool {
        let ok = el.waitForExistence(timeout: timeout)
        XCTAssertTrue(ok, "expected \(el) \(msg)")
        return ok
    }

    private func gone(_ el: XCUIElement, _ timeout: TimeInterval = 10, _ msg: String = "") {
        let predicate = NSPredicate(format: "exists == false")
        let result = XCTWaiter().wait(for: [expectation(for: predicate, evaluatedWith: el)], timeout: timeout)
        XCTAssertEqual(result, .completed, "expected \(el) to go away \(msg)")
    }

    /// The 24 words on the recovery phrase screen.
    private func words(_ app: XCUIApplication) -> [String] {
        exists(app.staticTexts["phrase-word-24"], 20, "24-word phrase")
        return (1...24).map { app.staticTexts["phrase-word-\($0)"].label }
    }

    /// Welcome → Create a box → recovery phrase on screen.
    private func createBox(_ app: XCUIApplication) -> [String] {
        let create = app.buttons["setup-go"]
        exists(create, 30, "welcome screen on first run")
        XCTAssertEqual(create.label, "Create a box")
        create.click()
        return words(app)
    }

    /// Welcome → phrase → Continue → import step → Skip for now. The window closes afterwards.
    private func onboard(_ app: XCUIApplication) {
        _ = createBox(app)
        app.buttons["phrase-continue"].click()
        exists(app.buttons["import-finish"], 15, "import step after the phrase")
        app.buttons["import-finish"].click()
        gone(app.buttons["import-finish"], 15, "after Skip for now")
    }

    /// The window is closed after onboarding; "Open Bisel" in the menu-bar item brings the settings window back.
    private func openSettingsWindow(_ app: XCUIApplication) {
        let item = app.statusItems.firstMatch
        exists(item, 10, "menu-bar item")
        item.click()
        let open = app.menuItems["Open Bisel"]
        exists(open, 5, "Open Bisel in the menu-bar menu")
        open.click()
        exists(app.buttons["nav-General"].firstMatch, 15, "settings window")
    }

    // MARK: first run

    func testWelcomeShowsCreateABoxAndIAlreadyHaveOne() {
        let app = launch(freshDir())
        exists(app.buttons["setup-go"], 30, "Create a box")
        XCTAssertTrue(app.buttons["setup-mode-recover"].exists, "I already have one")
        XCTAssertFalse(app.buttons["phrase-continue"].exists)
    }

    func testRecoveryPhraseBackSaveMenuContinue() {
        let app = launch(freshDir())
        let first = createBox(app)
        XCTAssertEqual(Set(first).count > 1, true)
        XCTAssertTrue(app.buttons["phrase-back"].exists, "Back is offered on a fresh box")

        // Save is a menu with Copy and Download…
        let save = app.menuButtons["phrase-save"].exists ? app.menuButtons["phrase-save"] : app.buttons["phrase-save"]
        exists(save, 5, "Save")
        save.click()
        exists(app.menuItems["Copy"], 5, "Copy in the Save menu")
        XCTAssertTrue(app.menuItems["Download…"].exists, "Download… in the Save menu")
        app.typeKey(.escape, modifierFlags: [])
        gone(app.menuItems["Copy"], 5, "after closing the Save menu")

        // Back discards the box: the welcome screen returns, and a new box gets a different phrase.
        app.buttons["phrase-back"].click()
        exists(app.buttons["setup-go"], 15, "welcome after Back")
        XCTAssertFalse(app.staticTexts["phrase-word-1"].exists, "no phrase while on the welcome screen")
        app.buttons["setup-go"].click()
        let second = words(app)
        XCTAssertNotEqual(first, second, "a discarded box must not come back with the same phrase")

        // Continue leaves the phrase screen for the import step.
        app.buttons["phrase-continue"].click()
        exists(app.buttons["import-finish"], 15, "import step")
        XCTAssertEqual(app.buttons["import-finish"].label, "Skip for now")
        XCTAssertTrue(app.buttons["import-choose"].exists, "Choose file…")
        XCTAssertFalse(app.staticTexts["phrase-word-1"].exists, "the phrase is shown once")
    }

    func testSkipImportClosesTheWindow() {
        let app = launch(freshDir())
        onboard(app)
        XCTAssertFalse(app.buttons["setup-go"].exists)
        XCTAssertFalse(app.buttons["phrase-continue"].exists)
    }

    // MARK: settings window

    func testSettingsWindowSections() {
        let app = launch(freshDir())
        onboard(app)
        openSettingsWindow(app)

        // General: the settings form of a local-only box.
        let general = app.buttons["nav-General"].firstMatch
        let devices = app.buttons["nav-Devices"].firstMatch
        let importer = app.buttons["nav-Import"].firstMatch
        exists(devices, 5); exists(importer, 5)
        general.click()
        exists(app.buttons["settings-export"], 10, "General section (Export backup…)")
        XCTAssertTrue(app.buttons["settings-new-phrase"].exists, "New recovery phrase…")

        devices.click()
        exists(app.buttons["devices-refresh"], 10, "Devices section")
        XCTAssertFalse(app.buttons["settings-export"].exists, "General content is gone")

        importer.click()
        exists(app.buttons["import-choose"], 10, "Import section")
        XCTAssertFalse(app.buttons["devices-refresh"].exists, "Devices content is gone")

        general.click()
        exists(app.buttons["settings-export"], 10, "back on General")

        // Lock from the sidebar: the window turns into the lock screen.
        app.buttons["lock-button"].click()
        exists(app.buttons["unlock-button"], 10, "lock screen")
        XCTAssertFalse(app.buttons["settings-export"].exists, "nothing from the box while locked")
        app.buttons["unlock-button"].click()   // Touch ID is bypassed by BISEL_DEV_SKIP_BIOMETRIC
        exists(app.buttons["lock-button"], 10, "unlocked again")
    }

    // MARK: persistence

    func testRelaunchKeepsTheBoxAndStartsLocked() {
        let dir = freshDir()
        var app = launch(dir)
        onboard(app)
        app.terminate()

        app = launch(dir)
        // An existing box does not show the welcome screen again.
        let item = app.statusItems.firstMatch
        exists(item, 20, "menu-bar item")
        XCTAssertFalse(app.buttons["setup-go"].exists, "the box survived the relaunch")
        item.click()
        exists(app.menuItems["Open Bisel"], 5).self
        app.menuItems["Open Bisel"].click()
        exists(app.buttons["unlock-button"], 15, "locked on relaunch")
        app.buttons["unlock-button"].click()
        exists(app.buttons["nav-General"].firstMatch, 15, "settings after unlock")
    }
}
