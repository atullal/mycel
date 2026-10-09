import XCTest

/// Drives the installed Mycel app (dev.mycel.host) through its real UI with
/// the on-screen keyboard. Needs a conversation with the contact named in
/// MYCEL_CONTACT (default "Desk Test"); see docs/PLATFORMS.md.
final class KeyboardTests: XCTestCase {
    func shot(_ app: XCUIApplication, _ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    func testReplyWithTheOnScreenKeyboard() throws {
        let contact = ProcessInfo.processInfo.environment["MYCEL_CONTACT"] ?? "Desk Test"
        let app = XCUIApplication(bundleIdentifier: "dev.mycel.host")
        app.launch()
        let row = app.staticTexts[contact].firstMatch
        XCTAssert(row.waitForExistence(timeout: 20), "the conversation with \(contact) is listed")
        row.tap()
        let accept = app.buttons["Accept"].firstMatch
        if accept.waitForExistence(timeout: 5) { accept.tap() }
        let composer = app.textViews.firstMatch
        XCTAssert(composer.waitForExistence(timeout: 10), "a composer")
        composer.tap()
        let keyboard = app.keyboards.firstMatch
        XCTAssert(keyboard.waitForExistence(timeout: 10), "the on-screen keyboard came up")
        sleep(2)
        shot(app, "keyboard-up")
        // The keyboard's frame leaves out the bar above it (arrows, Done): 44 pt.
        let k = keyboard.frame
        XCTAssertLessThanOrEqual(composer.frame.maxY, k.minY - 40, "the composer is above the keyboard and its bar")
        let title = app.staticTexts[contact].firstMatch
        XCTAssert(title.frame.minY >= 0 && title.frame.maxY < k.minY, "the header is on screen: \(title.frame)")

        composer.typeText("Typed on the iPhone keyboard")
        app.buttons["Send"].firstMatch.tap()
        sleep(2)
        shot(app, "sent")
        // still typing after a send: the layout must hold
        composer.typeText("And a second one")
        sleep(2)
        shot(app, "second")
        let k2 = app.keyboards.firstMatch.frame
        let c2 = composer.frame
        let t2 = app.staticTexts[contact].firstMatch.frame
        XCTAssertLessThanOrEqual(c2.maxY, k2.minY - 40, "composer above the keyboard and its bar after sending")
        XCTAssertGreaterThan(c2.maxY, k2.minY - 140, "composer just above the keyboard: \(c2) vs \(k2)")
        XCTAssert(t2.minY >= 0 && t2.maxY < k2.minY, "header on screen after sending: \(t2)")
    }
}
