// swift-tools-version: 6.1
import PackageDescription

// Headless benchmark of what the app does on launch, on unlock and in the panel, against a seeded box. Uses the app's own search
// sources (Sources/bisel-bench/App links to them) and the software key store: a dev tool, never shipped. See README.md.
let package = Package(
    name: "bisel-bench",
    platforms: [.macOS("26.0")],
    dependencies: [
        .package(path: "../../Packages/BiselCore", traits: ["SoftwareKeys"]),
        .package(url: "https://github.com/ordo-one/FuzzyMatch", exact: "1.4.0"),
    ],
    targets: [
        .executableTarget(
            name: "bisel-bench",
            dependencies: [
                .product(name: "BiselCore", package: "BiselCore"),
                .product(name: "FuzzyMatch", package: "FuzzyMatch"),
            ],
            swiftSettings: [.define("BISEL_SOFTWARE_KEYS")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
