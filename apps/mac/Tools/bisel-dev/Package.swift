// swift-tools-version: 6.1
import PackageDescription

// Dev CLI driving BiselCore against a server. Always built with the software key store
// (BISEL_SOFTWARE_KEYS): this tool is for headless flows, never shipped.
let package = Package(
    name: "bisel-dev",
    platforms: [.macOS("26.0")],
    dependencies: [
        .package(path: "../../Packages/BiselCore", traits: ["SoftwareKeys"]),
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2"),
    ],
    targets: [
        .executableTarget(
            name: "bisel-dev",
            dependencies: [
                .product(name: "BiselCore", package: "BiselCore"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            swiftSettings: [.define("BISEL_SOFTWARE_KEYS")]
        ),
        .testTarget(
            name: "BiselDevFlowTests",
            dependencies: ["bisel-dev", .product(name: "BiselTestSupport", package: "BiselCore")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
