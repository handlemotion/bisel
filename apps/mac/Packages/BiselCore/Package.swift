// swift-tools-version: 6.1
import PackageDescription

// Module names carry a `Bisel` prefix: a module called `Crypto` would collide with
// swift-crypto's `Crypto` (pulled in by the OTP package), and a module called `Vault`
// would shadow the public `Vault` type.
//
// The software key store (BISEL_SOFTWARE_KEYS) is only compiled when a consumer opts in with
// the `SoftwareKeys` trait. The Mac app never does; bisel-dev and the flow tests do.
let package = Package(
    name: "BiselCore",
    platforms: [.macOS("26.0"), .iOS("26.0")],
    products: [
        .library(name: "BiselCore", targets: ["BiselCore"]),
        .library(name: "BiselCrypto", targets: ["BiselCrypto"]),
        .library(name: "BiselKeyStore", targets: ["BiselKeyStore"]),
        .library(name: "BiselVault", targets: ["BiselVault"]),
        .library(name: "BiselSync", targets: ["BiselSync"]),
        .library(name: "BiselRecovery", targets: ["BiselRecovery"]),
        .library(name: "BiselTOTP", targets: ["BiselTOTP"]),
        .library(name: "BiselTestSupport", targets: ["BiselTestSupport"]),   // dev/test only: spawns the local server
    ],
    traits: [
        .trait(name: "SoftwareKeys", description: "Compile the software P-256 DeviceKeyStore (BISEL_SOFTWARE_KEYS). Never enable for Release."),
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", exact: "7.11.1"),
        .package(url: "https://github.com/pengpengliu/BIP39.git", exact: "1.0.2"),
        .package(url: "https://github.com/lachlanbell/SwiftOTP.git", exact: "3.0.2"),
    ],
    targets: [
        .target(name: "BiselCrypto", dependencies: [.product(name: "BIP39", package: "BIP39")]),
        .target(name: "BiselKeyStore", dependencies: ["BiselCrypto"],
                swiftSettings: [.define("BISEL_SOFTWARE_KEYS", .when(traits: ["SoftwareKeys"]))]),
        .target(name: "BiselTOTP", dependencies: [.product(name: "SwiftOTP", package: "SwiftOTP")]),
        .target(name: "BiselVault", dependencies: ["BiselCrypto", "BiselKeyStore", "BiselTOTP",
                                                    .product(name: "GRDB", package: "GRDB.swift")]),
        .target(name: "BiselSync", dependencies: ["BiselCrypto", "BiselKeyStore", "BiselVault"]),
        .target(name: "BiselRecovery", dependencies: ["BiselCrypto", "BiselKeyStore", "BiselVault", "BiselSync"]),
        .target(name: "BiselCore", dependencies: ["BiselCrypto", "BiselKeyStore", "BiselVault", "BiselSync",
                                                   "BiselRecovery", "BiselTOTP"],
                swiftSettings: [.define("BISEL_SOFTWARE_KEYS", .when(traits: ["SoftwareKeys"]))]),
        .target(name: "BiselTestSupport"),
        .testTarget(name: "BiselFlowTests", dependencies: ["BiselCore", "BiselTestSupport"],
                    swiftSettings: [.define("BISEL_SOFTWARE_KEYS", .when(traits: ["SoftwareKeys"]))]),
    ],
    swiftLanguageModes: [.v6]
)
