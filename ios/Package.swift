// swift-tools-version:5.9
import PackageDescription

/**
 AdShield battery core for Apple platforms.

 This is a library, not an app, on purpose: the measurement and alert rules are the part
 that has to be right, and a library can be compiled and tested on a macOS runner with no
 device, no signing certificate and no Apple developer account. The app target that wraps
 it is added in Xcode in two minutes (see docs/IOS.md).
 */
let package = Package(
    name: "AdShieldBattery",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "AdShieldBattery", targets: ["AdShieldBattery"])
    ],
    targets: [
        .target(name: "AdShieldBattery"),
        .testTarget(name: "AdShieldBatteryTests", dependencies: ["AdShieldBattery"])
    ]
)
