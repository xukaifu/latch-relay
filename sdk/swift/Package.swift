// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LatchRelay",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "LatchRelay", targets: ["LatchRelay"]),
        .executable(name: "latch-e2e", targets: ["LatchE2E"]),
    ],
    targets: [
        .target(name: "LatchRelay"),
        .executableTarget(name: "LatchE2E", dependencies: ["LatchRelay"]),
        .testTarget(name: "LatchRelayTests", dependencies: ["LatchRelay"]),
    ]
)
