// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LatchRelay",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "LatchRelay", targets: ["LatchRelay"]),
    ],
    targets: [
        .target(
            name: "LatchRelay",
            path: "sdk/swift/Sources/LatchRelay"
        ),
        .testTarget(
            name: "LatchRelayTests",
            dependencies: ["LatchRelay"],
            path: "sdk/swift/Tests/LatchRelayTests"
        ),
    ]
)
