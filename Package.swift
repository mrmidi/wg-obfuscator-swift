// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "WGObfuscator",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(
            name: "WGObfuscator",
            targets: ["WGObfuscator"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "WGObfuscator",
            dependencies: [],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .unsafeFlags(["-warnings-as-errors"])
            ]
        ),
        .testTarget(
            name: "WGObfuscatorTests",
            dependencies: ["WGObfuscator"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        )
    ],
    swiftLanguageModes: [.v6]
)
