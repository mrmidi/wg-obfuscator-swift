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
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.1")
    ],
    targets: [
        .target(
            name: "WGObfuscator",
            dependencies: [
                .product(name: "Logging", package: "swift-log")
            ],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
                // NOTE: For maximum performance, ensure the consuming Xcode project
                // has "Swift Compiler - Code Generation" set to:
                // - Optimization Level: Optimize for Speed [-O]
                // - Compilation Mode: Whole Module (not Incremental)
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
