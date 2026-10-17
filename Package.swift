// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "HelicoidMac",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "HelicoidCore", targets: ["HelicoidCore"]),
        .executable(name: "HelicoidManager", targets: ["HelicoidManager"]),
        .executable(name: "HelicoidComputer", targets: ["HelicoidComputer"]),
    ],
    targets: [
        .target(
            name: "HelicoidCore",
            path: "Sources/HelicoidCore"
        ),
        .executableTarget(
            name: "HelicoidManager",
            dependencies: ["HelicoidCore"],
            path: "Sources/HelicoidManager",
            resources: [
                .copy("Resources/Brand"),
            ],
            swiftSettings: [
                .defaultIsolation(MainActor.self),
            ]
        ),
        .executableTarget(
            name: "HelicoidComputer",
            dependencies: ["HelicoidCore"],
            path: "Sources/HelicoidComputer",
            resources: [
                .copy("Resources/Brand"),
            ],
            swiftSettings: [
                .defaultIsolation(MainActor.self),
            ]
        ),
        .testTarget(
            name: "HelicoidCoreTests",
            dependencies: ["HelicoidCore"],
            path: "Tests/HelicoidCoreTests"
        ),
        .testTarget(
            name: "HelicoidManagerTests",
            dependencies: ["HelicoidManager", "HelicoidCore"],
            path: "Tests/HelicoidManagerTests"
        ),
        .testTarget(
            name: "HelicoidComputerTests",
            dependencies: ["HelicoidComputer", "HelicoidCore"],
            path: "Tests/HelicoidComputerTests"
        ),
    ]
)
