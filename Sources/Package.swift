// swift-tools-version: 6.2
import PackageDescription

// The retained Computer app is built separately from the legacy Manager so
// its deployment target can remain macOS 13 while Manager work is retired.
let package = Package(
    name: "HelicoidMac",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "HelicoidComputer", targets: ["HelicoidComputer"]),
    ],
    targets: [
        .target(
            name: "HelicoidCore",
            path: "HelicoidCore",
            exclude: [
                "Fixtures/DevelopmentFixtures.swift",
                "Monitoring/OverviewModel.swift",
                "Setup/GuidedServerSetupModel.swift",
            ]
        ),
        .executableTarget(
            name: "HelicoidComputer",
            dependencies: ["HelicoidCore"],
            path: "HelicoidComputer",
            resources: [
                .copy("Resources/Brand"),
            ],
            swiftSettings: [
                .defaultIsolation(MainActor.self),
            ]
        ),
    ]
)
