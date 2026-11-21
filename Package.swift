// swift-tools-version: 5.7
import PackageDescription

let package = Package(
    name: "PocketShark",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(name: "PocketSharkCore", targets: ["SharkMobileCore"]),
        .executable(name: "PocketSharkCLI", targets: ["SharkMobileCLI"]),
        .library(name: "SharkMobileCore", targets: ["SharkMobileCore"]),
        .executable(name: "SharkMobileCLI", targets: ["SharkMobileCLI"])
    ],
    targets: [
        .target(
            name: "SharkMobileCore",
            path: "Sources/SharkMobileCore"
        ),
        .executableTarget(
            name: "SharkMobileCLI",
            dependencies: ["SharkMobileCore"],
            path: "Sources/SharkMobileCLI"
        )
    ]
)
