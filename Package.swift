// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "CPcap",
    platforms: [ // without platforms specified building on macOS produces interesting link errors
        .macOS("13.3"), .iOS(.v14)
    ],
    products: [
        .library(name: "CPcap", targets: ["CPcap"]),
        .library(name: "SwiftPcap", targets: ["SwiftPcap"]),
        .executable(name: "pcapdump", targets: ["pcapdump"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0")
    ],
    targets: [
        .systemLibrary(
            name: "CPcap",
            path: "Sources/CPcap",
            pkgConfig: "libpcap",
            providers: [
                .apt(["libpcap-dev"]),
                .brew(["libpcap"])
            ]
        ),
        .target(
            name: "SwiftPcap",
            dependencies: ["CPcap"],
            path: "Sources/SwiftPcap"
        ),
        .executableTarget(
            name: "pcapdump",
            dependencies: [
                "SwiftPcap",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/pcapdump"
        )
    ]
)
