// swift-tools-version:5.10

import PackageDescription

let package = Package(
    name: "CPcap",
    products: [
        .library(
            name: "CPcap",
            targets: ["CPcap"]
        )
    ],
    targets: [
        .target(
            name: "CPcap",
            path: ".",
            publicHeadersPath: "include"
        )
    ]
)
