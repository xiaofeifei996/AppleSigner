// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AppleSignerCore",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "AppleSignerCore", targets: ["AppleSignerCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/SideStore/SideSign.git", branch: "main")
    ],
    targets: [
        .target(
            name: "AppleSignerCore",
            dependencies: [.product(name: "SideSign", package: "SideSign")],
            path: "Sources"
        )
    ],
    swiftLanguageModes: [.v6]
)
