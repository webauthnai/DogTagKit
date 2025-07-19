// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DogTagKit",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "DogTagKit",
            targets: ["DogTagKit"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "DogTagKit",
            dependencies: []
        ),
        .testTarget(
            name: "DogTagKitTests",
            dependencies: ["DogTagKit"]
        )
    ]
) 
