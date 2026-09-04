// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "QVaultCrypto",
    platforms: [
        .macOS("26.0"),
        .iOS("26.0")
    ],
    products: [
        .library(name: "QVaultCrypto", targets: ["QVaultCrypto"])
    ],
    targets: [
        .target(
            name: "CArgon2",
            path: "Sources/QVaultCrypto/Cargon2",
            exclude: ["excluded"],
            publicHeadersPath: "."
        ),
        .target(
            name: "QVaultCrypto",
            dependencies: ["CArgon2"],
            path: "Sources/QVaultCrypto",
            exclude: ["Cargon2"]
        ),
        .testTarget(
            name: "QVaultCryptoTests",
            dependencies: ["QVaultCrypto"],
            path: "Tests/QVaultCryptoTests"
        )
    ]
)