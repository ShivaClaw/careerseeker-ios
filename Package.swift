// swift-tools-version: 6.0
import PackageDescription

// CareerSeeker iOS sync core.
//
// `CareerSeekerSync` is the client-role implementation of docs/Sync-Protocol.md v1 —
// the code the iPhone dashboard would ship. It imports CryptoKit on Apple platforms and
// swift-crypto everywhere else; the two are API-compatible for every primitive v1 uses,
// which is what lets this build and prove itself on Linux CI before a Mac exists.
//
// `ConformanceRunner` is the executable evidence: it consumes docs/sync-vectors/v1
// (the same files the C# SyncHarness and the Kotlin :core tests read) and prints a
// pass/fail table in the style of the existing offline harnesses. Non-zero exit on any
// failure, so it is CI-wireable as-is.

let package = Package(
    name: "CareerSeekerSync",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "CareerSeekerSync", targets: ["CareerSeekerSync"]),
        .executable(name: "conformance", targets: ["ConformanceRunner"]),
    ],
    dependencies: [
        // On Apple platforms this dependency is inert: the sources prefer CryptoKit.
        // _CryptoExtras is used only by the engine-role Play verifier (RSA), never by
        // the client-role code — see PlayEntitlementVerifier.swift for why that matters.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ],
    targets: [
        .target(
            name: "CareerSeekerSync",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .executableTarget(
            name: "ConformanceRunner",
            dependencies: ["CareerSeekerSync"]
        ),
    ]
)
