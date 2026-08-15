import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

func swiftVersionString() -> String {
    #if swift(>=6.0)
    return "6.x"
    #else
    return "5.x"
    #endif
}

/// Names the crypto backend so a run's provenance is unambiguous. The point of the
/// package is that these two are interchangeable for every primitive v1 uses; the point
/// of printing it is that "interchangeable" should be an observation in the log rather
/// than an assumption in a README.
func cryptoBackendName() -> String {
    #if canImport(CryptoKit)
    return "CryptoKit (Apple)"
    #else
    return "swift-crypto (BoringSSL)"
    #endif
}

/// SHA-256 over the concatenated, name-sorted vector files. Pins a passing run to the
/// exact corpus bytes it passed against.
@MainActor
func vectorDigest(dir: URL, names: [String]) -> String {
    var hasher = SHA256()
    for name in names.sorted() {
        guard let data = try? Data(contentsOf: dir.appendingPathComponent("\(name).json")) else { continue }
        hasher.update(data: Data(name.utf8))
        hasher.update(data: data)
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
}
