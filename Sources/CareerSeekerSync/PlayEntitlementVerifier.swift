import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import _CryptoExtras

/// §4.3.2 entitlement verification — **engine role, not client role.**
///
/// It is implemented here for one reason: to prove the whole vector corpus is consumable
/// by a third implementation, and to make a scope problem visible in code rather than in
/// a memo. Three facts follow from writing it:
///
///  1. **The phone never runs this.** §4.3.2 makes the phone a courier and the engine the
///     verifier. Nothing in the iOS client would call this type; it exists in the package
///     only so `conformance` can exercise the five entitlement vectors end to end.
///
///  2. **The kind is Google-Play-shaped.** `packageName == app.careerseeker.dashboard`,
///     an RSA key minted by Play Console, and `purchaseState == 0` are Android facts. An
///     iPhone has no Play purchase to courier. The App Store equivalent is a StoreKit 2
///     `JWSTransaction`: ES256, x5c chaining to the Apple Root CA, verifiable offline by
///     the engine — the same courier/verifier shape, a completely different payload. v1
///     has no kind for it, which is why the iOS work needs `entitlement_appstore`
///     reserved before v1 ossifies (PQ-IOS-1).
///
///  3. **The crypto is off CryptoKit's map.** CryptoKit has no RSA at all. This file uses
///     `_CryptoExtras`, an underscored module with no API-stability promise, and even the
///     digest is `Insecure.SHA1` — Google's fixed IAB format, not a choice. On a real
///     Apple platform the engine-side equivalent would go through Security.framework
///     (`SecKeyVerifySignature` with `.rsaSignatureMessagePKCS1v15SHA1`). Worth knowing
///     before anyone assumes a macOS engine port inherits this verifier for free.
public enum PlayEntitlementVerifier {

    public enum Result: String, Equatable {
        case accepted
        case signatureInvalid = "signature_invalid"
        case wrongPackage = "wrong_package"
        case wrongProduct = "wrong_product"
        case notPurchased = "not_purchased"
        case malformed
    }

    public struct Configuration {
        /// Base64 X.509 SubjectPublicKeyInfo — the "License Key for This Application"
        /// from Play Console. Configuration, never a baked-in constant: the production
        /// key does not exist until the Play app does.
        public let rsaPublicKeySPKIBase64: String
        public let expectedPackageName: String
        public let expectedProductIds: Set<String>
        public let purchasedState: Int

        public init(
            rsaPublicKeySPKIBase64: String,
            expectedPackageName: String,
            expectedProductIds: Set<String>,
            purchasedState: Int = 0
        ) {
            self.rsaPublicKeySPKIBase64 = rsaPublicKeySPKIBase64
            self.expectedPackageName = expectedPackageName
            self.expectedProductIds = expectedProductIds
            self.purchasedState = purchasedState
        }
    }

    /// Verification order is fixed by §4.3.2: signature, then package, then product, then
    /// state. Each failure has a distinct reason, and the corpus pins one negative vector
    /// per reason — so a checker that short-circuits in the wrong order fails visibly
    /// instead of quietly accepting a wrong-product purchase as a signature problem.
    public static func verify(originalJSON: String, signatureBase64: String, config: Configuration) -> Result {
        guard let spki = Data(base64Encoded: config.rsaPublicKeySPKIBase64),
              let publicKey = try? _RSA.Signing.PublicKey(derRepresentation: spki)
        else { return .malformed }

        // Standard base64 with padding, not base64url: this is payload *content* emitted
        // by Play, so the §3 framing rule deliberately does not apply (§4.3.2).
        guard let signatureBytes = Data(base64Encoded: signatureBase64) else { return .malformed }

        // Verify over the exact bytes of the string as received. Re-serialising the JSON
        // would change the bytes the signature covers — the single most likely way to
        // break this and not notice until a paying user's unlock silently fails.
        let payloadBytes = Data(originalJSON.utf8)
        let digest = Insecure.SHA1.hash(data: payloadBytes)
        let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes)

        guard publicKey.isValidSignature(signature, for: digest, padding: .insecurePKCS1v1_5) else {
            return .signatureInvalid
        }

        guard let any = try? JSONSerialization.jsonObject(with: payloadBytes, options: []),
              let obj = any as? [String: Any]
        else { return .malformed }

        guard let packageName = obj["packageName"] as? String else { return .malformed }
        guard packageName == config.expectedPackageName else { return .wrongPackage }

        guard let productId = obj["productId"] as? String else { return .malformed }
        guard config.expectedProductIds.contains(productId) else { return .wrongProduct }

        // The raw JSON's purchased value is 0. `Purchase.getPurchaseState()` on the
        // Android side remaps it to 1; the engine reads the raw JSON, so 0 is correct
        // here and reading the Android enum's value would invert the check.
        guard let state = obj["purchaseState"] as? Int else { return .malformed }
        guard state == config.purchasedState else { return .notPurchased }

        return .accepted
    }
}
