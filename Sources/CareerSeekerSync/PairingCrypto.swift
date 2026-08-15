import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// §5.2 key agreement: ECDH P-256 → `ikm = concat(ss)` → HKDF-SHA256 for every derived
/// value.
///
/// A note that matters for the port, recorded where the code is rather than in a
/// roadmap: the P1-CURVE amendment moved this suite from X25519/Ed25519 to P-256 for
/// Android reasons (Keystore cannot do Ed25519 below API 33) and .NET reasons (no
/// XChaCha20 in the BCL). Nobody was considering iOS. The result is that every primitive
/// v1 needs — ECDH P-256, HKDF-SHA256, AES-256-GCM, ECDSA P-256 as raw r||s — is native
/// CryptoKit, and P-256 is the *only* curve the Secure Enclave supports. The amendment
/// made the protocol enclave-native by accident. Under the P0 draft, an iOS device key
/// could not have been hardware-bound at all.
public enum PairingCrypto {

    public struct DerivedKeys {
        public let sharedSecret: Data
        public let kE2P: SymmetricKey
        public let kP2E: SymmetricKey
        public let relayToken: String
        public let confirmCode: String
    }

    /// `ikm` is the concatenation function over the suite's shared secrets — one element
    /// in v1, two under the reserved `p256+mlkem768` hybrid.
    ///
    /// §5.2 flags this line as deliberate and load-bearing: deriving straight from the
    /// raw ECDH output would make the post-quantum migration a breaking change for every
    /// paired device, whereas going through `concat` makes it a suite bump. The Swift
    /// implementation keeps the seam visible for the same reason the C# one does.
    public static func ikm(from secrets: [Data]) -> Data {
        secrets.reduce(into: Data()) { $0.append($1) }
    }

    public static func hkdf(ikm: Data, salt: Data, info: String, outputByteCount: Int) -> Data {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: Data(info.utf8),
            outputByteCount: outputByteCount
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    /// Full §5.2 derivation from this side's private key and the peer's public point.
    public static func derive(
        ownPrivateKey: P256.KeyAgreement.PrivateKey,
        peerPublicKey: P256.KeyAgreement.PublicKey,
        oneTimeSecret: Data
    ) throws -> DerivedKeys {
        let ss = try ownPrivateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        // The 32-byte X coordinate — CryptoKit's SharedSecret is exactly that, unhashed.
        let ssBytes = ss.withUnsafeBytes { Data($0) }
        let material = ikm(from: [ssBytes])

        let kE2P = hkdf(ikm: material, salt: oneTimeSecret, info: "careerseeker/v1/e2p", outputByteCount: 32)
        let kP2E = hkdf(ikm: material, salt: oneTimeSecret, info: "careerseeker/v1/p2e", outputByteCount: 32)
        let token = hkdf(ikm: material, salt: oneTimeSecret, info: "careerseeker/v1/relay-token", outputByteCount: 32)
        let confirmBytes = hkdf(ikm: material, salt: oneTimeSecret, info: "careerseeker/v1/confirm", outputByteCount: 4)

        let be = confirmBytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let confirm = String(format: "%06u", be % 1_000_000)

        return DerivedKeys(
            sharedSecret: ssBytes,
            kE2P: SymmetricKey(data: kE2P),
            kP2E: SymmetricKey(data: kP2E),
            relayToken: Base64URL.encode(token),
            confirmCode: confirm
        )
    }

    /// §5.2.1 provisional relay token — keyed on the one-time secret alone, because the
    /// engine must be able to create the channel before the phone's key exists.
    public static func provisionalRelayToken(oneTimeSecret: Data) -> String {
        Base64URL.encode(hkdf(
            ikm: oneTimeSecret,
            salt: Data("careerseeker/v1/bootstrap".utf8),
            info: "careerseeker/v1/relay-token",
            outputByteCount: 32
        ))
    }

    /// §5.2.2 pairing-completion AAD. `phone_pub` must travel in clear — the engine
    /// cannot derive `k_p2e` without it — so it is bound in here instead. A relay that
    /// swaps the key changes both the derived key and the AAD, and the tag fails either
    /// way; `pairing-mitm-keyswap` is that proof.
    public static func completionAAD(pairing: String, suite: String, phonePublicKeyB64u: String) -> Data {
        Data("careerseeker/v1/pair|\(pairing)|\(suite)|\(phonePublicKeyB64u)".utf8)
    }

    /// Open a sealed pairing completion (engine role, exercised by the pairing vectors).
    public static func openCompletion(
        ciphertext: Data,
        nonce: Data,
        aad: Data,
        key: SymmetricKey
    ) throws -> Data {
        guard ciphertext.count > SyncProtocol.tagBytes else { throw SyncError.decryptFailed }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext.prefix(ciphertext.count - SyncProtocol.tagBytes),
                tag: ciphertext.suffix(SyncProtocol.tagBytes)
            )
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw SyncError.decryptFailed
        }
    }
}
