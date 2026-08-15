import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The client-role receiver. Holds the active pairing's keys and the per-direction
/// sequence cursors, and applies the §5–§7 checks **in a fixed order**.
///
/// The order is the security property, not an implementation detail. Two rules in the
/// spec are explicitly about ordering rather than about the checks themselves:
///
///   - §5.3: `key_id` is checked *before* decryption, and a receiver "MUST NOT rely on
///     the AEAD tag to catch it… treating 'it decrypted' as 'it was authorized' is how a
///     revoked device keeps working."
///   - §6.2: replay rejection happens "on the header, before any decryption attempt, so
///     a replayed envelope costs a comparison rather than a crypto operation."
///
/// So `accept` is written as a gauntlet with the cheap, authorization-relevant checks
/// first and the crypto last. Getting the right answer for the wrong reason is a failure
/// the vector corpus is designed to catch (§10: "Rejecting for the wrong reason is a
/// failure: it usually means a check fired earlier than intended").
public final class EnvelopeReceiver {

    public struct Accepted {
        public let envelope: Envelope
        public let kind: String
        public let plaintext: Data
    }

    private let pairingId: String
    private let activeKeyId: String
    private let keyE2P: SymmetricKey
    private let keyP2E: SymmetricKey
    /// The pairing's device signing key, learned from the encrypted pairing completion
    /// (§5.2.2) — never from the envelope being verified. `sig-by-revoked-key` is the
    /// vector that fails any implementation which trusts a per-envelope key.
    private let deviceSigningPublicKey: P256.Signing.PublicKey?

    private var highestAccepted: [Direction: Int64] = [.engineToPhone: 0, .phoneToEngine: 0]

    public init(
        pairingId: String,
        activeKeyId: String,
        keyE2P: SymmetricKey,
        keyP2E: SymmetricKey,
        deviceSigningPublicKey: P256.Signing.PublicKey?
    ) {
        self.pairingId = pairingId
        self.activeKeyId = activeKeyId
        self.keyE2P = keyE2P
        self.keyP2E = keyP2E
        self.deviceSigningPublicKey = deviceSigningPublicKey
    }

    public func highestAcceptedSeq(_ dir: Direction) -> Int64 { highestAccepted[dir] ?? 0 }

    public func accept(wireBytes: Data) throws -> Accepted {
        // 1 — size (§3.1). Before the parse, so an oversized body is never materialised.
        guard wireBytes.count <= SyncProtocol.maxEnvelopeBytes else { throw SyncError.tooLarge }

        // 2 — strict parse (§3), unknown top-level fields rejected.
        let env = try Envelope.parse(wireBytes: wireBytes)

        // 3 — version (§7.1), "without attempting decryption".
        guard env.v == SyncProtocol.version else { throw SyncError.versionUnsupported }

        // 4 — pairing identity. Not spelled out as a numbered rule, but an envelope for
        // another pairing is by definition one this receiver has no channel for.
        guard env.pairing == pairingId else { throw SyncError.pairingUnknown }

        // 5 — key id (§5.3), before decryption. Revocation is an explicit check, never a
        // side effect of cryptography.
        guard env.keyId == activeKeyId else { throw SyncError.keyUnknown }

        // 6 — replay (§6.2), on the header. Gaps are legal and MUST NOT stall the stream;
        // only non-advancement is rejected.
        guard env.seq > highestAcceptedSeq(env.dir) else { throw SyncError.replayRejected }

        // 7 — signature presence on the header (§3): an e2p envelope must never carry
        // `sig`. The engine holds no device key, so a signed e2p envelope is a forgery
        // attempt or a confused implementation; either way it is not acceptable. This
        // half of the rule is checkable pre-decryption because `dir` is a header field.
        if env.dir == .engineToPhone && env.sigB64u != nil { throw SyncError.badSignature }

        // 8 — strict base64url of the framing fields (§3).
        let nonceBytes: Data
        let ciphertextBytes: Data
        do {
            nonceBytes = try Base64URL.decode(env.nonceB64u)
            ciphertextBytes = try Base64URL.decode(env.ciphertextB64u)
        } catch {
            throw SyncError.decryptFailed
        }
        guard nonceBytes.count == SyncProtocol.nonceBytes,
              ciphertextBytes.count > SyncProtocol.tagBytes
        else { throw SyncError.decryptFailed }

        // 9 — device signature, if present, over the exact wire artifacts (§5.4).
        // Verified *before* decryption: the signature binds header, nonce and ciphertext
        // bytes, none of which require the plaintext to check.
        if let sigB64u = env.sigB64u {
            guard let trustedKey = deviceSigningPublicKey else { throw SyncError.badSignature }
            guard let sigBytes = try? Base64URL.decode(sigB64u),
                  sigBytes.count == 64,
                  let signature = try? P256.Signing.ECDSASignature(rawRepresentation: sigBytes)
            else { throw SyncError.badSignature }

            let input = Self.signatureInput(aad: env.aad, nonceB64u: env.nonceB64u, ciphertext: ciphertextBytes)
            guard trustedKey.isValidSignature(signature, for: input) else { throw SyncError.badSignature }
        }

        // 10 — AEAD (§5.1). AAD is rebuilt from the parsed header, so a rewritten routing
        // field fails here rather than being honoured.
        let key = env.dir == .engineToPhone ? keyE2P : keyP2E
        let plaintext: Data
        do {
            let ct = ciphertextBytes.prefix(ciphertextBytes.count - SyncProtocol.tagBytes)
            let tag = ciphertextBytes.suffix(SyncProtocol.tagBytes)
            let box = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonceBytes),
                ciphertext: ct,
                tag: tag
            )
            plaintext = try AES.GCM.open(box, using: key, authenticating: env.aad)
        } catch {
            throw SyncError.decryptFailed
        }

        // 11 — payload vocabulary (§4.2/§4.3). A receiver that does not recognise `kind`
        // MUST NOT act on `body`, so the kind is resolved before the body is looked at at
        // all — this implementation never even parses `body` into a typed shape here.
        guard let any = try? JSONSerialization.jsonObject(with: plaintext, options: []),
              let obj = any as? [String: Any],
              let kind = obj["kind"] as? String
        else { throw SyncError.malformed }

        if PayloadKind.reservedForL2.contains(kind) { throw SyncError.unknownKind }
        guard PayloadKind.isKnown(kind, direction: env.dir) else { throw SyncError.unknownKind }

        // 12 — signature *requirement* (§3), necessarily post-decryption: whether a
        // signature was required is a fact about the kind, and the kind is inside the
        // ciphertext. This is the one check the spec explicitly orders after decryption.
        if PayloadKind.stateChanging.contains(kind) && env.sigB64u == nil {
            throw SyncError.badSignature
        }

        // Only now does the cursor move. A rejected envelope MUST NOT advance it — see
        // the note in the conformance runner about `invalid-aad-tampered-seq`, whose
        // forged seq of 9999 would otherwise wedge the stream permanently.
        highestAccepted[env.dir] = env.seq
        return Accepted(envelope: env, kind: kind, plaintext: plaintext)
    }

    /// §5.4 signature input:
    /// `careerseeker/v1/cmd|<AAD>|<nonce b64u>|<sha256-hex of the raw ciphertext bytes>`
    ///
    /// ASCII, and hex is lowercase. The spec does not say "lowercase" in so many words,
    /// but the vectors do, and C#'s `ToString("X2")` defaults to upper — the same class
    /// of hazard already recorded once in this program for `rotate_to`. Pinned here
    /// rather than left to a default.
    public static func signatureInput(aad: Data, nonceB64u: String, ciphertext: Data) -> Data {
        let digest = SHA256.hash(data: ciphertext)
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        var out = Data("careerseeker/v1/cmd|".utf8)
        out.append(aad)
        out.append(Data("|\(nonceB64u)|\(hex)".utf8))
        return out
    }
}
