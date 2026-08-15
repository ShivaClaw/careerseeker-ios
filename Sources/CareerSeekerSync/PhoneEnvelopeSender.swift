import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Errors local to outbound sequence allocation. They are not wire error codes: the
/// phone discovers them before it has created or sent an envelope.
public enum PhoneEnvelopeSenderError: Error, Equatable, Sendable {
    /// §6.1: p2e sequence numbers start at 1 and must strictly increase.
    case nonIncreasingSequence
    /// The caller asked this sender to seal a payload not allowed in the v1 p2e vocabulary.
    case invalidPayloadKind
}

/// Phone-role p2e envelope sender. The caller persists highestSealedSeq with its pairing
/// state and restores it after a process launch; this type prevents reuse or regression
/// within one process.
public final class PhoneEnvelopeSender {
    private let pairingId: String
    private let activeKeyId: String
    private let keyP2E: SymmetricKey
    private let deviceSigningKey: any DeviceSigningKey
    private var highestSealedSeq: Int64

    public init(
        pairingId: String,
        activeKeyId: String,
        keyP2E: SymmetricKey,
        deviceSigningKey: any DeviceSigningKey,
        highestSealedSeq: Int64 = 0
    ) {
        self.pairingId = pairingId
        self.activeKeyId = activeKeyId
        self.keyP2E = keyP2E
        self.deviceSigningKey = deviceSigningKey
        self.highestSealedSeq = highestSealedSeq
    }

    public func highestSealedSequence() -> Int64 { highestSealedSeq }

    /// Seal a phone-to-engine payload with a fresh AES-GCM nonce. State-changing kinds
    /// carry the required §5.4 device signature; other p2e kinds omit it per §3.
    public func seal(seq: Int64, ts: String, plaintext: Data) throws -> Data {
        guard seq >= 1, seq > highestSealedSeq else {
            throw PhoneEnvelopeSenderError.nonIncreasingSequence
        }

        guard let any = try? JSONSerialization.jsonObject(with: plaintext, options: []),
              let payload = any as? [String: Any],
              let kind = payload["kind"] as? String,
              PayloadKind.isKnown(kind, direction: .phoneToEngine),
              !PayloadKind.reservedForL2.contains(kind)
        else {
            throw PhoneEnvelopeSenderError.invalidPayloadKind
        }

        let aad = Envelope.authenticatedData(
            pairing: pairingId,
            dir: .phoneToEngine,
            seq: seq,
            ts: ts,
            keyId: activeKeyId
        )
        // Supplying no nonce asks the crypto backend for a fresh random 96-bit value.
        let sealed = try AES.GCM.seal(plaintext, using: keyP2E, authenticating: aad)
        let nonceB64u = Base64URL.encode(Data(sealed.nonce))
        var ciphertext = sealed.ciphertext
        ciphertext.append(sealed.tag)

        var wire: [String: Any] = [
            "v": SyncProtocol.version,
            "pairing": pairingId,
            "dir": Direction.phoneToEngine.rawValue,
            "seq": seq,
            "ts": ts,
            "key_id": activeKeyId,
            "nonce": nonceB64u,
            "ciphertext": Base64URL.encode(ciphertext),
        ]

        if PayloadKind.stateChanging.contains(kind) {
            let signatureInput = EnvelopeReceiver.signatureInput(
                aad: aad,
                nonceB64u: nonceB64u,
                ciphertext: ciphertext
            )
            wire["sig"] = Base64URL.encode(try deviceSigningKey.signature(over: signatureInput))
        }

        let wireBytes = try JSONSerialization.data(withJSONObject: wire, options: [.sortedKeys])
        // A failed seal must not consume a sequence number in persisted sender state.
        highestSealedSeq = seq
        return wireBytes
    }
}
