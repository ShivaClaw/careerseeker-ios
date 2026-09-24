import Foundation

/// Wire constants from Sync-Protocol.md v1. Values here are the *spec's* strings, not
/// convenience names — they appear in `error` payloads and in the vector corpus, so
/// renaming one is a wire change.
public enum SyncProtocol {
    public static let version = 1
    public static let suite = "p256-hkdf-sha256"
    /// §5.3: every fresh pairing begins on this fixed key ID. Rotation is a
    /// separate, presently unshipped protocol action that names its successor.
    public static let initialKeyId = "k1"
    /// §3.1's binding limit is measured after base64url decoding and includes the
    /// 16-byte GCM tag.
    public static let maxCiphertextBytes = 1_048_576
    /// An unpadded base64url encoding needs ceil(4/3 * n) characters at this boundary.
    public static let maxCiphertextBase64URLCharacters = (maxCiphertextBytes * 4 + 2) / 3
    /// Coarse pre-parse allocation guard. The 4 KiB is headroom for the fixed JSON
    /// fields and optional signature; the binding protocol limit remains the decoded
    /// ciphertext count above. Deriving this total keeps every legal ciphertext
    /// transportable instead of imposing an unrelated round-number wire cap.
    public static let maxWireEnvelopeBytes = maxCiphertextBase64URLCharacters + 4_096
    public static let nonceBytes = 12                // §5.1
    public static let tagBytes = 16                  // §5.1
}

/// §7.2's closed set of observable wire errors. Parser diagnostics are intentionally a
/// separate internal type and are mapped to `decrypt_failed` at the receiver boundary.
public enum SyncError: String, Error, Equatable, Sendable {
    case versionUnsupported = "version_unsupported"
    case replayRejected     = "replay_rejected"
    case decryptFailed      = "decrypt_failed"
    case unknownKind        = "unknown_kind"
    case keyUnknown         = "key_unknown"
    case badSignature       = "bad_signature"
    case revConflict        = "rev_conflict"
    case pairingUnknown     = "pairing_unknown"
    case tooLarge           = "too_large"
    case unimplemented      = "unimplemented"
}

/// §4.3 payload vocabulary, split by direction. A kind valid in one direction is not
/// valid in the other; the receiver enforces both facts.
public enum PayloadKind {
    /// Engine → phone. `doc` is specified but not emitted in v1 (§4.3.1); it is accepted
    /// here because the spec defines its shape and a phone that rejected it would be
    /// wrong the day P3 lands.
    public static let engineToPhone: Set<String> = [
        "snapshot", "delta", "doc", "evidence", "heartbeat", "conflict",
        "entitlement_ack", "error",
    ]

    /// Phone → engine.
    public static let phoneToEngine: Set<String> = [
        "doc_edit", "outcome", "entitlement", "pull_request", "error",
    ]

    /// §4.3: claimed so a future L2 cannot collide with v1 traffic. A v1 receiver MUST
    /// reject these as `unknown_kind` — the same code as a genuinely unrecognised kind,
    /// deliberately: distinguishing them would tell an attacker which L2 features exist.
    public static let reservedForL2: Set<String> = [
        "gate_request", "gate_resolve", "kill", "config_change",
        "lesson_proposal", "metric", "state_change",
    ]

    /// §3/§5.4: kinds whose envelopes MUST carry the device signature. Checked *after*
    /// decryption, because the kind is inside the ciphertext.
    public static let stateChanging: Set<String> = ["doc_edit", "outcome", "entitlement"]

    public static func isKnown(_ kind: String, direction: Direction) -> Bool {
        switch direction {
        case .engineToPhone: return engineToPhone.contains(kind)
        case .phoneToEngine: return phoneToEngine.contains(kind)
        }
    }
}

public enum Direction: String, Sendable, Equatable {
    case engineToPhone = "e2p"
    case phoneToEngine = "p2e"
}
