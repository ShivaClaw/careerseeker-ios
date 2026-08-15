import Foundation

/// Wire constants from Sync-Protocol.md v1. Values here are the *spec's* strings, not
/// convenience names — they appear in `error` payloads and in the vector corpus, so
/// renaming one is a wire change.
public enum SyncProtocol {
    public static let version = 1
    public static let suite = "p256-hkdf-sha256"
    public static let maxEnvelopeBytes = 1_048_576   // §3.1
    public static let nonceBytes = 12                // §5.1
    public static let tagBytes = 16                  // §5.1
}

/// §7.2 error kinds. `malformed` is **not** in the spec's table — see the note below.
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

    /// Local-only. §3 requires rejecting unparseable JSON and unknown top-level fields,
    /// but §7.2 defines no code for either, so there is nothing this implementation can
    /// legitimately put in an outbound `error` payload for that case. Raised as a finding
    /// (PQ-IOS-2) rather than papered over by borrowing a neighbouring code — reporting
    /// a parse failure as `decrypt_failed` would make a spec bug look like a crypto bug
    /// in the field.
    case malformed = "malformed"
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
