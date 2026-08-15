import Foundation
#if canImport(CoreFoundation)
import CoreFoundation
#endif

/// The parsed envelope header (§3). Parsing is deliberately strict and hand-rolled
/// rather than `Codable`: a synthesised `Codable` conformance silently ignores unknown
/// keys, and §3 says "Other unknown top-level fields MUST be rejected, not ignored. A
/// permissive parser here is how a future version's field silently becomes an injection
/// point." Strictness is the requirement, so it is the code, not a comment.
public struct Envelope: Sendable {
    public let v: Int
    public let pairing: String
    public let dir: Direction
    public let seq: Int64
    public let ts: String
    public let keyId: String
    public let nonceB64u: String
    public let ciphertextB64u: String
    public let sigB64u: String?

    /// The raw byte length of the envelope as received, for the §3.1 size check.
    public let wireByteCount: Int

    private static let allowedKeys: Set<String> = [
        "v", "pairing", "dir", "seq", "ts", "key_id", "nonce", "ciphertext", "sig",
    ]

    /// Parse from raw wire bytes. Order matters: the size check precedes the parse, so a
    /// 40 MiB body is rejected on a length comparison rather than by allocating it into
    /// a JSON tree first.
    public static func parse(wireBytes: Data) throws -> Envelope {
        guard wireBytes.count <= SyncProtocol.maxEnvelopeBytes else { throw SyncError.tooLarge }

        guard let any = try? JSONSerialization.jsonObject(with: wireBytes, options: []),
              let obj = any as? [String: Any]
        else { throw SyncError.malformed }

        let keys = Set(obj.keys)
        guard keys.isSubset(of: allowedKeys) else { throw SyncError.malformed }

        // `v` is read before anything else can reject on it, but the *decision* about a
        // wrong version belongs to the receiver (§7.1 wants version_unsupported, not a
        // parse error), so a non-1 integer parses fine here.
        guard let v = obj["v"] as? Int,
              let pairing = obj["pairing"] as? String,
              let dirRaw = obj["dir"] as? String,
              let ts = obj["ts"] as? String,
              let keyId = obj["key_id"] as? String,
              let nonce = obj["nonce"] as? String,
              let ciphertext = obj["ciphertext"] as? String
        else { throw SyncError.malformed }

        guard let dir = Direction(rawValue: dirRaw) else { throw SyncError.malformed }

        // seq must be an integer, not a JSON double that happens to look like one.
        guard let seqNum = obj["seq"] as? NSNumber,
              !isJSONBool(seqNum),
              case let seqDouble = seqNum.doubleValue,
              seqDouble == seqDouble.rounded(),
              abs(seqDouble) <= 9_007_199_254_740_991
        else { throw SyncError.malformed }
        let seq = seqNum.int64Value

        let sig = obj["sig"] as? String
        if obj["sig"] != nil && sig == nil { throw SyncError.malformed }

        return Envelope(
            v: v, pairing: pairing, dir: dir, seq: seq, ts: ts, keyId: keyId,
            nonceB64u: nonce, ciphertextB64u: ciphertext, sigB64u: sig,
            wireByteCount: wireBytes.count
        )
    }

    /// §4.1 additional authenticated data. Rebuilt from the parsed header, never taken
    /// from the sender — that is the whole mechanism by which a relay that rewrites
    /// `seq` breaks the tag instead of being believed.
    ///
    /// The exact form is load-bearing: one line, ASCII, no whitespace, fields in this
    /// order. §4.1 uses a deterministic string rather than canonical JSON specifically
    /// so two implementations in two languages cannot disagree about key order or
    /// number formatting.
    public var aad: Data {
        Data("v=\(v)|pairing=\(pairing)|dir=\(dir.rawValue)|seq=\(seq)|ts=\(ts)|key_id=\(keyId)".utf8)
    }
}

/// Foundation bridges JSON `true` to an NSNumber; distinguishing it from the integer 1
/// requires asking CoreFoundation. Without this, `{"seq": true}` parses as seq 1.
private func isJSONBool(_ n: NSNumber) -> Bool {
    CFGetTypeID(n) == CFBooleanGetTypeID()
}
