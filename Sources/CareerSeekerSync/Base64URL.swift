import Foundation

/// Unpadded base64url (RFC 4648 §5) — strict in both directions.
///
/// Sync-Protocol.md §3: "All base64url values are **unpadded**. Decoders MUST reject
/// padded input rather than accepting both, so the vectors mean one thing."
///
/// Foundation's `Data(base64Encoded:)` is permissive in exactly the ways that rule
/// forbids, so this does not wrap it. A lenient decoder here is not a style question:
/// `invalid-padded-base64` is a vector precisely because accepting both spellings means
/// the corpus stops pinning one encoding, and two implementations can then disagree
/// about what a byte string is while both passing their own tests.
public enum Base64URL {

    public enum DecodeError: Error, Equatable {
        case padded            // '=' present
        case standardAlphabet  // '+' or '/' — that is base64, not base64url
        case invalidCharacter
        case invalidLength     // a length that no unpadded base64url string can have
    }

    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    private static let reverse: [Int8] = {
        var t = [Int8](repeating: -1, count: 256)
        for (i, c) in alphabet.enumerated() { t[Int(c.asciiValue!)] = Int8(i) }
        return t
    }()

    public static func encode(_ data: Data) -> String {
        // Flat array, integer offsets. `Data`'s indices are not guaranteed to start at 0
        // (a slice carries its parent's offsets), so index arithmetic against
        // `startIndex` is a trap here — one worth avoiding by not doing it.
        let bytes = [UInt8](data)
        var out = ""
        out.reserveCapacity((bytes.count + 2) / 3 * 4)

        var i = 0
        while i < bytes.count {
            let b0 = bytes[i]
            let b1: UInt8? = i + 1 < bytes.count ? bytes[i + 1] : nil
            let b2: UInt8? = i + 2 < bytes.count ? bytes[i + 2] : nil

            out.append(alphabet[Int(b0 >> 2)])
            out.append(alphabet[Int((b0 & 0x03) << 4 | ((b1 ?? 0) >> 4))])
            if let b1 { out.append(alphabet[Int((b1 & 0x0F) << 2 | ((b2 ?? 0) >> 6))]) }
            if let b2 { out.append(alphabet[Int(b2 & 0x3F)]) }

            i += 3
        }
        return out
    }

    public static func decode(_ s: String) throws -> Data {
        if s.contains("=") { throw DecodeError.padded }
        if s.contains("+") || s.contains("/") { throw DecodeError.standardAlphabet }

        let chars = Array(s.utf8)
        // A base64 quantum of 1 character cannot encode any whole byte.
        if chars.count % 4 == 1 { throw DecodeError.invalidLength }

        var out = Data()
        out.reserveCapacity(chars.count * 3 / 4)
        var accumulator: UInt32 = 0
        var bits = 0

        for c in chars {
            let v = reverse[Int(c)]
            if v < 0 { throw DecodeError.invalidCharacter }
            accumulator = (accumulator << 6) | UInt32(UInt8(v))
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((accumulator >> UInt32(bits)) & 0xFF))
            }
        }

        // Leftover bits must be zero padding, never dropped data.
        if bits > 0 && (accumulator & ((1 << UInt32(bits)) - 1)) != 0 {
            throw DecodeError.invalidLength
        }
        return out
    }
}
