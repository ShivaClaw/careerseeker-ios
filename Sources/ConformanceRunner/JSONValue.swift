import Foundation
#if canImport(CoreFoundation)
import CoreFoundation
#endif

/// A parsed JSON value with structural equality.
///
/// Round-tripping a decrypted payload cannot be a byte comparison against the vector's
/// `plaintext_json`: the sealed bytes came from Node's `JSON.stringify`, while the field
/// in the file is that same value re-encoded by whatever wrote it. Key order and Unicode
/// escaping are free to differ, and `heartbeat-unicode` exists to make sure an
/// implementation is not accidentally depending on them matching.
///
/// This is the same reasoning §4.1 uses to keep canonical JSON *out* of the AAD. Where
/// bytes must agree, the protocol uses a deterministic ASCII string; where only meaning
/// must agree, comparison is structural. Conflating the two is the bug.
indirect enum JSONValue: Equatable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    static func parse(_ data: Data) throws -> JSONValue {
        let any = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        return from(any)
    }

    static func from(_ any: Any) -> JSONValue {
        switch any {
        case is NSNull:
            return .null
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return .bool(n.boolValue) }
            return .number(n.doubleValue)
        case let s as String:
            return .string(s)
        case let a as [Any]:
            return .array(a.map(from))
        case let o as [String: Any]:
            return .object(o.mapValues(from))
        default:
            return .null
        }
    }
}
