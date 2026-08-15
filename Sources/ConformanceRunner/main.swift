import Foundation
import CareerSeekerSync
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// CareerSeeker iOS sync conformance runner.
//
// Consumes docs/sync-vectors/v1 — the same corpus the C# SyncHarness and the Kotlin
// :core tests read — and proves a Swift client-role implementation agrees with it.
// Output format follows the existing offline harnesses (a check line per assertion,
// counts at the end, non-zero exit on any failure) so it can be wired into CI beside
// them without inventing a second reporting convention.

// ─────────────────────────────────────────────────────────────── reporting

var passed = 0
var failed = 0
var failures: [String] = []

@MainActor
func check(_ label: String, _ ok: Bool, _ detail: String = "") {
    if ok {
        passed += 1
        print("  ok   \(label)")
    } else {
        failed += 1
        failures.append(label)
        print("  FAIL \(label)\(detail.isEmpty ? "" : "  — \(detail)")")
    }
}

@MainActor
func section(_ title: String) { print("\n[ \(title) ]") }

// ─────────────────────────────────────────────────────────────── vector loading

let args = CommandLine.arguments
var vectorDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    .appendingPathComponent("Vectors")
if let i = args.firstIndex(of: "--vectors"), i + 1 < args.count {
    vectorDir = URL(fileURLWithPath: args[i + 1])
}

@MainActor
func loadJSON(_ name: String) -> [String: Any] {
    let url = vectorDir.appendingPathComponent("\(name).json")
    guard let data = try? Data(contentsOf: url),
          let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    else {
        FileHandle.standardError.write(Data("cannot read vector \(name) at \(url.path)\n".utf8))
        exit(2)
    }
    return obj
}

@MainActor
func hexToData(_ hex: String) -> Data {
    var out = Data(capacity: hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        out.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }
    return out
}

let index = loadJSON("index")
let vectorList = index["vectors"] as! [[String: Any]]

print("CareerSeeker Sync v1 — Swift conformance")
print("  spec       \(index["spec"] as? String ?? "?")")
print("  suite      \(index["suite"] as? String ?? "?")")
print("  cipher     \(index["cipher"] as? String ?? "?")")
print("  vectors    \(vectorList.count) declared in index.json")
print("  toolchain  Swift \(swiftVersionString()) · \(cryptoBackendName())")

// A manifest, so a passing run is pinned to the bytes it passed against. The corpus is
// generated and committed upstream; if it moves, this hash moves, and a stale "25/25"
// cannot be quoted about a corpus that has since changed.
let manifest = vectorDigest(dir: vectorDir, names: vectorList.compactMap { $0["name"] as? String } + ["index"])
print("  corpus     sha256 \(manifest)")

// ─────────────────────────────────────────────────────────────── pairing (§5.2)

section("pairing — ECDH P-256 → HKDF derivations (§5.2)")

let pairing = loadJSON("pairing-basic")
let pairingExpected = pairing["expected"] as! [String: Any]
let engineD = hexToData((pairing["engine"] as! [String: Any])["d_hex"] as! String)
let phonePubB64u = (pairing["phone"] as! [String: Any])["pub_b64u"] as! String
let oneTimeSecret = try! Base64URL.decode(pairing["secret_b64u"] as! String)

let enginePriv = try! P256.KeyAgreement.PrivateKey(rawRepresentation: engineD)
let phonePub = try! P256.KeyAgreement.PublicKey(x963Representation: try! Base64URL.decode(phonePubB64u))
let derived = try! PairingCrypto.derive(
    ownPrivateKey: enginePriv, peerPublicKey: phonePub, oneTimeSecret: oneTimeSecret
)

@MainActor
func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

check("shared secret matches (ss = X coordinate, unhashed)",
      hex(derived.sharedSecret) == pairingExpected["ss_hex"] as! String,
      hex(derived.sharedSecret))
check("k_e2p matches",
      hex(derived.kE2P.withUnsafeBytes { Data($0) }) == pairingExpected["k_e2p_hex"] as! String)
check("k_p2e matches",
      hex(derived.kP2E.withUnsafeBytes { Data($0) }) == pairingExpected["k_p2e_hex"] as! String)
check("relay token matches",
      derived.relayToken == pairingExpected["relay_token_b64u"] as! String)
check("provisional relay token matches (§5.2.1, keyed on the one-time secret alone)",
      PairingCrypto.provisionalRelayToken(oneTimeSecret: oneTimeSecret)
        == pairingExpected["provisional_token_b64u"] as! String)
check("6-digit confirm code matches",
      derived.confirmCode == pairingExpected["confirm"] as! String,
      derived.confirmCode)

// The engine's directional keys are the same two keys the phone derives; the phone side
// is not a separate derivation, so proving one side byte-for-byte proves the agreement.
let completion = pairing["completion"] as! [String: Any]
let completionPlain = try? PairingCrypto.openCompletion(
    ciphertext: try! Base64URL.decode(completion["ciphertext_b64u"] as! String),
    nonce: try! Base64URL.decode(completion["nonce_b64u"] as! String),
    aad: PairingCrypto.completionAAD(
        pairing: index["pairing_id"] as! String,
        suite: pairing["suite"] as! String,
        phonePublicKeyB64u: phonePubB64u
    ),
    key: derived.kP2E
)
check("sealed completion opens", completionPlain != nil)

var trustedDeviceKey: P256.Signing.PublicKey? = nil
if let plain = completionPlain {
    let got = try! JSONValue.parse(plain)
    let want = JSONValue.from(completion["payload_json"] as! [String: Any])
    check("completion payload round-trips to the stated device_sig_pub + ts", got == want)

    if case let .object(o) = got, case let .string(dsp)? = o["device_sig_pub"] {
        trustedDeviceKey = try? P256.Signing.PublicKey(x963Representation: try Base64URL.decode(dsp))
    }
    check("device signing key recovered from inside the ciphertext (relay never sees it)",
          trustedDeviceKey != nil)
}

section("pairing — malicious relay key swap (§5.2.2)")

let mitm = loadJSON("pairing-mitm-keyswap")
let mitmPhonePubB64u = (mitm["phone"] as! [String: Any])["pub_b64u"] as! String
let mitmCompletion = mitm["completion"] as! [String: Any]
let mitmPriv = try! P256.KeyAgreement.PrivateKey(
    rawRepresentation: hexToData((mitm["engine"] as! [String: Any])["d_hex"] as! String))
let mitmPeer = try! P256.KeyAgreement.PublicKey(
    x963Representation: try! Base64URL.decode(mitmPhonePubB64u))
let mitmDerived = try! PairingCrypto.derive(
    ownPrivateKey: mitmPriv, peerPublicKey: mitmPeer, oneTimeSecret: oneTimeSecret)
let mitmOpened = try? PairingCrypto.openCompletion(
    ciphertext: try! Base64URL.decode(mitmCompletion["ciphertext_b64u"] as! String),
    nonce: try! Base64URL.decode(mitmCompletion["nonce_b64u"] as! String),
    aad: PairingCrypto.completionAAD(
        pairing: index["pairing_id"] as! String,
        suite: mitm["suite"] as! String,
        phonePublicKeyB64u: mitmPhonePubB64u
    ),
    key: mitmDerived.kP2E
)
check("swapped phone_pub fails the tag (expect decrypt_failed)", mitmOpened == nil)

// ─────────────────────────────────────────────────────────────── envelopes (§3–§7)

section("envelopes — ordered validation gauntlet (§3, §5, §6, §7)")

// The receiver is constructed the way a paired phone would be: keys and the trusted
// device key are properties of the pairing, not of any envelope. The envelope corpus
// uses its own fixed test keys (key_hex per vector) rather than the pairing-derived
// ones, so those are read from the first vector of each direction.
let e2pKey = SymmetricKey(data: hexToData(loadJSON("delta-basic")["key_hex"] as! String))
let p2eKey = SymmetricKey(data: hexToData(loadJSON("doc-edit-signed")["key_hex"] as! String))

let receiver = EnvelopeReceiver(
    pairingId: index["pairing_id"] as! String,
    activeKeyId: index["active_key_id"] as! String,
    keyE2P: e2pKey,
    keyP2E: p2eKey,
    deviceSigningPublicKey: trustedDeviceKey
)

/// Rebuild the exact wire bytes. Vectors ship `envelope_json` as a parsed object, so it
/// is re-encoded here; that is safe because every check the receiver makes is either on
/// a field value or on the AAD it rebuilds itself — none depends on the outer JSON's
/// byte layout. (`invalid-oversized` has no `envelope_json` at all and is synthesised.)
@MainActor
func wireBytes(for vector: [String: Any], name: String) -> Data {
    if let synthLen = vector["synth_ciphertext_len"] as? Int {
        let envelope: [String: Any] = [
            "v": 1,
            "pairing": index["pairing_id"] as! String,
            "dir": "e2p",
            "seq": 11,
            "ts": "2026-06-11T14:02:11Z",
            "key_id": index["active_key_id"] as! String,
            "nonce": vector["nonce_b64u"] as! String,
            "ciphertext": String(repeating: "A", count: synthLen),
        ]
        return try! JSONSerialization.data(withJSONObject: envelope)
    }
    guard let env = vector["envelope_json"] as? [String: Any] else {
        FileHandle.standardError.write(Data("vector \(name) has no envelope_json\n".utf8))
        exit(2)
    }
    return try! JSONSerialization.data(withJSONObject: env)
}

var envelopeCount = 0

for entry in vectorList where (entry["type"] as? String) == "envelope" {
    let name = entry["name"] as! String
    let vector = loadJSON(name)
    envelopeCount += 1

    let bytes = wireBytes(for: vector, name: name)
    let isValid = vector["valid"] as! Bool
    let expectError = vector["expect_error"] as? String

    do {
        let accepted = try receiver.accept(wireBytes: bytes)
        if isValid {
            let got = try JSONValue.parse(accepted.plaintext)
            let want = JSONValue.from(vector["plaintext_json"] as! [String: Any])
            check("\(name): accepted and round-trips to plaintext_json", got == want)
        } else {
            check("\(name): must be rejected with \(expectError ?? "?")", false, "accepted")
        }
    } catch let e as SyncError {
        if isValid {
            check("\(name): accepted and round-trips to plaintext_json", false, "rejected \(e.rawValue)")
        } else {
            // §10: rejecting for the wrong reason is a failure, not a pass. A check that
            // fires earlier than intended hides the fact that the real check is untested.
            check("\(name): rejected with \(expectError ?? "?")",
                  e.rawValue == expectError, "got \(e.rawValue)")
        }
    } catch {
        check("\(name): rejected with \(expectError ?? "?")", false, "unexpected \(error)")
    }
}

// A rejected envelope must not move the cursor. `invalid-aad-tampered-seq` carries a
// forged seq of 9999; an implementation that advanced on rejection would then reject
// every subsequent legitimate envelope as a replay and wedge the stream permanently —
// silently, and only under attack. The corpus catches this only because the vectors
// after it carry lower sequence numbers, which reads like an accident of ordering but
// is load-bearing.
// The last *accepted* e2p envelope is empty-body at seq 4; everything from seq 5 up is a
// rejection vector, including the forged 9999. So the cursor must read 4 — not 9999, and
// not 10 either.
check("rejected envelopes did not advance the e2p cursor (highest = 4, the last accepted)",
      receiver.highestAcceptedSeq(.engineToPhone) == 4,
      String(receiver.highestAcceptedSeq(.engineToPhone)))
check("rejected envelopes did not advance the p2e cursor (highest = 1, the last accepted)",
      receiver.highestAcceptedSeq(.phoneToEngine) == 1,
      String(receiver.highestAcceptedSeq(.phoneToEngine)))

// Directly: after the forged 9999 was rejected, a legitimate seq 5 must still be
// acceptable. If the cursor had moved, this is where the stream would be dead.
do {
    var revive = loadJSON("delta-basic")["envelope_json"] as! [String: Any]
    revive["seq"] = 5
    // Re-sealing is not possible here (the AAD changes), so this only asserts that the
    // *replay gate* lets seq 5 through — it fails later, at the tag, which is the proof
    // wanted: decrypt_failed, not replay_rejected.
    let bytes = try! JSONSerialization.data(withJSONObject: revive)
    do {
        _ = try receiver.accept(wireBytes: bytes)
        check("post-forgery seq 5 passes the replay gate", false, "unexpectedly accepted")
    } catch let e as SyncError {
        check("post-forgery seq 5 passes the replay gate (fails at the tag, not as a replay)",
              e == .decryptFailed, "got \(e.rawValue)")
    } catch {
        check("post-forgery seq 5 passes the replay gate", false, "unexpected \(error)")
    }
}

// ─────────────────────────────────────────────────────────────── entitlement (§4.3.2)

section("entitlement — engine-role Play verification (§4.3.2)")
print("  note: the phone is a courier here, never the verifier. Run for corpus coverage;")
print("        no iOS client code path calls this. See PlayEntitlementVerifier.swift.")

for entry in vectorList where (entry["type"] as? String) == "entitlement" {
    let name = entry["name"] as! String
    let vector = loadJSON(name)
    let ent = vector["entitlement"] as! [String: Any]
    let body = (vector["plaintext_json"] as! [String: Any])["body"] as! [String: Any]

    let config = PlayEntitlementVerifier.Configuration(
        rsaPublicKeySPKIBase64: ent["rsa_pub_spki_b64"] as! String,
        expectedPackageName: ent["package_name_expected"] as! String,
        expectedProductIds: Set(ent["product_ids_expected"] as! [String]),
        purchasedState: ent["purchase_state_purchased"] as! Int
    )

    let result = PlayEntitlementVerifier.verify(
        originalJSON: body["original_json"] as! String,
        signatureBase64: body["signature"] as! String,
        config: config
    )
    let expect = ent["expect"] as! String
    check("\(name): verifier returns \(expect)", result.rawValue == expect, "got \(result.rawValue)")
}

// ─────────────────────────────────────────────── implementation-defined hardening

// Not from the corpus. §3 requires rejecting unknown top-level fields and §3.1 requires
// a size cap, but neither has a vector, and §7.2 defines no error code for a malformed
// envelope at all — so these assert this implementation's behaviour and stand as the
// evidence behind PQ-IOS-2 rather than claiming corpus coverage they do not have.
section("hardening — beyond the corpus (implementation-defined)")

@MainActor
func rejects(_ label: String, _ json: [String: Any], _ expected: SyncError) {
    let bytes = try! JSONSerialization.data(withJSONObject: json)
    do {
        _ = try receiver.accept(wireBytes: bytes)
        check(label, false, "accepted")
    } catch let e as SyncError {
        check(label, e == expected, "got \(e.rawValue), wanted \(expected.rawValue)")
    } catch {
        check(label, false, "unexpected \(error)")
    }
}

let baseEnvelope = loadJSON("delta-basic")["envelope_json"] as! [String: Any]

var withUnknownField = baseEnvelope
withUnknownField["seq"] = 900
withUnknownField["x_experimental"] = "anything"
rejects("unknown top-level field rejected, not ignored (§3)", withUnknownField, .malformed)

var withBoolSeq = baseEnvelope
withBoolSeq["seq"] = true
rejects("JSON true is not accepted as seq 1", withBoolSeq, .malformed)

var wrongPairing = baseEnvelope
wrongPairing["seq"] = 901
wrongPairing["pairing"] = "p_0000000000000000"
rejects("envelope for another pairing rejected", wrongPairing, .pairingUnknown)

check("base64url decoder rejects standard-alphabet input",
      (try? Base64URL.decode("a+b/c")) == nil)
check("base64url decoder rejects a 1-char final quantum",
      (try? Base64URL.decode("AAAAA")) == nil)
check("base64url round-trips arbitrary bytes",
      (try? Base64URL.decode(Base64URL.encode(Data((0...255).map(UInt8.init))))) == Data((0...255).map(UInt8.init)))

// ─────────────────────────────────────────────────────────────── summary

print("\n────────────────────────────────────────────")
print("  envelope vectors consumed : \(envelopeCount)")
print("  checks passed             : \(passed)")
print("  checks failed             : \(failed)")
if failed > 0 {
    print("\nfailures:")
    for f in failures { print("  · \(f)") }
}
print("────────────────────────────────────────────")
exit(failed == 0 ? 0 : 1)
