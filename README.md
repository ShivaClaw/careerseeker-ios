# CareerSeekerSync (Swift)

A client-role implementation of **Sync-Protocol v1** (`docs/Sync-Protocol.md` in
`ShivaClaw/careerseeker`) plus a conformance runner that proves it against the shared
vector corpus.

This is the seed of the iOS dashboard's sync layer. It exists now, before there is a Mac,
an Apple Developer account, or an iOS app, because the protocol was deliberately built so
a third implementation could be validated independently — §10: *"a generator written in
the same language as its verifier proves only that the language agrees with itself."*

```
swift run conformance                                    # vendored copy
swift run conformance --vectors ../careerseeker/docs/sync-vectors/v1   # upstream
```

Exit code is non-zero on any failure, so it wires into CI as-is
(`.github/workflows/conformance.yml`).

## Status

```
CareerSeeker Sync v1 — Swift conformance
  suite      p256-hkdf-sha256
  cipher     AES-256-GCM
  vectors    25 declared in index.json
  toolchain  Swift 6.3.3 · swift-crypto (BoringSSL)
  corpus     sha256 6366a860…af1ab2ba
  ───────────────────────────────────
  envelope vectors consumed : 18
  checks passed             : 42
  checks failed             : 0
```

All 25 vectors consumed: 18 envelope, 2 pairing, 5 entitlement. Every valid vector
decrypts to its stated plaintext; every invalid one is rejected **with the code the
corpus names** — rejecting for the right reason, per §10.

Verified on Linux with swift-crypto. Not yet run under CryptoKit; that needs Apple
hardware and is the one claim this harness cannot make. The two are API-compatible for
every primitive v1 uses, which is a strong expectation, not evidence.

## Layout

| File | Role |
| --- | --- |
| `Base64URL.swift` | Strict unpadded base64url (§3). Does not wrap Foundation's permissive decoder. |
| `Protocol.swift` | Wire constants, §7.2 error codes, §4.3 kind vocabulary. |
| `Envelope.swift` | Strict header parse; unknown top-level fields rejected (§3). |
| `EnvelopeReceiver.swift` | The ordered validation gauntlet (§3, §5, §6, §7). |
| `PairingCrypto.swift` | ECDH P-256 → HKDF derivations (§5.2). |
| `DeviceSigningKey.swift` | Device identity; Secure Enclave impl behind `#if os(iOS)`. |
| `PlayEntitlementVerifier.swift` | **Engine role.** Present for corpus coverage only — see below. |

## The finding this package exists to record

**P1-CURVE made the protocol Secure-Enclave-native, by accident.**

The P1 amendment moved the suite from X25519/Ed25519 to ECDH P-256 / ECDSA P-256 for two
reasons that had nothing to do with Apple: Android Keystore cannot generate Ed25519 below
API 33, and .NET's BCL has no XChaCha20. The result is that every primitive v1 requires —
ECDH P-256, HKDF-SHA256, AES-256-GCM, ECDSA P-256 as a raw 64-byte `r||s` — is native
CryptoKit, and P-256 is the **only** key type the Secure Enclave supports.
`P256.Signing.ECDSASignature.rawRepresentation` is literally the encoding §5.4 mandates.

Under the P0 draft, an iOS device key could not have been hardware-bound at all. Under P1,
the iPhone gets *stronger* key custody than the Android side — Secure Enclave presence is
uniform across the target fleet, while Keystore hardware backing varies. The amendment
should be credited with this in the claims register; right now nothing records it.

## Findings raised by building this

**PQ-IOS-1 — `entitlement` is Google-Play-shaped and v1 has no App Store sibling.**
§4.3.2 verifies an RSA-PKCS1-SHA1 signature over `Purchase.getOriginalJson()` and checks
`packageName == app.careerseeker.dashboard`. An iPhone has no Play purchase to courier.
The App Store equivalent is a StoreKit 2 `JWSTransaction` (ES256, x5c chaining to the
Apple Root CA, offline-verifiable by the engine) — the same courier/verifier shape, an
entirely different payload. Reserving `entitlement_appstore` and speccing the verifier's
check order costs a paragraph now; retrofitting it after external audit costs an
amendment cycle. Unknown-kind rejection keeps this forward-compatible either way.

Corollary worth knowing before the macOS engine port: **CryptoKit has no RSA at all.**
This package uses `_CryptoExtras`, an underscored module with no API-stability promise.
A real Apple-platform engine would go through Security.framework's `SecKeyVerifySignature`
with `.rsaSignatureMessagePKCS1v15SHA1`. The Play verifier does not port for free.

**PQ-IOS-2 — §7.2 has no error code for a malformed envelope.**
§3 requires rejecting unparseable JSON and unknown top-level fields, but the §7.2 table
defines nothing to put in an outbound `error` payload for either. This implementation
raises a local-only `malformed` rather than borrowing a neighbouring code, because
reporting a parse failure as `decrypt_failed` makes a spec bug look like a crypto bug in
the field. Either add a code or state that these are dropped silently.

**PQ-IOS-3 — `invalid-padded-base64` does not discriminate strict from lenient decoders.**
Found by mutation testing, not by reading. The vector's nonce (`AAAAAAAAAAAAAAAA==`)
strips to exactly 12 bytes and its ciphertext (`AAAA==`) to 3 — below the 16-byte tag. So
a lenient decoder that strips padding still fails, at the length check or the tag, and
still returns `decrypt_failed`: **the expected code, for the wrong reason.** A permissive
implementation passes this vector. That is precisely the failure mode §10 warns about,
appearing in the corpus itself rather than in a consumer of it.

Fix direction: give the padded vector a ciphertext long enough to reach the AEAD, so a
lenient decoder produces a *decryptable* envelope and visibly accepts something it must
reject. Until then, strict base64 is untested on the C# and Kotlin sides too — this is
not an iOS-specific gap. Local coverage is asserted in the runner's hardening section,
but a local assertion does not bind the other two implementations.

## Mutation evidence

A harness that cannot fail proves nothing, so four deliberate defects were introduced and
reverted:

| Mutation | Result |
| --- | --- |
| Drop the reserved-L2-kind check (accept `kill`) | **caught** — `invalid-reserved-kind-l2` accepted |
| Trust the envelope-supplied device key instead of the pairing's | **caught** — `sig-by-revoked-key` accepted |
| Skip the pre-decrypt `key_id` check, rely on the AEAD tag | **caught** — `invalid-unknown-key-id` accepted |
| Make base64url lenient (accept padding) | **not caught** — see PQ-IOS-3 |

The `key_id` mutation is the most instructive: the envelope still decrypted, because the
test key is unchanged and only the id differs. That is exactly the case §5.3 describes —
*"a superseded pairing whose derived key happens to still decrypt is precisely the case a
tag check cannot see"* — and the corpus catches it.

## Scope

**In:** envelope codec, receiver validation order, pairing derivation, device signing,
protocol vocabulary.

**Out:** relay transport (HTTP/WSS), local replica and persistence, UI, push. The
Notification Service Extension is where the iOS design gets genuinely different from
Android and needs its own spike — a background extension has a ~30s budget, gets the
decryption key from a Keychain access group, and cannot use a biometry-gated Secure
Enclave key. That last interaction is noted in `DeviceSigningKey.swift`: gating signing on
Face ID makes every state-changing action foreground-only. Product decision, not a crypto
one, and better made deliberately than discovered.

Nothing here touches `src/Sync/`, `Host.cs`, or the verifier scripts — all claimed by the
in-flight S5 stack (draft PR #39).
