# CareerSeeker Apple — Program Handoff

2026-08-14 · Fable · Authoritative context for the Apple program. Commit to
`careerseeker-ios` as `docs/Apple-Handoff.md`; upload to project knowledge. When this
document and a repo disagree, the repo wins and this document gets amended.

---

## 1. What this program is

CareerSeeker is a local-first autonomous job-search engine (Windows, .NET 8) with a paid
phone dashboard connected through an end-to-end-encrypted blind relay. The Apple program
delivers two things:

- **Workstream I — iOS dashboard** (`careerseeker-ios`, App Store, one-time paid
  ~$4.99): the iPhone sibling of the Android app. A thin, push-driven viewer/proposer;
  the engine remains authoritative.
- **Workstream M3 — Swift menu-bar shell for the macOS engine**: a small `NSStatusItem`
  supervisor app. The engine port itself (M0–M2, M4–M6) is **not** in this repo — it is
  the same .NET code in `ShivaClaw/careerseeker`, published for `osx-arm64`.

Everything else — pipeline, Fabrication Gate, Gmail drafting, scoring, the relay Worker,
the wire protocol — lives in the main repo and is consumed here, never re-implemented.

## 2. The seam decision (2026-08-13, locked)

Split is **app vs. engine**, not Apple vs. everything else:

| Concern | Home |
| --- | --- |
| iOS app, Swift sync SDK, conformance runner, macOS menu-bar shell | `careerseeker-ios` |
| macOS engine port (vault abstraction, launchd host, signing, CI) | `careerseeker` |
| `Sync-Protocol.md` + `sync-vectors/` (normative) | `careerseeker` |
| PQ ledger, entitlement architecture, Android program docs | `careerseeker-android` |

Rationale: forking the engine creates two Gates that can disagree; scattering the spec
creates three "normative" copies; splitting the PQ queue splits the amendment gate. The
ios repo vendors the vectors with a pinned digest (`Vectors/PROVENANCE.md`) so it runs
standalone while drift stays detectable.

## 3. Wire protocol in one paragraph (read the real one before coding)

Sync-Protocol v1 (`careerseeker/docs/Sync-Protocol.md`, normative, RFC-2119): JSON
envelopes over a blind Cloudflare relay; AES-256-GCM with a deterministic ASCII AAD built
from the header; ECDH P-256 + HKDF-SHA256 pairing bootstrapped by a QR one-time secret
with a 6-digit confirm; per-direction monotonic sequence numbers, replay rejected on the
header before decryption; `key_id` checked before decryption (revocation is explicit,
never a side effect of crypto); state-changing phone→engine kinds (`doc_edit`, `outcome`,
`entitlement`) carry an envelope-level ECDSA P-256 signature (raw 64-byte `r||s`) over
`careerseeker/v1/cmd|<AAD>|<nonce>|<sha256-hex(ciphertext)>`; unpadded base64url
everywhere in framing, rejected if padded; unknown kinds and unknown top-level fields
rejected; L2 kinds (`kill`, `gate_request`, …) reserved and rejected in v1.

## 4. The finding that shapes everything: P1-CURVE is Secure-Enclave-native

The P1 amendment moved the suite from X25519/Ed25519 to P-256 for Android Keystore and
.NET reasons. By accident, every primitive v1 needs is native CryptoKit, and P-256 is the
**only** key type the Secure Enclave supports; `ECDSASignature.rawRepresentation` is
exactly the mandated 64-byte form. Consequence: the iPhone device signing key can be
enclave-generated and non-exportable — *stronger* custody than Android Keystore's
variable hardware backing. Under the P0 draft this would have been impossible. Not yet
recorded in the main repo's claims register; it should be, once shipped code makes it a
claim rather than a plan.

One designed-in interaction: a biometry-gated enclave key cannot sign inside a
Notification Service Extension, which would force all state-changing actions
foreground-only. Product decision, deliberately unmade — see §8.

## 5. Executed state (as of 2026-08-13)

**`careerseeker-ios-sync` SwiftPM package built and passing** (tarball in this handoff
package; becomes the repo's initial commit):

- Library `CareerSeekerSync` (client role): strict `Base64URL`, strict `Envelope` parser
  (unknown fields rejected; JSON `true` ≠ seq 1), `EnvelopeReceiver` implementing the
  ordered gauntlet (size → parse → version → pairing → key_id → replay → e2p-sig-ban →
  strict b64u → device sig → AEAD → kind vocabulary → sig requirement; cursor advances
  only on acceptance), `PairingCrypto` (§5.2 derivations incl. provisional token),
  `DeviceSigningKey` protocol with software impl + `SecureEnclave` impl behind
  `#if os(iOS) || os(macOS)`, `PlayEntitlementVerifier` (engine-role, corpus coverage
  only).
- Executable `conformance`: consumes `docs/sync-vectors/v1`, harness-style output,
  non-zero exit on failure. **Result: all 25 vectors (18 envelope, 2 pairing,
  5 entitlement), 42 checks, 0 failures.** Corpus digest
  `6366a86092971dfed0d96a560de1095962e6ce172a83b5a46e3037e5af1ab2ba` at source commit
  `efb9cd6` (vectors last touched `340dcee`, 2026-07-24).
- Toolchain: Swift 6.3.3, Linux x86_64, swift-crypto (BoringSSL). **CryptoKit itself is
  unproven** — API-compatible by design, but that is an expectation, not evidence, until
  a macOS/iOS run exists.
- Mutation evidence: dropped reserved-kind check, envelope-supplied device key, and
  skipped pre-decrypt `key_id` check were all **caught** by the corpus. Lenient base64
  was **not** — that is finding PQ-IOS-3, not a pass.
- CI: `.github/workflows/conformance.yml`, Ubuntu 24.04, `swift:6.1-noble` container.
  Linux deliberately: protocol conformance needs no Mac and no Apple account.

Raw log: `docs/evidence/conformance-run-2026-08-13.txt`. Evidence narrative:
`CareerSeekerSync-Swift-Evidence.md`.

## 6. Findings filed (live in the android repo's PQ ledger once transferred)

- **PQ-IOS-3 (act first, one line):** `invalid-padded-base64` does not discriminate
  strict from lenient decoders — its ciphertext strips to 3 bytes, under the 16-byte
  tag, so a lenient decoder still returns `decrypt_failed` for the wrong reason. Fix in
  `generate.mjs`: make the padded vector's ciphertext long enough to reach the AEAD.
  Until fixed, strict base64url is untested in the C# and Kotlin implementations too.
- **PQ-IOS-1:** `entitlement` is Google-Play-shaped (RSA-PKCS1-SHA1 over
  `Purchase.getOriginalJson()`, `packageName` check). iOS needs an
  `entitlement_appstore` sibling: StoreKit 2 JWSTransaction, ES256, x5c chain to Apple
  Root, offline-verifiable by the engine — same courier/verifier shape. Reserve the kind
  and the check order before v1 ossifies. Corollary for the macOS engine port: CryptoKit
  has no RSA; the Play verifier needs Security.framework
  (`SecKeyVerifySignature`, `.rsaSignatureMessagePKCS1v15SHA1`) on Apple platforms.
- **PQ-IOS-2:** §3 requires rejecting malformed envelopes; §7.2 defines no error code
  for it. The Swift implementation raises a local-only `malformed` rather than
  mislabeling a parse bug as `decrypt_failed`. Spec should add a code or state that
  malformed input is dropped silently.

## 7. Roadmap state (vs. `CareerSeeker-CrossPlatform-Roadmap.md`, 2026-07-24)

Still current: §0 sequencing gates, Workstream M structure, meatspace table, timeline
(macOS ≈ Q4 2026 if Windows L1 launches late Q3; iOS tracks Phase F + ~1 month).

Superseded or moved by events:

- "iOS lands 4–8 weeks after Android F2" understates what exists now: the sync core is
  no longer hypothetical — the Swift SDK + conformance evidence predate any Android app
  code.
- I1's framing ("build F2 multiplatform once") is now conditional: Sync-Protocol §5.1
  justifies AES-GCM via Tink on Android. If `:core` is Tink/JVM-bound, KMP sharing is
  foreclosed and the honest architecture is **three independent implementations against
  one normative spec + corpus** — which the executed harness demonstrates is cheap.
- Repo/Project structure is now decided (§2 above), which the roadmap left open.

## 8. Open decisions (ADR queue for this program)

1. **I1 — iOS stack**: independent Swift (SwiftUI + `CareerSeekerSync`) vs. KMP shared
   core. Blocked on the `:core` Tink question; needs a `careerseeker-android` bundle.
   Constrains F1 envelope crypto; precedes Android UI code.
2. **Biometry on the device signing key**: Face-ID-gated enclave key (stronger custody,
   foreground-only actions) vs. `privateKeyUsage`-only (background approve/skip from
   notifications works). Interacts with the Notification Service Extension design.
3. **Notification Service Extension key sharing**: Keychain access group layout for
   decrypting e2p pushes in the ~30s extension budget. Needs a spike on real hardware.
4. **Demo mode** (App Review requirement and screenshot generator): seeded-data reviewer
   path — feature, not hack. Spec before any App Store submission.
5. **macOS shell**: native menu-bar Swift app (recommended) vs. Avalonia. Decide when M
   starts; not urgent.

## 9. Meatspace ledger

| Item | Status | Note |
| --- | --- | --- |
| Apple Developer Program (organization, $99/yr) | **Verify before assuming** — enrollment requires LLC (no DBAs) + D-U-N-S + public site + verification call, 1–2 wks | Covers both Developer ID (macOS) and App Store (iOS). File the day LLC papers exist |
| D-U-N-S | In flight for Play org | Same number reuses for Apple |
| Mac hardware (mini M4, ~$599–799) | Needed for Xcode, notarization, CryptoKit/enclave verification | The one thing Linux CI cannot replace |
| iPhone test device (used, ~$200–350) | Needed for push + Notification Service Extension testing | Simulator push support is partial; `SecureEnclave.isAvailable` is false on simulator |
| Small Business Program (15%) | Enroll once membership is live | Net ≈ $4.24 on $4.99 |
| Export compliance | Annual self-classification (E2E crypto, standard-algorithm exemption) | Calendar item next to CASA |
| CASA / Gmail OAuth | **Unaffected** — per-Google-Cloud-project, engine-side, OS-agnostic | No new scope provided the relay stays blind |

## 10. Definition of "up to speed" for a new agent

An agent is oriented when it can state, from fresh clones and without this document:
current HEAD of `careerseeker-ios` and `careerseeker`; the conformance runner's pass
count and corpus digest, re-derived by running it; the three PQ-IOS findings and which
one is a one-line fix; the I1 blocker; and the two things it must never touch from this
program (main-repo `src/Sync/` + verifier scripts; the normative spec except via PQ).
The seed prompts in `04-Seed-Prompts.md` walk exactly that path.
