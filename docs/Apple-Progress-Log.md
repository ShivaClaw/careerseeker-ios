# CareerSeeker Apple — Progress Log

Append-only. Every session that changes anything adds a dated entry: what changed, what
was verified (counts/digests/SHAs), what was found, what remains. Claims without
executed evidence are marked UNPROVEN. Newest entry last.

---

## 2026-07-24 — Cross-platform roadmap drafted

- `CareerSeeker-CrossPlatform-Roadmap.md` written against the July 20 audit: Workstream
  M (macOS engine, M0–M6), Workstream I (iOS dashboard), meatspace table, timeline
  (macOS ≈ Q4 2026 if Windows L1 late Q3; iOS tracks Phase F + ~1 month).
- Key strategic call recorded: F2 (Android app) did not exist yet, so the iOS stack
  decision (I1) precedes Android UI code and constrains F1 envelope crypto.
- Status: planning spec only; no Apple code existed.

## 2026-08-13 — Repo re-audit + iOS-readiness assessment

- Fresh clone of `careerseeker` at `main @ efb9cd6`. Found the program had moved well
  past roadmap assumptions: `Sync-Protocol.md` v1 normative (610 lines), relay Worker
  real (`relay/`, Durable Objects, vitest), `src/Sync/` at 14 files, vector corpus at
  25+index, S-ladder mid-flight (draft PR #39 stack), R-ladder at R6 with R2 BLOCKED.
- Finding: **P1-CURVE made the protocol Secure-Enclave-native by accident** (P-256 is
  the enclave's only supported key type; `rawRepresentation` is the mandated 64-byte
  `r||s`).
- Identified ready-now work: Swift conformance harness (vectors self-contained; §10
  designed for third implementations), `entitlement_appstore` reservation, `:core` Tink
  question, Apple org enrollment as longest meatspace lead.

## 2026-08-13 — Swift conformance harness built and passing

- Swift 6.3.3 installed on Linux x86_64; swift-crypto probed: AES-256-GCM w/ AAD, HKDF,
  P-256 ECDH, ECDSA raw `r||s` (64 bytes), RSA-PKCS1-SHA1 via `_CryptoExtras` — all
  confirmed against real vector values before any package code was written.
- `careerseeker-ios-sync` SwiftPM package: `CareerSeekerSync` library (client role) +
  `conformance` runner. **All 25 vectors consumed (18 envelope, 2 pairing,
  5 entitlement): 42 checks, 0 failures.** Corpus digest
  `6366a86092971dfed0d96a560de1095962e6ce172a83b5a46e3037e5af1ab2ba` at source
  `efb9cd6`; per-file `SHA256SUMS` + `PROVENANCE.md` vendored.
- Mutation testing (harness must be able to fail): reserved-kind drop **caught**;
  envelope-supplied device key **caught**; skipped pre-decrypt `key_id` **caught**
  (envelope still decrypted — exactly §5.3's warning); lenient base64 **NOT caught** →
  filed as PQ-IOS-3.
- Findings filed: **PQ-IOS-1** (`entitlement_appstore` reservation; StoreKit 2 JWS
  ES256/x5c; CryptoKit has no RSA so the Play verifier won't port to Apple platforms for
  free), **PQ-IOS-2** (§7.2 lacks a malformed-envelope code), **PQ-IOS-3**
  (`invalid-padded-base64` non-discriminating; one-line `generate.mjs` fix; C#/Kotlin
  strict-decode equally untested).
- CI workflow included (Ubuntu 24.04, `swift:6.1-noble`); release build verified;
  `EXIT=0`.
- UNPROVEN: CryptoKit backend (needs Apple hardware); Secure Enclave path (compiles
  behind `#if`, never executed); Notification Service Extension budget/keychain-group
  design (needs device spike).

## 2026-08-13 — Structure decision: seam is app vs. engine

- New private repo `careerseeker-ios` for the iOS app + Swift sync SDK + (later) macOS
  menu-bar shell. macOS **engine** port stays in `careerseeker` (one engine, multiple
  RIDs, one Gate). Spec + vectors stay in `careerseeker` (single normative source; ios
  repo vendors a digest-pinned copy). PQ ledger stays in `careerseeker-android` (one
  queue, one amendment gate).
- Claude Project: Apple work gets its own project, seeded by this handoff package.

## 2026-08-14 — Handoff package assembled

- This package: manifest, project instructions, program handoff, this log, seed
  prompts, repo `CLAUDE.md`, roadmap + evidence + run log + repo-seed tarball.
- Next actions, in order: (1) create `careerseeker-ios`, extract tarball, commit,
  confirm CI green on GitHub's runner; (2) transfer PQ-IOS-1/2/3 into the android
  repo's PQ ledger verbatim from the Evidence doc; (3) land the PQ-IOS-3 one-liner in
  `generate.mjs` upstream (main-repo change — file as a request to the engine program,
  not an edit from here); (4) send Fable a `careerseeker-android` bundle to resolve the
  `:core` Tink question and unblock ADR I1; (5) file Apple org enrollment when LLC
  papers exist.

---

<!-- Append new entries below. Format: date — headline; verified facts with numbers;
     findings; UNPROVEN items; what remains. -->

## 2026-08-14 — T1 phone-role sender self-tests BLOCKED

- Changed CareerSeekerSync to add PhoneEnvelopeSender: it seals p2e payloads with a
  fresh AES-GCM nonce, signs state-changing payloads over the §5.4 input, and rejects
  reused or regressed sender sequence numbers. The conformance runner now derives
  pairing keys from the phone private key plus engine public key in pairing-basic,
  checks each derived value against the engine-role result, seals a vector-backed
  doc_edit through a software device key, opens it with EnvelopeReceiver, and checks
  receiver-cursor advance plus sender sequence refusal. Vectors/, PROVENANCE.md, and
  the workflow were not changed.
- BLOCKER, attempt 1: swift build -c release and swift run -c release conformance could
  not start because this Windows environment has no swift executable.
- BLOCKER, attempt 2: no Docker runtime is installed and wsl -l -q reports that WSL is
  not installed, so no Linux Swift runtime is available locally.
- UNPROVEN: release build, conformance result and corpus digest, and all deliberate
  mutation demonstrations. No test result is claimed.
- Stopped after the required two attempts. Resume on a host with Swift 6 (or the
  repository's Linux CI runtime), run both required gates, then demonstrate the three
  new check groups fail under deliberate mutations before treating T1 as complete.

## 2026-09-22 — T1 reconciled; D1–D6 complete on Linux Swift

- Fresh clone began at `main` `062b79576e4408f534b88cacab6c8de89b3d17fc`;
  read-only engine clone was `d2c6a9ae88af3ca0ed1257a1afc6e085c5c9d10c`.
  The Windows host had no Swift executable, its only WSL distribution had no shell, and
  Docker Desktop did not expose a Linux engine after startup. The required gates were
  therefore executed in the repository's existing `swift:6.1-noble` GitHub Actions
  environment. Apple hardware was not used.
- **T1 verdict: MERGE.** `terra/t1-unvalidated` still pointed exactly to `04d49c0`; its
  merge base with current `main` was `f3b8ec0`, with `main` 2 commits ahead and T1 1
  commit ahead. The actual T1 objects contain 4 files, 211 insertions, 2 deletions; no
  16-line partial push exists. The old anomaly was an uncommitted/line-ending observation,
  not repository history. Integrated commit `450a7c3` built and passed 50/0 against
  digest `6366a86092971dfed0d96a560de1095962e6ce172a83b5a46e3037e5af1ab2ba`
  ([green run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35765897617)).
  Deliberately corrupting phone peer derivation, suppressing required signatures, and
  allowing sequence reuse/regression produced 8 failures
  ([mutation run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35766252001)).
- **D1:** `swift-crypto` now requires 4.5.1+ and resolves to 4.5.2
  (`da9d28d69ebe3894b18376c8f2395c2f37b8448f`); release build and the then-current
  50/0 conformance gate passed with no API changes
  ([resolver run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35766448623)).
  Moving engine-role `PlayEntitlementVerifier` out of the public client target is a
  source/API change, so follow-up [iOS issue #1](https://github.com/ShivaClaw/careerseeker-ios/issues/1)
  was filed; the verifier did not grow.
- **D2:** re-vendored the authoritative 29-case corpus byte-for-byte from engine `main`
  and pinned aggregate digest
  `f9fe90be5d1b62cfdfeb814f0936ce7df945e51a9743744723ee1775dc06fb6a`.
  The runner rejects unknown families, accounts for declared/executed/explicitly skipped
  cases, dispatches high-bit pairing and both entitlement acknowledgements, and uses
  separate receiver contexts. Its D2 gate reported 29 declared, 28 executed, 1 explicit
  D4 skip, 62/0
  ([green run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35767882042));
  disabling the whole entitlement-ack family failed with both names unaccounted
  ([mutation run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35768278141)).
- **D3:** the binding 1 MiB cap is now measured on decoded ciphertext including the tag;
  a separately derived base64url-plus-4-KiB wire guard protects allocation. The exact
  1,048,576-byte boundary reaches AEAD, byte 1,048,577 returns `too_large`, and the
  coarse guard fires pre-parse ([66/0 gate](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35768542930)).
  The shared maximum-valid vector request is filed as
  [engine issue #63](https://github.com/ShivaClaw/careerseeker/issues/63); no local-only
  vector was created.
- **D4:** the local wire-visible `.malformed` code was removed. Detailed parser errors
  remain internal and structural rejection maps to `decrypt_failed`. All 29 vectors then
  executed with zero skips and 67/0, including `invalid-unknown-field`
  ([green run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35769058371)).
  PQ-IOS-2 is recorded closed in the Android ledger request below.
- **D5:** `ReplayBoundary` can be persisted and restored through `EnvelopeReceiver`;
  negative durable values fail construction. A reconstruction test accepts once, saves
  the cursor, and rejects the same envelope after restart. The C07 note requires one
  durable owner to commit replica plus checkpoint atomically and restricts a future
  notification extension to noncommitting presentation. The full gate reported all 29
  executed, 71/0
  ([green run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35769633847));
  deliberately ignoring restored state made the replay test accept and fail
  ([mutation run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35769944519)).
- **D6 / coordination:** Android
  [issue #7](https://github.com/ShivaClaw/careerseeker-android/issues/7) requests the
  canonical ledger entries: PQ-IOS-1 remains open with the exact StoreKit/protocol
  decision requested; PQ-IOS-2 is closed; PQ-IOS-3 remains open. The upstream
  discriminating padded-base64 generator change is filed as
  [engine issue #64](https://github.com/ShivaClaw/careerseeker/issues/64).
- **UNPROVEN:** CryptoKit, Secure Enclave, App Group cross-process storage, Notification
  Service Extension behavior, any app target, and TestFlight. Linux Swift proves SDK and
  protocol behavior only.
- **Brandon decisions — exactly the four program gates:** (1) provide the Apple
  hardware/Xcode lane; (2) choose independent Swift vs KMP from actual reuse cost;
  (3) choose the Apple paid/free boundary; (4) decide PQ-IOS-1. No TestFlight clock,
  purchase, enrollment, or Apple-side action was triggered.

## 2026-09-23 — 30-case re-vendor blocked before CI

- Fresh iOS clone began clean at `main` `38e03c8e5cece30ceaf502fa499cf6ac5e2c7ae8`;
  read-only engine clone began at `main` `081b5eb611c27f92fb757b88a31ef09a6b945288`.
  Engine commit `5db3f949aaff1b4b76dd9eedc590aa8e1d471a05` is an ancestor of its
  current main, with no subsequent corpus changes.
- Local branch `sol/ios-revendor-20260923` has commit `f3bf611` containing only the
  verbatim 30-case corpus copy, updated per-file SHA256SUMS, and provenance. The three
  changed JSON Git blobs match engine `5db3f94` exactly. All 31 SHA256SUMS entries
  verify. Aggregate runner-method digest computed from those bytes is
  `326866efe88887b570aba2ec99a6da66e9a59bdf09c2df28b4292477dd7c8d63`.
- BLOCKER, attempt 1: `git push -u origin sol/ios-revendor-20260923` returned HTTP
  403, permission denied to ShivaClaw. GitHub API reported the logged-in account has
  push permission, but the Git remote still rejected the write.
- BLOCKER, attempt 2: `gh auth setup-git` followed by the same push returned the same
  HTTP 403. Per the repository's two-attempt rule, stopped before further implementation.
- UNPROVEN: CI failure on the new `boundary` family, Linux release build, 30/30
  conformance, padding and boundary mutations, and Play verifier isolation. No upstream
  engine files were edited and no iOS PR was created. Resume after Git push credentials
  are repaired or on a writable host; then push the corpus-only commit first so CI
  records the expected unknown-family failure before changing the runner.

## 2026-09-23 — Re-vendor resumed; boundary, key-ID pin, and verifier isolation verified

- Push credentials were repaired externally. The corpus-only commit `f3bf611` went up
  first; its [Linux run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35943089648)
  built but failed conformance exactly as intended: unknown family `boundary`, its
  case unaccounted, 30 declared / 29 executed / 0 skipped, 69 passed / 2 failed,
  digest `326866efe88887b570aba2ec99a6da66e9a59bdf09c2df28b4292477dd7c8d63`.
- Implementation commit `0948f41` added a dedicated receiver for the boundary family,
  exact 1 MiB decoded/1,398,102-character wire and plaintext-byte checks, and a same-
  receiver +1 decoded byte `too_large` check. The fresh-pairing receiver now defaults
  to `k1`; conformance asserts that value against the vendored `initial_key_id` and
  rejects the corpus's different mid-life key before decryption. The engine-role Play
  verifier moved from the client target to a separate corpus-only target; the runner
  still executes all five Play vectors. `Package.resolved` did not change.
- The [release build and conformance run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35943397509)
  passed: 30 declared / 30 executed / 0 skipped, 78 passed / 0 failed, digest
  `326866efe88887b570aba2ec99a6da66e9a59bdf09c2df28b4292477dd7c8d63`.
  The client target compiled without errors or new Swift warnings. The workflow file
  did not change: this credential can push source but lacks GitHub's `workflow` scope.
- Deliberate mutation evidence, each from the green implementation commit: accepting
  `=` padding made the rebuilt `invalid-padded-base64` decrypt and **accept**, failing
  four checks including replay-state fallout
  ([run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35943615242));
  changing the decoded-byte cap from `<=` to `<` rejected the shared maximum-valid
  vector and failed two checks
  ([run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35943636513));
  changing `k1` to `k2` failed the manifest assertion
  ([run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35943668038));
  and importing the corpus-only module from a client-target file failed the existing
  release-build gate with `no such module 'CareerSeekerCorpusCoverage'`
  ([run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35943652981)).
- PQ-IOS-3 is closed on the iOS side by the discriminating upstream vector plus the
  padding-lenient mutation above; relay this to the Android-owned canonical PQ ledger.
  PQ-IOS-1 remains Brandon's StoreKit/protocol decision. UNPROVEN: CryptoKit, Secure
  Enclave, App Group cross-process storage, extension behavior, app target, TestFlight.

## 2026-09-25 — Alpha release gate made explicit; no Apple build claimed

- Fresh clone began clean at `main` `bba24bd57636a1428cb9066666e0e6832bf874e5`.
  The existing Linux Swift evidence remains 30/30 vectors, 78/0 checks, corpus digest
  `326866efe88887b570aba2ec99a6da66e9a59bdf09c2df28b4292477dd7c8d63`
  ([run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35943397509));
  this session did not rerun it. `README.md` now matches that pinned record and notes
  the later padded-base64 mutation that closed PQ-IOS-3 on the iOS side.
- `docs/Alpha-Release-Gates.md` records the concrete path from a KMP Apple framework
  through real app/device/TestFlight proof to a truthful `careerseeker.app/download/`
  link. It keeps DS-8.2/O3 and the canonical DS-8.3 UI checklist in force. Android
  draft PR #12 moves protocol, pull policy, Ktor relay and token handover, base64url,
  and envelope parser
  source; its Apple framework, crypto, and vectors are still unproven.
- `docs/Apple-Handoff.md` now labels its older paid-app and independent-Swift
  assumptions as historical, pending the design contract's O3 and alpha boundary.
- The Windows host has no `swift` executable (`Get-Command` and `where.exe` found none),
  so the required release build and conformance gates cannot run locally. No Swift
  source or workflow changed here; this is a documentation/readiness PR, not a new
  conformance claim.
- UNPROVEN: Apple target compilation, CryptoKit/Secure Enclave, any iOS app target,
  on-device pairing/sync, signing, TestFlight, and public install link. Remains:
  Brandon's O3/bundle/free-alpha decisions and Apple account/build-lane access, then
  the implementation and evidence gates in `Alpha-Release-Gates.md`.
