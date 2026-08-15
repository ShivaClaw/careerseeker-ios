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
