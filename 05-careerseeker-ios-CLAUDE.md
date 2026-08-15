# CLAUDE.md — careerseeker-ios

Agent instructions for this repo. Binding on Fable, Terra, and any future agent. The
program-level context lives in `docs/Apple-Handoff.md`; read it first in any session.

## What this repo is

The Apple **app-side** of CareerSeeker: the Swift sync SDK (`CareerSeekerSync`), its
conformance runner, the iOS dashboard app (when it exists), and later the macOS
menu-bar shell. The engine, the wire spec, and the relay live in
`ShivaClaw/careerseeker` and are consumed, never re-implemented, here.

## Truth hierarchy

1. `ShivaClaw/careerseeker` → `docs/Sync-Protocol.md` — **normative** for the wire.
2. `docs/sync-vectors/v1` upstream — normative corpus. `Vectors/` here is a vendored,
   digest-pinned copy (`Vectors/PROVENANCE.md`); if digests disagree, re-vendor — never
   reconcile by hand, never edit a vector file.
3. This repo's code — an implementation. Tests pin implementations, not the wire.
4. `docs/Apple-Handoff.md` and `docs/Apple-Progress-Log.md` — orientation; amended when
   reality diverges, never the other way around.

## Gates (all of them, every time)

- `swift build -c release` — 0 errors, 0 warnings introduced.
- `swift run -c release conformance` — exit 0. Paste the summary block **and the corpus
  digest** into any completion claim; a count without the digest pins nothing.
- New protocol-adjacent behavior ships with a check that can fail, and evidence that it
  fails under a deliberate mutation. A harness that cannot fail proves nothing.
- Rejecting for the wrong reason is a failure (Sync-Protocol §10). Match error codes,
  not just accept/reject.

## Invariants inherited from the program

- **Blind relay**: nothing here may require the relay to see plaintext or hold a key.
- **Engine authoritative**: this app proposes; it never causes irreversible engine
  action on its own, and nothing here creates a path to sending email.
- **v1 vocabulary is closed**: reserved L2 kinds are rejected as `unknown_kind`. No
  parser for unshipped shapes.
- **Strictness is the requirement**: unpadded base64url rejected if padded; unknown
  top-level envelope fields rejected; `key_id` checked before decryption; replay checked
  on the header; the cursor advances only on acceptance.

## Boundaries

- Never edit, from this repo's lanes: main-repo `src/Sync/`, `Host.cs`, verifier
  scripts, `docs/Sync-Protocol.md`, `docs/sync-vectors/`. Cross-repo needs are filed as
  requests.
- Protocol questions go to the PQ ledger in `careerseeker-android`, prefixed `PQ-IOS-`.
  Open at time of writing: PQ-IOS-1 (`entitlement_appstore`), PQ-IOS-2 (malformed error
  code), PQ-IOS-3 (padded-base64 vector — fix lives in upstream `generate.mjs`).
- `PlayEntitlementVerifier` is **engine-role**, present only for corpus coverage. No iOS
  client code path may call it; do not grow it.
- Platform claims: anything requiring Apple hardware (CryptoKit backend, Secure Enclave,
  Notification Service Extension) is UNPROVEN until executed there. Linux CI proves
  protocol logic only. Say which one you have.
- Published test keys in `Vectors/` MUST NOT appear in any build; fixed nonces are
  correct only there.

## Session discipline

- Start by fresh-cloning and reporting HEAD; end any changing session by appending a
  dated entry to `docs/Apple-Progress-Log.md` (verified facts with numbers; findings;
  UNPROVEN items; remains).
- SHA-verify any prior agent claim before building on it. Two-attempt limit on blocked
  work; write the blocker and stop.
- Consumer-facing copy: no internal terminology (envelope, AAD, relay internals, L1);
  "autonomous software," not "AI"; every public claim maps to a structural invariant,
  harness, or ADR.
