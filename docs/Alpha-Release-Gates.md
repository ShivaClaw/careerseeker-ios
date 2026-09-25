# iPhone alpha: build-to-download gate

Status 2026-09-25: **not releasable**. This repo has a Swift sync package and a Linux
conformance runner, not an iOS app target or an Apple-signed build. The latest verified
runner evidence is 30/30 vectors, 78/0 checks at corpus digest
`326866efe88887b570aba2ec99a6da66e9a59bdf09c2df28b4292477dd7c8d63`
([CI run](https://github.com/ShivaClaw/careerseeker-ios/actions/runs/35943397509)).
That is protocol evidence, not iPhone execution evidence.

## Decisions and access before distribution

1. Brandon confirms DS-8.2/O3's SwiftUI-over-shared-Kotlin-core direction, the
   permanent bundle ID, and whether the first alpha is free-only. The current design
   contract is `ShivaClaw/careerseeker` `docs/Design-System.md`; do not build a second
   Swift state machine or improvise a platform-specific UI contract. Paste its exact
   DS-8.3 checklist into every UI PR.
2. Confirm an active Apple Developer Program team, App Store Connect access, a macOS
   Xcode build lane, and signing/upload credentials. Do not register a bundle ID or
   purchase services on an inferred answer.
3. Keep this repo's engine-role Play corpus verifier out of any client binary. Published
   vector keys and fixed nonces must never appear in a shipping app.

## Build acceptance, not just a screenshot

1. The KMP `:core` framework must compile for `iosArm64` and `iosSimulatorArm64` on
   macOS, with an explicit native crypto boundary. Kotlin/Native cannot directly import
   Swift-only CryptoKit ([interop docs](https://kotlinlang.org/docs/native-objc-interop.html)).
   The current framework exports through Objective-C headers: inspect the generated
   `DigestPort` protocol and compile a Swift CryptoKit implementation before treating
   that bridge as viable. The separate Swift-export mode is not configured here.
   The configured Gradle task is `:core:assembleCareerSeekerCoreXCFramework`; task
   discovery on Windows proves configuration only, not an Apple link.
   Android JVM behavior must remain green. Draft Android KMP PR #12 moves protocol
   vocabulary, pull policy, relay transport and token handover, QR invite
   validation, a compatible base64url codec, strict envelope parsing, and shared
   HKDF/pairing derivation behind `DigestPort`, and pairing-completion assembly
   behind `PairingCryptoPort`,
   but it is **not** this gate.
2. Run the shared 30-case corpus against the actual iOS implementation. Record the
   corpus digest, declared/executed/skipped accounting, expected error codes, and a
   deliberate failing mutation. The existing Linux Swift run is not a substitute for
   Apple-target evidence.
3. Build and exercise a minimal SwiftUI shell, pairing, foreground pull, and a durable
   replica/replay checkpoint as specified by `docs/C07-Durable-Replay-Ownership.md`.
   Verify on simulator and a real iPhone; identify anything only simulator-proven.
   No notification extension or background-freshness claim without device evidence.
4. Verify that every visible state is sourced from the engine or clearly labeled demo;
   the phone must not imply it sent email, completed an irreversible action, or granted
   Pro on its own. Run the design-system checklist on the UI PR.
5. Archive with Xcode, sign for the chosen team/bundle ID, upload, and verify an
   installable TestFlight build. Record the exact build, platform, test device, pairing
   scenario, and outcome. Apple's [TestFlight overview](https://developer.apple.com/help/app-store-connect/test-a-beta-version/testflight-overview/)
   describes the upload, tester, and build-expiration path.

## Publication gate for careerseeker.app/download/

Internal TestFlight access is not a public download link. For a public download-page
CTA, create an eligible external tester group and obtain its valid TestFlight public
link; Apple's [external tester instructions](https://developer.apple.com/help/app-store-connect/test-a-beta-version/invite-external-testers)
cover review and public-link availability. Have a tester open the link and install the
same verified build before publishing it. If external access is not yet approved,
leave the site truthful about availability.

The website source is `site-v3`; its `release.json` currently has Windows and Android
entries but no iOS release field. Any iPhone card needs a deliberate source-schema and
`build.py` change under the canonical design contract, followed by preview and live
`/download/` checks. Audit its other generated iPhone-status copy too (home/FAQ,
`/dashboard/`, trust, and privacy) so one available card does not coexist with an
"in development" or unverified privacy claim elsewhere. Never present the Swift
package, an unsigned `.ipa`, or a pending
TestFlight invitation as an available iPhone alpha.
