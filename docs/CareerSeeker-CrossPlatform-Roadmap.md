# CareerSeeker Cross-Platform Roadmap — macOS Engine + iOS Dashboard

Draft 2026-07-24 · Fable · Status: **planning spec, not scheduled work**. Companion to `docs/CareerSeeker-Integration-Windows-Roadmap.md`; workstream letters continue its scheme (M = macOS, I = iOS).

## 0. Position in the sequence

This is post-L1 work and must not jump the queue. Hard prerequisites before either port starts:

1. **CI exists and guards the harnesses** (audit M1). Porting doubles the claimed-vs-actual surface; a second platform without CI is two platforms of unverifiable status reports.
2. **H1 (SSRF) and H2 (ReconcileAsync wiring) closed.** Porting a known-vulnerable fetch path and an inert crash-recovery guarantee just replicates the debt.
3. **Windows L1 beta stable (E1 running).** The port target should be a proven engine, not a moving one.
4. **C3 (Managed-inference posture) decided** — it shapes onboarding on every platform and the App Store privacy labels.

One exception belongs in the *current* work queue: **M0 portability hygiene** (below) is cheap now and expensive later, and two of its items are already flagged in the July 20 audit as latent Windows bugs-in-waiting (M2/L2 case-sensitivity).

**iOS strategic note, stated up front:** Workstream F (Android app) has not been built yet. That means the correct iOS strategy is not "port the Android app later" — it is **build F2 multiplatform once**, so iOS is a second UI target rather than a rewrite. The F2 stack decision (§2.1) is therefore an *iOS* decision that must be made *before* the first line of Android code, i.e., much earlier than any iOS ship date.

---

## Workstream M — macOS engine

The good news: the engine core is .NET 8, and .NET 8 is a first-class macOS citizen. Pipeline, Gate, Researcher, Dispatcher, Store, and every offline harness should compile and run on macOS with near-zero changes. All safety invariants (Gate graph, pinned entailment stage, no-send Dispatcher) are pure managed code — **nothing about the port touches an invariant.** The port cost is concentrated in five Windows-specific seams.

### M0. Portability hygiene (do now, on Windows, benefits Windows)

- **`ISecretVault` abstraction.** DPAPI (`ProtectedData`) is Windows-only and is currently the vault for OAuth tokens and BYOK keys. Extract an interface now; Windows impl stays DPAPI. This is the single most security-sensitive seam in the port — treat the interface design as ADR-worthy.
- **Path and case-sensitivity fixes.** Audit M2/L2 already flagged `OrdinalIgnoreCase` prefix compares in `Host.cs` document-serving and `AlphaPackageImport.cs` as "wrong if this ever runs case-sensitively." APFS is case-insensitive by default but can be case-sensitive; the fix is a platform-appropriate comparer chosen at startup, and it hardens Windows too (it converts an assumption into code).
- **Data directory abstraction.** `%ProgramData%\CareerSeeker\` → `Environment.SpecialFolder`-derived paths (`~/Library/Application Support/CareerSeeker` on macOS). Privacy-policy copy references the Windows path; the trust-copy claims register should note the per-OS variants.
- **RID-aware publish + SQLite natives.** `Microsoft.Data.Sqlite` via `SQLitePCLRaw.bundle_e_sqlite3` ships mac natives (`osx-arm64`/`osx-x64`); this rides on the already-planned SQLite restoration (the `nuget.config` source-clearing must be resolved first regardless).
- **Inventory Windows-only API leakage.** Grep for `System.Security.Cryptography.ProtectedData`, registry access, `Environment.OSVersion` branches, `HttpListener` assumptions. `HttpListener` itself works cross-platform in .NET (managed implementation off-Windows), but verify the `UserHostName`/loopback checks in `Host.cs` behave identically — those carry real security weight per audit M3.

Estimated effort: 1–2 weeks of agent work interleaved with current remediation. Everything else in Workstream M waits for the §0 gates.

### M1. Keychain vault

macOS impl of `ISecretVault` backed by the Keychain (Security.framework via P/Invoke, or a vetted thin wrapper — evaluate before trusting a dependency with token custody). Access-control choice matters: kSecAttrAccessibleAfterFirstUnlock-class semantics so the LaunchAgent can read tokens after login without prompting. A `VaultParityHarness` (round-trip, absence-fails-closed, wrong-account isolation) mirrors the DPAPI harness.

### M2. Background host — and the Session 0 dividend

macOS host is a **launchd LaunchAgent** registered via `SMAppService` (macOS 13+), running in the user's login session. This dissolves the platform's version of the open Windows contradiction: a LaunchAgent lives in the GUI session, so **headed Playwright works without any Session 0 equivalent**. Two implications: (a) the macOS host design is straightforwardly simpler than C2; (b) it strengthens the case that the Windows answer is also a user-session autostart process (Task Scheduler at-logon / Run key) rather than a true Windows Service — worth folding into the C2 decision rather than resolving twice.

Playwright itself fully supports macOS; Chromium download and headless/headed both work. No engine changes expected.

### M3. Shell — WinUI 3 does not port

The tray app/onboarding host is the one component with no cross-platform path. Options:

- **(a) Recommended: native menu-bar wrapper.** A small Swift `NSStatusItem` app that supervises the .NET engine process, shows status glyph/pause/kill, and opens the existing localhost dashboard (default browser or `WKWebView`). Onboarding is served by the engine's own HTTP UI. Keeps the engine headless and identical across OSes; the per-platform surface is ~1–2 KLOC of shell.
- **(b) Avalonia.** Cross-platform XAML; could eventually replace WinUI 3 and unify shells. More upfront cost, one codebase later. Defer unless the WinUI 3 shell is already painful.
- **(c) .NET MAUI / Mac Catalyst.** Rejected — poor fit for menu-bar utility apps, adds a heavy dependency for a thin shell.

Option (a) also means the signed/notarized artifact is a conventional `.app` bundle with the .NET engine embedded as a helper — the shape Apple's tooling expects.

### M4. Laptop physics

Most Macs are laptops; lid-closed means the engine is asleep. This is true on Windows laptops too but is near-universal on Mac and must be a designed-for state, not a surprise: App Nap exemption for the engine process while a cycle is running (bounded power assertion, released between cycles — never a permanent `caffeinate`), catch-up scheduling on wake, and honest copy ("CareerSeeker works while your Mac is awake"). H2's reconcile sweep, once wired, is also the wake-recovery path.

### M5. Signing, notarization, distribution

- **Developer ID Application** certificate (included in the $99 program), **hardened runtime** entitlements (JIT entitlement needed for .NET; Playwright's helper processes need audit), **notarization** via `notarytool` + stapling. Unsigned/un-notarized apps are effectively undistributable on modern macOS — this is the Gatekeeper analog of the SmartScreen problem, but unlike SmartScreen there is no reputation aging: notarization passes or it doesn't, which is actually the friendlier regime.
- **Format:** `.dmg` with drag-to-Applications. **Updates:** Sparkle 2 (signed appcasts) — the de-facto standard; a custom updater is not worth building.
- **Architecture:** ship **arm64-only** at launch. Intel Macs are past their last macOS by 2026; supporting x64 doubles the CI/test matrix for a shrinking audience. Revisit only on demand signal.

### M6. CI expansion

GitHub Actions macOS runners for build + offline harness suite + the SQLite harnesses (real SQLite works fine there). Cost note: macOS runner minutes bill at ~10× Linux minutes on private repos — budget accordingly or gate mac CI to PR-merge rather than every push.

---

## Workstream I — iOS dashboard

### I1. The F2 stack decision (make before Android is built)

Three options, evaluated against "F2 doesn't exist yet":

- **(a) Recommended: Kotlin Multiplatform, shared core + Compose Multiplatform UI.** Share the event-log replica, relay protocol client, E2E crypto, and viewmodels; swap Room→**SQLDelight**, OkHttp→**Ktor** in the F2 spec (both are drop-in-grade for a thin dashboard client). Compose Multiplatform renders on iOS (stable since 2025); one UI codebase, both stores. The dashboard is exactly the app shape KMP is best at — thin client, no deep platform integration except notifications.
- **(b) KMP shared core + SwiftUI shell.** Same shared logic, native iOS feel. Choose this if Compose-on-iOS quality disappoints during a 1-week spike.
- **(c) Independent SwiftUI rewrite.** Only correct if F2 had already shipped pure-Android. It hasn't; rejected.

Amendments to the F2 section of the spec if (a) is adopted: minSdk stays 26; Room/OkHttp references become SQLDelight/Ktor; crypto must be a multiplatform implementation (libsodium bindings or Kotlin crypto) rather than a JVM-only library — this constrains the relay envelope format design in **F1**, which is another reason the decision predates Android code.

### I2. Push and the E2E envelope on iOS

FCM delivers to iOS via APNs, but the E2E design has iOS-specific consequences:

- **Notification Service Extension** is mandatory to decrypt ciphertext payloads into human-readable notifications ("Gate: approve application to Acme?"). The extension runs sandboxed with ~30s budget; keys shared with the main app via Keychain access group. Without it, users see opaque placeholder pushes — unacceptable for the product.
- **Actionable notifications** (Approve/Skip inline) map to `UNNotificationCategory` — supported, parity with Android achievable.
- **Silent/background pushes are throttled** by iOS; the app cannot hold a background WSS connection. State freshness model: push-driven + foreground refresh, not live socket. The **kill switch** honesty requirement carries over: the app must surface "engine unreachable / last ack" rather than implying instant control it can't guarantee in background.

### I3. App Store realities (the review gauntlet)

- **Companion-app review:** the app depends on a desktop engine the reviewer doesn't have. Provide a **demo mode or reviewer test relay** with seeded data — App Review rejects what it cannot exercise. Build demo mode as a feature, not a hack; it doubles as the store-listing screenshot generator.
- **Paid up-front at $4.99** is fine and matches the one-way-door pricing decision. Enroll in the **App Store Small Business Program** (15% commission under $1M; net ≈ $4.24/sale).
- **Pro stays web-sold.** The Play-billing gray zone repeats on iOS with stricter enforcement: if the app *unlocks or upsells* digital features, Apple requires IAP. Posture: the iOS app is a one-time-paid viewer for engine state; it does not sell, mention, or link to Pro purchase in-app. (US anti-steering rules have loosened external-link policy, but the litigation-proof posture is silence.)
- **Privacy nutrition labels:** the honest answer — "Data Not Collected" for the developer, with the relay's ciphertext-only design documented — is a marketing asset; get the label right and screenshot it.
- **Export compliance:** E2E crypto requires the encryption declaration in App Store Connect; standard-algorithm exemption applies but must be claimed, and the annual self-classification report obligation should go on the compliance calendar next to CASA.

---

## Meat-space obligations

| Item | Detail | Cost | Lead time |
|---|---|---|---|
| Apple Developer Program (organization) | One membership covers **both** macOS Developer ID and iOS App Store. Requires: **legal entity** (LLC — already in progress; DBAs rejected), **D-U-N-S** (already in flight for Play org — same number reuses), Apple ID with 2FA under legal name, **public website on the org's domain** (careerseeker.app qualifies; ensure it shows business identity/contact), verification phone call — D&B record phone must be answered | $99/yr | Org verification typically **1–2 weeks** after LLC + D-U-N-S exist; start immediately once the LLC papers land |
| Mac hardware | Required for Xcode, iOS builds, notarization workflow, and real testing; CI runners don't replace a dev/test machine | Mac mini M4 ~$599–799 one-time | Same-week |
| iOS test device | Physical device needed for push/Notification-Service-Extension testing (simulator push support is partial) | Used iPhone ~$200–350 one-time | Same-week |
| macOS CI | GH Actions macOS minutes ≈ 10× Linux rate | est. $10–40/mo depending on gating | — |
| Small Business Program | Enroll in App Store Connect once membership is live | $0 | Days |
| Export-compliance self-report | Annual, tied to E2E crypto in the apps | $0 | Calendar item |

**What does *not* change:** CASA/OAuth verification is per-Google-Cloud-project, not per-OS — the engine holds `gmail.compose` identically on macOS, and the iOS app (like Android) never touches Gmail scopes through the blind relay. No new CASA cost, no new SAQ scope, provided the relay stays blind. Incremental recurring cost of the entire cross-platform program is essentially **$99/yr + CI minutes**.

## Realistic timeline

Assumes solo founder + agents, and the §0 gates (CI, H1/H2, E1 beta running) cleared first. Calendar time, not effort time.

- **Now → +2 wks:** M0 portability hygiene folded into current remediation. LLC completes → start Apple org enrollment (runs in parallel with everything).
- **Port start → +6–10 wks:** M1–M3 (vault, launchd host, menu-bar shell) to a self-built macOS alpha running a full DISCOVERED→DRAFTED cycle. The wide range is honest: the engine core ports in days; the shell, vault, and signing plumbing are where weeks go.
- **+2–4 wks:** M5/M6 — signed, notarized, Sparkle-updating `.dmg` + mac CI green. macOS closed beta.
- **iOS:** I1 decision at F2 spec time (pre-Android). If KMP: iOS beta lands **+3–6 wks after the Android app ships**, mostly notification-extension and review-prep work. App Review: budget **1–2 wks including one rejection cycle** (companion apps commonly eat one on reviewability — the demo mode is the insurance).

Blunt summary: if Windows L1 public launch happens around late Q3, **macOS public is a Q4 2026 outcome and iOS tracks Phase F plus roughly a month** — and the only piece of this that belongs in this week's work is M0 plus filing the Apple enrollment the day the LLC exists.

## Decisions needed (ADR candidates)

1. **F2 stack: KMP/Compose-MP vs SwiftUI shell** — decide before any Android code; constrains F1 envelope crypto.
2. **macOS shell: native menu-bar vs Avalonia** — cheap now vs unified later.
3. **arm64-only** at macOS launch — recommend yes.
4. **C2 revision:** adopt the user-session-agent model on Windows in light of the launchd finding, retiring the Session 0 contradiction in one decision instead of two.
