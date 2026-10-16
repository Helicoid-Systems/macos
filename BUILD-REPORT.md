## Coordinator native authentication and expiry candidate, 16 October 2026

Coordinator packaging passed **229 core tests plus 2 actual ManagerSession tests**,
then built and packaged both release applications. `codesign --verify --deep
--strict` passed for both ad-hoc development bundles. Independent before/after
regressions prove cancellation no longer spins, deadline tasks do not retain
abandoned clients, subsecond continuous time is preserved, and actual automatic
expiry clears UI state without another user action. The actual Manager facade
now observes those changes through a weak, generation-fenced coordinator link.

Exported session metadata confirms `xiaomi-token-plan-ams/mimo-v2.6-pro`, `high`.
The receipt is `/tmp/hs-finish-20261013/coordinator-macos-final-package-receipt-20261016.json`.
Native CI and the current real Rust HTTPS interop rerun are pending. Ad-hoc
signatures do not pass Developer ID/notarization, installed worker/hosting,
Intel runtime, public routing, media/control or any complete release checkpoint.
No production trust fixture or supplied artwork was changed.

# BUILD-REPORT — Helicoid macOS (apps/macos)

## Reviewed SSH lifecycle and asynchronous fixture generation, 11 October 2026

MiMo exported metadata confirms `xiaomi/mimo-v2.6-pro` for both bounded packages. The coordinator reviewed each diff and fixed missed failure cleanup, incomplete-stdin handling and deadline success semantics. The local command runner uses checked POSIX spawn/file actions, nonblocking owned pipes, fd-scoped SIGPIPE suppression and sole PID reaping. Cancellation before registration is latched; all terminal failures reap the owned child before returning. No raw PID signal follows reaping, no process-wide signal handler changes, and success requires complete output EOF. New actual OS regressions cover unread stdin, trailing output, child cleanup on cancellation/overflow, pre-start cancellation, inherited pipe writers, NUL refusal and independent later commands.

The narrow checks passed near 50 ms, but concurrent full-suite checks initially failed the original one-second deadline assertions. A disposable probe observed actual spawn at 2–7 ms and failure continuation resume at 50–52 ms; instrumentation perturbed scheduling. TLS generation/material locks synchronously blocked test executors. The test-only repair retains one native generation worker and real certificates while awaiting tasks suspend. An actor owns shared material and its single generation flight; cancelled fixture requests dispose their owned files. Production TLS trust checks are unchanged. Tests and thresholds are not skipped, relaxed or serialized as suites.

MiMo checks passed 54 certificate/trust/socket cases and all 186 tests in 27 suites (21.888s). The coordinator froze the six source/test files, verified their hashes, and independently passed **186 tests / 27 suites** (21.054s), Apple Silicon release builds, supplied artwork packaging and strict ad-hoc bundle signatures. The same production source cross-builds as x86_64; arm64 and Intel Mach-O minimum OS is 15.0. Source compilation is not Intel runtime acceptance.

Native [CI 38167550626](https://github.com/Helicoid-Systems/macos/actions/runs/38167550626) passes at exact code revision `7bf00ac9ce6b03f47f66539a913136451abe55fd`: all 186 tests in 27 suites pass in both Test (43.877s) and Package apps (43.843s), release packaging and Intel source build pass. The coordinator downloaded [artifact 11711859570](https://github.com/Helicoid-Systems/macos/actions/runs/38167550626/artifacts/11711859570), checked both ZIP archives and strict ad-hoc bundle signatures, and verified arm64 executables with minimum macOS 15.0. Artifact digest: `89b2f3928c5bd0cd1a08de3f6c62c0d008500af70d051e584db46389749593f2`. Native acceptance is scoped to these prerequisites. Platform signing, trust adoption, installed workers, real preview/control and recovery remain unavailable.

## Current pinned HTTPS prerequisite, 11 October 2026

Sanitized MiMo Code session metadata confirms `xiaomi/mimo-v2.6-pro`. The coordinator reviewed task-owned trust diagnostics, sole pinned CA evaluation with no online CA fetch, request registration/disposal, bounded streaming and cancellation. Native trust remains strict; no OS-root fallback or insecure override was added.

The session-level auth method is omitted so URLSession forwards server trust to the task handler with the actual task. Diagnostics are stored only on that task's sink; missing/retired task IDs cannot rewrite a sibling. Certificate count is inspected only after configured native evaluation, and external CFError descriptions are omitted. A real-socket regression shares one production delegate between two tasks and replays the exact retired task's foreign-certificate challenge; the other task still cancels independently. The coordinator corrected the fixture recorder to index challenges by task ID rather than select whichever callback arrived last.

Coordinator `HELICOID_BUILD_DIR=/tmp/hs-build/macos-tls-package HELICOID_DIST_DIR=/tmp/hs-build/macos-tls-dist ./scripts/build.sh` passed **173 tests in26 suites** (19.833s), arm64 release builds, supplied layered-icon compilation and packaging. Both bundles passed `codesign --verify --deep --strict`. Intel release cross-build passed and both executable architectures were checked as x86_64. Local host is macOS27/Swift6.4. Intel runtime and platform signing remain Not Verified.

Native [CI38146856209](https://github.com/Helicoid-Systems/macos/actions/runs/38146856209) at `dab66917ce71714fa9484b3d2c1efb9ba19c087f` **Failed**14 issues: TLS helpers start, but positive requests and exact body-rejection cases receive cancellation; a separate SSH command-runner timing assertion also fails. The native trust cause remains unproven until the next run supplies exact `decision`, `step`, `osStatus`, `cfDomain` and `cfCode`. This candidate does not pass the native gate yet. Earlier failed runs:38143728598 (`8efc0fd`, dated LibreSSL fixture),38144537088 (`7ef997b`, READY timeout),38145963036 (`17caa1e`, READY timeout). Intel source compilation passed those runs; it is not runtime evidence.

The next fixture-only candidate removes ambient request/self-sign extension configuration and checks DER extension OID uniqueness, positive CA/keyCertSign and the retained invalid-CA shape. Both local OpenSSL3.6.4 and LibreSSL3.3.6 generate one copy of each intended extension. The original local DER also had no duplicates, so native root cause remains unproven. Coordinator verification used a frozen `c098c02` snapshot plus only the two fixture files, excluding the concurrent SSH task: **177 tests in 27 suites passed** (21.458s). Production transport/build code is unchanged by this fixture package. Fresh Mac15 CI remains required.

Trust adoption, production authentication, capture/input, public routing, installed hosting/recovery and Developer ID/notarization remain incomplete. The records below are historical evidence and do not state the current test count.

Date: 2026-10-10 (post-review fixes)
Owner path: `apps/macos/**` only
Product: Helicoid / Helicoid Systems
Apps: Helicoid Manager, Helicoid Computer
Toolchain: Xcode 27.0 (27A266a), Apple Swift 6.4

## Coordinator review defects — status

| # | Defect | Fix |
| --- | --- | --- |
| 1 | `127.attacker.example` allowed | Strict dotted-quad parse only; hostnames refused. `localhost` rewritten to `127.0.0.1` before transport. All redirects refused (including other loopback ports). Base URLs refuse query/path/credentials/fragments. |
| 2 | Login/inventory used stale `configuration.baseURL` | Client binds exact canonical address after connect (`boundBaseURL`). Sign-in clears bearer before attempt and on every failure. Login validates token/account/active/expiry/manager. Inventory validates IDs and max 100. |
| 3 | `maxResponseBytes` checked after full download | Transport streams and caps before return (`HTTPTransport.bytes(for:maxBytes:)`). Whole-operation timeout via task group. Finite positive config bounds enforced. |
| 4 | Fake `verificationFingerprint` | Removed. Development transport is explicit (`ServerIdentity.developmentTransport`, empty fingerprint, `isDevelopmentTransport`). `verifiedIdentity` stays nil in dev. Health requires `schema_version == 1` and `accepting_authorized_operations`; unbootstrapped → failure/needs-setup, not verified ready. |
| 5 | UI manager identity ineffective; stale inventory | Sign-in passes current manager identity; failed sign-in and auth-failed reload clear inventory and remote windows. |
| 6 | Setup Continue never advanced (no observation) | `GuidedServerSetupModel` and `OverviewModel` are `@Observable`. Continue disabled with visible reason when step incomplete. Radio route selection. Duplicate custom View menu removed (system View menu only). |
| 7 | actool `--app-icon` with `.icon` suffix; stale Assets.car | Script strips `.icon`, uses unique staging dir, **fails package** if Assets.car or .icns missing. `.gitignore` added. Copyright is company name only. Ad-hoc codesign after packaging. |

## Fresh commands and results

```
HELICOID_BUILD_DIR=/tmp/helicoid-macos-build2 ./scripts/build.sh
xcrun swift build -c release --arch x86_64 --scratch-path /tmp/helicoid-macos-build-x64
```

| Step | Result |
| --- | --- |
| `xcrun swift test` | **73 tests, 14 suites, all passed** |
| `xcrun swift build -c release` | Build complete |
| Package apps | Both `.app` with fresh `Assets.car` + `AppIcon.icns` |
| actool Manager | Assets.car 2,904,232 B + HS Manager App icon.icns 90,955 B |
| actool Computer | Assets.car 2,208,904 B + HS App icon.icns 58,804 B |
| Intel `--arch x86_64` | **exit 0** (toolchain deprecation warning only) |
| Ad-hoc codesign | Both bundles signed (`codesign -s -`) |

### Regression tests added for review boundaries

- Malicious `127.attacker.example`, octal/short IPv4, localhost rewrite, redirect (all ports) refused
- Login payload: empty token, inactive account, past expiry, manager mismatch/pending
- Inventory: empty/oversized/duplicate IDs, page cap 100
- Byte-cap transport, config bounds
- Setup phase advance + host-identity gate
- Development identity has empty fingerprint / `isDevelopmentTransport`

## Honest boundaries (do not treat as passed)

| Boundary | Status |
| --- | --- |
| Live `hs-server` loopback E2E | **NOT VERIFIED** this turn |
| Native CUA navigation of new setup UI after @Observable fix | **NOT RE-DRIVEN** (code + unit regression only) |
| Full icon appearance matrix (Finder/Dock/About, both arch, older OS) | **NOT VERIFIED** (compile + package **VERIFIED**) |
| Production trusted server identity | Not implemented (production Connect disabled) |
| VoiceOver / Dynamic Type | **NOT VERIFIED** |
| Universal fat binary | Not produced (x86_64 and arm64 built separately) |
| Notarization / Developer ID | Not performed (ad-hoc only) |

## File map (ownership scope)

```
apps/macos/Sources/HelicoidCore/HTTP/LoopbackAddressPolicy.swift   (strict literals, localhost rewrite, no redirects)
apps/macos/Sources/HelicoidCore/HTTP/LoopbackDevelopmentClient.swift (bound base, streaming cap, no fake trust)
apps/macos/Sources/HelicoidCore/HTTP/ServerDTOs.swift
apps/macos/Sources/HelicoidCore/Monitoring/OverviewModel.swift      (@Observable)
apps/macos/Sources/HelicoidCore/Setup/GuidedServerSetupModel.swift  (@Observable)
apps/macos/Sources/HelicoidManager/ManagerSession.swift
apps/macos/Sources/HelicoidManager/Views/**                         (connect disabled when closed; setup reasons)
apps/macos/Tests/HelicoidCoreTests/**                               (73 tests)
apps/macos/scripts/build.sh                                         (icon name strip, fail-hard packaging)
apps/macos/.github/workflows/macos.yml
apps/macos/.gitignore
```

No git operations. No global installs. Brand artwork sources unchanged (four-file manager icon preserved).

## Coordinator integration verification

Final packaged source passes 77 tests in 15 suites. Both release apps package with compiled layered icons and ad-hoc signatures. Live loopback integration with the actual server and both native client libraries passes 21 checks (19 HTTP operations and two client probes). This is development transport proof, not production authentication or remote viewing.

Native Manager navigation was driven through Choose Hosting into SSH details; missing SSH address disables Continue. Production Connect remains disabled. Removed the simulated SSH identity verifier: entering a fingerprint no longer creates a verified host. Actual host-key verification remains unavailable. Required login expiry, capabilities, account revision, MFA state and health readiness now fail closed when malformed.

Final packaged Manager CUA check: production Connect disabled; Guided Setup advances into SSH address entry; after entering example.invalid, Host Identity explains real verification is unavailable and Continue remains disabled. No SSH connection or deployment occurred.

## Coordinator archive correction

Direct archive inspection found that earlier CI bundles did not contain complete app signatures and icon compilation failures were tolerated. Those artifacts are superseded. The corrected packager requires an approved icon: it compiles the layered source when supported or verifies the checked-in .icns fallback against provenance. Fallbacks were generated from the exact approved role artwork using Xcode 27.0 actool with a 15.0 minimum target. Both packaging paths now ad-hoc sign the complete app and run `codesign --verify --deep --strict`.

Fresh clean temporary builds passed the forced fallback path and the layered compilation path. Final CI archive inspection must verify signatures, executable modes, minimum OS and both role icons after download. This does not claim Developer ID, notarization or the full installed appearance matrix.

Coordinator corrected the menu status-window action to SwiftUI openWindow(id: "status") after source review. The updated apps build/package and verify their full signatures. Native endpoint launch inspection hit a Computer Use timeout; this change is compile/package verified, with endpoint window reopen still unverified at runtime.

## Guided SSH and Manager identity integration, 2026-10-10

This section supersedes the earlier unavailable-SSH observations. The new wizard
uses `/usr/bin/ssh` with strict existing host trust and a fixed read-only Python
preflight supplied through stdin. Checks cannot be manually marked passed.
Address/authentication changes invalidate prior host results. Unknown/changed
keys, malformed or missing facts, occupied product ports and failed commands
deny continuation. Stdin and combined stdout/stderr have size bounds; process
timeouts and cancellation terminate the local child.

Fresh verification:

- `HELICOID_SSH_TEST_ADDRESS=ubuntu@57.131.161.27 swift test`: **90 tests passed**,
  including actual trusted SSH to Ubuntu 26.04 x86-64, product ports free and
  existing web listeners retained. This preceded the identity additions.
- `swift test` after Keychain integration: **95 tests passed**; the explicitly
  gated live-host test is disabled without its environment variable.
- Regression red then green: OpenSSH CRLF fingerprint output was rejected;
  newline-aware parsing accepts it while absent/ambiguous fingerprints refuse.
- Regression red then green: a descendant retaining a pipe delayed timeout to
  2 seconds; refusal now finishes under 1 second (observed 0.057 seconds).
- `HELICOID_FORCE_ICON_FALLBACK=1 ./scripts/build.sh`: release apps packaged and
  both complete ad-hoc signatures verified with approved artwork fallbacks.
- Native CUA navigation: production Connect disabled; Guided Setup → SSH address
  → verified actual public host fingerprint → all seven checks Passed → Network
  shows the target address and port 8920 → Deployment Identity shows the real
  Manager public key. Restarting the app and repeating the path showed the same
  Keychain-backed public key. Only public metadata was inspected.

Manager keys use CryptoKit Ed25519 and a nonsynchronizing Keychain item. Atomic
creation uses the persisted winner if another instance races. Invalid version,
corrupt bytes or failed persistence returns no usable identity and never rotates
trust silently. Signing size limits, real signature verification, altered-message
refusal, concurrency and corruption are covered by the identity tests.

Installation, signed package apply, MFA bootstrap, public TLS, live relayed pixels
and remote input remain **NOT VERIFIED / pending implementation** in this slice.
No remote installation, service, firewall or server data change occurred. Intel
runtime, notarization and the full appearance/accessibility matrix are unchanged
release gates.

## Minimal native setup dialog, 2026-10-10

Setup opens at the SSH address, with no introductory screen, phase counter,
large heading or repeated description. The native title reads
`Server Setup · Helicoid Manager`; there is no custom navigation bar or
separator. Verification and compatibility share one screen, with details
available on demand. Network options, Manager identity and optional backup
location use disclosures. Linux storage defaults to `/var/lib/helicoid`.
Cancel restores the original window title and size.

- `HELICOID_FORCE_ICON_FALLBACK=1 ./scripts/build.sh`: exit 0; **95 tests in
  18 suites passed**, release apps packaged and complete signatures verified.
- Native CUA on the final packaged build: empty SSH and deployment/admin fields
  disable the primary button; actual trusted SSH preflight succeeds; the
  disclosure shows the verified fingerprint and all seven passed checks.
  Continue goes directly to Network; Back traverses the combined check screen
  to Connect. Deployment, administrator, storage and review screens have no
  repeated introductory heading. The storage default and collapsed backup
  option display correctly. Escape returns to the original Manager window.
- Source diff whitespace check passed. Full VoiceOver, light appearance, and the
  complete window-size matrix remain unverified. Installation remains pending.

Layout references reviewed online: [Little Snitch setup](https://help.obdev.at/littlesnitch6/intro-install)
and [Tailscale macOS permission flow](https://tailscale.com/docs/concepts/macos-sysext).
Borrowed focused native dialogs and a clear primary action; no assets copied.

## MiMo-V2.6-Pro continuation: local Mac preflight

Coordinator run on 10 October 2026. Sanitized session export `ses_ffe5ed8b01754ffejl2HRxPgba` contains only provider `xiaomi` / model `mimo-v2.6-pro` for this work package. Prior setup/About/window changes and supplied artwork were preserved and tested with the package.

`HELICOID_BUILD_DIR=<isolated scratch> HELICOID_DIST_DIR=<checkpoint> bash scripts/build.sh` exited 0: 122 tests in 19 suites, both release builds, original layered-icon compilation, both app bundles, and `codesign --verify --deep --strict` with ad-hoc signatures. Actual packaged Manager UI: production Connect disabled; Guided Server Setup offers This Mac and Existing Linux Server; Check This Mac refuses incomplete unprivileged listener visibility. Disk-space failure was also observed and cleared only after deleting stale generated build cache. No host resource was installed.

Parser/loaded-service/symlink/cancellation cases use fixtures; the live read-only probe and native wizard were exercised on Apple Silicon/macOS 27.0.1. Elevated complete-listener inspection, Service Management registration, all endpoint permissions/capture/input, public connections, Intel runtime and Developer ID/notarization are Not Verified. This is a development prerequisite checkpoint, not a passed media or deployment gate.

## Native CI repair (commit `6fd17e5`, run `38082769211`)

Failed CI proof: native macOS job failed the Local Mac hosting preflight suite (3 issues). Root causes observed in `macos-ci-failure.log`:

1. `resourceState uses lstat so dangling symlinks are conflicts` wrote a symlink into coordinator-specific `/tmp/hs-production-20261010/…` whose parent does not exist on CI (`symlink(...) → -1`, state `.absent` instead of `.brokenSymlink`).
2. `Live read-only preflight on this Mac is structurally valid` threw `setupBlocked("Invalid local host preflight response.")`. `validate()` applied the product-friendly-name 64-byte bound to the system hostname, which is informational display text and can legitimately exceed that bound on CI hosts.

Repaired proof (this working tree, not yet a new CI run):

- Symlink/absent fixtures now use a unique directory under `FileManager.default.temporaryDirectory` and clean up only that directory.
- Hostname is validated at `HOST_NAME_MAX` (255 bytes) and is not treated as an identity; `displayComputerName` truncates to 64 UTF-8 bytes for UI only. Empty name and 256-byte name still refuse. Deterministic regression `Long legitimate hostnames validate; display truncation is not identity` reproduces a 227-byte legitimate name.
- Live probe still runs full `validate()` on real OS/hostname/port facts (no bypass, no swallowed failure) and still refuses to claim complete listeners without elevation.

Commands after the fix: `xcrun swift test` → **123 tests / 19 suites passed**; debug and release builds of `HelicoidManager` and `HelicoidComputer` succeeded; `xcrun swift build -c release --arch x86_64` succeeded (x86_64 deprecation warning only). A fresh native CI run is still required to close the failed job; this is local repaired proof.

## Native v2 auth candidate — coordinator review fixes (15 October 2026)

Owner path: `apps/macos/**` only. No commit/push. Model: MiMo-V2.6-Pro (Xiaomi Token Plan Europe).

### Acceptance findings addressed

| # | Finding | Fix |
| --- | --- | --- |
| 1 | `public_identity` compared as key | Completion-only top-level `manager_public_key` binds signer/challenge key; `public_identity` display-only (`key:<hex>`) |
| 2 | MFA metadata unchecked | `validateMFAConsistency` requires the block and required/available to match the completed factor |
| 3 | Int expiry overflow / Unicode digits | `remainingSeconds` uses `subtractingReportingOverflow`; TOTP accepts ASCII 0-9 only |
| 4 | connect ignored address / empty fingerprint | Refuse non-origin addresses; probe pinned `GET /health`; identity from configured CA pin |
| 5 | Stale cleanup / task slot / inventory races | `AuthSignInCoordinator` owns generations; stale branches cannot clear/cancel/install; inventory fenced |
| 6 | Injection seam only | Documented in README: production v2 requires injected trusted configuration; default remains closed |

### Commands (fresh this turn)

```
xcrun swift test
# → 208 tests, 29 suites, all passed (19.688s)

HELICOID_FORCE_ICON_FALLBACK=1 \
  HELICOID_BUILD_DIR=/tmp/hs-finish-20261013/build-macos-auth \
  HELICOID_DIST_DIR=/tmp/hs-finish-20261013/dist-macos-auth \
  ./scripts/build.sh
# → tests 208/29, release build complete, both apps packaged, ad-hoc signed
```

Deployment minimum remains macOS 15; Swift tools 6.2 / local Xcode Swift 6.4.
No mock pixels. Media/control flags remain closed.

### Remaining gates (not verified)

- Actual built Rust server E2E login (coordinator)
- Normal app wiring that loads persisted deployment trust (injection seam only)
- Intel runtime, Developer ID/notarization, production trust adoption UI

### Independent client regression fix (15 October 2026, follow-up)

Coordinator snapshot test `coordinatorStaleCompletionPreservesReplacement` failed
on the previous candidate: `completeChallenge` mismatch and post-await branches
called `clearPendingChallenge()` and erased a replacement challenge. Root cause
fixed in `NativeV2AuthClient`: obsolete completions never clear pending; cleanup
is `clearPending(ifChallengeID:)`; `beginChallenge` refuses cancelled entry and
does not mutate after a stale await. Optional completion now requires
`!mfa.required && !mfa.available`.

Added regressions through the actual client public API:
`coordinatorStaleCompletionPreservesReplacement` (coordinator snapshot, unchanged),
`lateResponseAfterReplacementPreservesPending`,
`cancelledBeginDoesNotClearReplacement`,
`optionalAvailableFactorContradiction`.

```
xcrun swift test --filter coordinatorStaleCompletionPreservesReplacement
# 1 test passed

xcrun swift test
# 212 tests, 29 suites, all passed (46.659s)

HELICOID_FORCE_ICON_FALLBACK=1 ./scripts/build.sh
# tests + release + both apps packaged/signed
```

### Session expiry reception clock (15 October 2026, interop)

Real Rust HTTPS login issued a bounded 7200s v2 session; the client captured
`now` before the complete HTTP await and rejected a legitimate response as
oversized (`remaining > 7200`). `completeChallenge` now validates with a
**reception** timestamp taken after the await. Strict bounds are unchanged:
reception-relative remaining lifetime > 7200s, expired sessions, overflow
values, binding checks and generation fences still deny. No TTL padding and no
fixture expiry mutation.

Causal regressions (actual client + delayed test responder):
- `slowCompletionAcceptsFresh7200` — delay 1.2s, issue `expires = issue+7200` → accepted
- `oversizedAndExpiredStillDenied` — `issue+7201` and past expiry → denied

```
xcrun swift test
# 214 tests, 29 suites, all passed (19.426s)

HELICOID_FORCE_ICON_FALLBACK=1 ./scripts/build.sh
# tests + release + both apps packaged/signed
```

### Session expiry / invalidation (15 October 2026)

Live bearer uses a conservative monotonic deadline from reception-relative
remaining lifetime (max 7200s, no padding). Expired bearers are never returned
or sent; local clear needs no network. Authorized 401 for the exact
token/generation is credential loss (`sessionExpired`); 403 is operation-only
and keeps the session. Coordinator clears inventory and returns to sign-in on
expiry; stale expiry/401 cannot clear a replacement.

`xcrun swift test` → **224 tests / 30 suites passed**. Packaged build with
`HELICOID_FORCE_ICON_FALLBACK=1` succeeded. Report:
`/tmp/hs-finish-20261013/macos-session-expiry-report.md`.
