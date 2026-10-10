# BUILD-REPORT — Helicoid macOS (apps/macos)

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
