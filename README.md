# Helicoid macOS apps

The native v2 sign-in and session-expiry candidate passes **231 coordinator
tests** and both release app builds on Apple Silicon. Automatic expiry updates
the actual Manager screen and clears inventory/windows; cancellation, replacement
and client lifetime regressions pass. The staged bundles pass strict ad-hoc
signature verification. [Native CI38927581414](https://github.com/Helicoid-Systems/macos/actions/runs/38927581414)
passes at `d657e9762246f3a2b7814cecadd79ef61dacda95`, including Intel source
compatibility. The actual Rust HTTPS interop suite passes7 Swift and6 C# checks.
The downloaded [Apple Silicon development apps](https://github.com/Helicoid-Systems/macos/actions/runs/38927581414/artifacts/12056404592)
match the published archive digest and both strict ad-hoc signatures. Independently enrolled trust is still required; normal
operation stays unavailable when no trusted configuration is supplied. Live
capture/control and the worker/admission checkpoint remain incomplete. Earlier
14 October billing and failed-candidate records are historical.

Native SwiftUI apps for Helicoid Systems computer monitoring. The retained
Computer status app targets macOS 13 and newer; the legacy Manager remains at
macOS 15 while the shared Qt Manager replacement is built.

| App | Role |
| --- | --- |
| **Helicoid Manager** | Operator console: connect, Computers inventory, inclusion/filter/selection, view-only remote window |
| **Helicoid Computer** | Native menu with connection/screen-access status, Open Status Window, Settings and Quit. The status window shows connection, screen-access identity, and real permission details. Help stays hidden in normal builds until a real transport exists. |

This tree builds without sibling path dependencies. The server HTTP contract is
vendored under `Resources/Contracts/`. Brand assets are bundled copies under
`Resources/` and each app target.

## Requirements

- Helicoid Computer: macOS 13 or newer
- Legacy Helicoid Manager: macOS 15 or newer
- Xcode 27 / Swift 6.4 toolchain (`xcrun swift`)
- Intel and Apple Silicon source compatibility

## Build, test, package

```bash
./scripts/build.sh
```

Optional environment:

- `HELICOID_BUILD_DIR` — scratch build directory (default `apps/macos/.build`)
- `HELICOID_DIST_DIR` — packaged `.app` output (default `apps/macos/dist`)

The script runs the existing Swift tests and macOS 15 package build, builds
Helicoid Computer from `Sources/Package.swift` with a macOS 13 deployment
target, packages both apps, and compiles bundled `.icon` sources with `actool`
into `Assets.car` / `.icns`. The macOS 13 package excludes the three legacy
Manager-only core files that use newer Observation APIs.

## Launch modes

Default launches show truthful empty/unconfigured state. No ordinary fake inventory.

### Source fixtures

```bash
open "dist/Helicoid Manager.app" --args --development-fixtures
```

Labeled fixtures exercise selection, filter, inclusion, and view-only UI only.

### Loopback development server

```bash
open "dist/Helicoid Manager.app" --args --development-server
open "dist/Helicoid Manager.app" --args \
  --development-server \
  --development-server-address http://127.0.0.1:8787 \
  --manager-public-identity lab-mac-1
```

Enabled only with `--development-server`. The client accepts loopback only
(`127.0.0.1`, `[::1]`, or `localhost` that resolves to loopback). It never
claims a verified production server identity. Tokens are memory-only.

Production mode stays closed until persisted deployment trust adoption and authentication are integrated. The pinned HTTPS transport below is independently tested and does not enable production Connect.

Fixture mode and development-server mode are independent and must not be conflated.

## Architecture

- `Sources/HelicoidCore` — models, monitoring state, connection boundary, loopback development client, DTOs
- `Sources/HelicoidManager` — SwiftUI manager app
- `Sources/HelicoidComputer` — SwiftUI menu-bar status app with permission readiness
- `Tests/HelicoidCoreTests` — pure Swift and HTTP parsing/denial tests
- `Tests/HelicoidComputerTests` — permission lifecycle/policy tests via injected probe seam

### Connection boundary

- `UnavailableConnectionClient` — default production path (closed)
- `LoopbackDevelopmentClient` — bounded development HTTP client for contract v1

### Monitoring state (kept distinct)

1. Monitoring inclusion (All or explicit IDs)
2. Displayed IDs (inclusion + search/status filter)
3. Temporary tile selection
4. Action snapshots (frozen at composer open)
5. Admitted observation streams

### Guided server setup

Mac manager offers **This Mac** read-only preflight and **Existing Linux Server** via verified SSH. Install never claims success without integrated server packages.

Setup opens directly to the SSH address in a compact custom native dialog.
Its title is **Server Setup · Helicoid Manager**, with no navigation bar,
step counter, large heading or introductory paragraph. Verification and host
checks share one screen; details, advanced network settings and optional
backups expand on demand. Cancel/Back/Continue stay along the bottom, and
exiting setup restores the original window title and size.

The native wizard uses the system OpenSSH client with strict host-key checking,
key authentication and bounded read-only preflight. Unknown or changed keys stop
setup. It checks Ubuntu 26.04 on x86-64, systemd, noninteractive sudo, storage,
the dedicated Helicoid ports and an existing installation. Existing listeners on
80/443 are informational and are preserved. Cancellation ends the local SSH child;
it does not claim to roll back remote operations.

The This Mac route uses bounded read-only local inspection (OS/architecture,
privileges, disk, product path, launchd service, ports). The system hostname is
informational display text (shown truncated in the UI) and is not a product
identity; legitimate long hostnames validate. Without elevation, listener
inspection is explicitly incomplete and Product ports cannot pass. Installation
stays unavailable in this build.

Opening setup creates or loads the initiating Manager's Ed25519 identity through
macOS Keychain. Only its public key is shown. Corrupt or inaccessible stored
identities are refused rather than silently replaced. Package apply and MFA
bootstrap are still pending integration; this build cannot reach Ready.

An optional read-only host regression is enabled explicitly:

```bash
HELICOID_SSH_TEST_ADDRESS=user@host swift test --filter SSHLiveSetupTests
```

The host regression targets the approved Ubuntu 26.04 development host with
occupied web ports; it requires an already trusted SSH key and performs no install.

### Remote view

View-only remote window shows honest **Engine Unavailable**. Take Control is
disabled.

## Brand assets

Independent copies (build does not read a sibling checkout):

- Manager: `HS Manager App icon.icon` four-file layered composition preserved exactly
- Computer: original `HS App icon.icon`

## Related documents

- `BUILD-REPORT.md` — build evidence, verification boundaries, technical IDs
- `Resources/Contracts/http-v1.md` — vendored server HTTP contract (version 1)

## Local hosting prerequisite (10 October 2026)

Guided setup offers **This Mac** and **Existing Linux Server**. This Mac performs bounded, read-only OS/architecture, privilege, disk, product-path, launchd-service and listener checks. Unknown facts block progress. Unprivileged listener inspection is explicitly incomplete; this checkpoint does not install or register a launchd service or claim Server Ready for Enrollment. Windows local hosting is offered by the Windows app.

Fresh coordinator verification: 122 Swift tests in 19 suites, both release app bundles, the supplied layered icons, and deep strict ad-hoc signature checks passed. The packaged Manager was exercised through This Mac → Check This Mac and refused incomplete listener inspection. Intel runtime, privileged installation, live preview/control and production signing remain Not Verified.


## Native v2 device-key sign-in (13–15 October 2026)

`NativeV2AuthClient` implements the frozen two-step challenge login over
independently pinned HTTPS: `POST /v2/auth/challenge` then
`POST /v2/auth/challenge/complete`. It reuses `ManagerSigningIdentity`
(CryptoKit Ed25519 + Keychain) and `PinnedHTTPSTransport` unchanged.

- Canonical signature message: `hs-auth-v2|deployment:<id>|challenge:<id>|operation:session|manager:<key_hex>`
- `mfa_required` missing → required; `false` → optional (omit TOTP). Required
  code UI is cancellable; optional non-enrolled login does not ask for TOTP.
  Optional completion must report `!required` and `!available` (an available
  factor always requires TOTP).
- Completion binds top-level `manager_public_key` to the actual signer/challenge
  key. `manager.public_identity` is display-only (bootstrap uses `key:<hex>`).
- MFA metadata must match the completed factor; weaker/malformed blocks fail closed.
- Challenge expiry ≤ 120s and session expiry ≤ 2h use checked arithmetic.
- Codes accept ASCII `0-9` only. Secrets stay in process memory.
- Development loopback remains an explicit separate legacy option; the v2 client
  never falls back to v1/password-only/dev labels.

**Injection seam only:** normal `HelicoidManager` construction does not yet load
persisted deployment trust. Production v2 sign-in is available only when a
`NativeV2AuthClient` is injected into `ManagerSession` with a genuine
`DeploymentTLSIdentity` + `PinnedHTTPSTransport`. Without that configuration,
production Connect stays explicitly unavailable. Actual-server integration
against the built Rust server remains a coordinator gate.

`AuthSignInCoordinator` owns causal generation fencing for sign-in, required
code, inventory, and sign-out so stale completions cannot clear a newer
challenge or re-install inventory after sign-out.

## Computer permission readiness (P01, 17 October 2026)

[CI39063635258](https://github.com/Helicoid-Systems/macos/actions/runs/39063635258)
passes239 tests, both release packages and Intel cross-build. The downloaded
[Apple Silicon development apps](https://github.com/Helicoid-Systems/macos/actions/runs/39063635258/artifacts/12112082811)
are archive-hash, architecture and ad-hoc signature verified. Installed
permission behavior and full worker/capture/input acceptance remain Not Verified.

Helicoid Computer reports **current-process** Screen Recording and
Accessibility permission status using installed SDK APIs only
(`CGPreflightScreenCaptureAccess`, `AXIsProcessTrusted`). No shell, TCC
database inspection, private APIs, or capture/input.

- Query without prompting on startup, when permission status is presented,
  and on app reactivation.
- `unknown` is treated as unavailable; a fresh query replaces stale granted
  after revoke.
- Permission readiness stays separate from connection, admission, and actual
  screen access. Grants alone never mark connected/observed/controlled or
  enable capture/media/input.
- A single **Allow** action may prompt once per permission kind. After an
  explicit unsuccessful request the row offers **Open Settings** for the exact
  System Settings privacy pane and never prompts again. Status stays
  unavailable until a fresh native query confirms; a grant is never inferred
  from requesting.
- Development fixtures use a clearly labeled synthetic probe and never supply
  live permission facts.

Lifecycle/policy tests inject a scripted probe seam. An actual read-only
native preflight is separate labeled evidence, not fixture runtime proof.

Full ScreenCaptureKit worker, authenticated supervisor, disclosure, and input
remain unfinished and do not claim checkpoint1.

## Endpoint invitation redemption

Helicoid Computer Settings includes a user-driven Server Enrollment form. It
accepts the HTTPS origin plus the deployment ID, invitation ID, and one-time
code shown by an enrollment Manager. It creates an Ed25519 endpoint identity,
keeps the signing key in the macOS Keychain, signs the server contract's
deployment/invitation/code-hash-bound proof, and clears the code after the
server confirms enrollment. The code is never persisted by this client.

A successful response is shown as **Waiting for administrator approval** with
the returned computer ID. This API call does not establish a persistent server
connection or enable capture, observation, input, or media. The receiver checks
`/health` and stops before endpoint authentication unless the deployment
advertises `features.file_jobs=true`. The current server source advertises
`true` and mounts the authenticated v2 delivery routes; installed delivery
remains unbuilt and unverified. The source path verifies
chunk hashes and the whole-file size and digest, then atomically saves without
overwriting into `~/Library/Application Support/Helicoid/Computer/Received Files`.
The server origin is retained with the Keychain identity. The origin must
present a certificate trusted by macOS; for a private CA, install the approved
CA before enrollment. D29's verified local-user binding and same-user commit
check now use the signed-in console user's stable macOS UID. The server binds
new targets to that identity, and the client rechecks it during transfer and
before publishing into that user's private folder. When the process no longer
matches an eligible console user, it replaces the prior endpoint session with
an unbound session when the Keychain is available; that session cannot access
file jobs. Endpoint sessions sign the OS account display label along with the
stable UID; the Manager uses a fresh session preflight to show the account and
computer in the confirmation, and creation is bound to that exact session ID.

The Computer Settings window now lets the signed-in user refresh requests for
this enrolled computer, review each request's instructions and limits, and
choose files through the native file importer. Selected files are opened
without following a final symbolic link, size-checked and hashed in bounded
chunks, then uploaded only after explicit user selection. The client checks the
signed local UID before each chunk, resumes a matching partial submission, and
requires an explicit confirmation naming the prior submission ID before
replacement. The server verifies the complete manifest and SHA-256 before
marking a submission Received. These request APIs use authenticated v2 routes
independently of the `file_jobs` delivery feature. The server now advertises
`file_jobs=true` and mounts the recipient-bound delivery routes; this source
path is not an accepted workflow until platform builds and runtime evidence
confirm it. The Swift package builds, but
request interaction, real-server transfer, and installed-device acceptance
remain unverified. Screen viewing and control are not enabled.

## Pinned HTTPS prerequisite (11 October 2026)

`DeploymentTLSIdentity` accepts an independently supplied deployment CA and SHA-256 pin. `PinnedHTTPSTransport` uses native Security hostname, chain, validity and server-authentication checks with that sole anchor, TLS1.2 minimum, no redirects or online CA fetch, and bounded streaming/cancellation. Invalid trust, body bounds and operation deadlines fail closed. Deployment trust adoption and production sign-in remain unavailable.

The coordinator passed **186 Swift tests in 27 suites**, including genuine TLS sockets and actual local command cleanup. The POSIX runner owns one child and one reaper; timeout, cancellation, input failure and output overflow confirm child cleanup before returning. Successful output is retained through EOF, and inherited writers remain subject to the original deadline. Certificate generation runs on one dedicated test worker; awaiting test tasks suspend instead of blocking on generation locks. Real certificates, strict trust rules, concurrent tests and the original one-second SSH assertions remain intact.

Native [CI 38167550626](https://github.com/Helicoid-Systems/macos/actions/runs/38167550626) passes at `7bf00ac9ce6b03f47f66539a913136451abe55fd`: all 186 tests pass in both Test and Package apps, release packaging and Intel cross-build pass. The coordinator verified both downloaded ZIP archives and strict ad-hoc bundle signatures from the [Apple Silicon development apps](https://github.com/Helicoid-Systems/macos/actions/runs/38167550626/artifacts/11711859570), including arm64 architecture and minimum macOS 15.0. Developer ID/notarization, Intel runtime, production trust adoption, installed worker capture/input and preview/control remain **Not Verified**.

## Native UI checkpoint — 20 October 2026

The current source adds compact permission/status windows, four overview density presets, session-owned Grid/List preferences, native mixed inclusion checkboxes, and independent generation-scoped view-only windows. Connection, sign-in, setup and About use compact native composition. Unsupported tools remain hidden, installation stops before administrator collection, and normal connection still requires the missing verified-profile adoption flow.

Coordinator verification passed 233 Core, 18 Manager and 14 Computer tests, release packaging with the verified supplied-artwork fallback, and strict ad-hoc bundle signature checks. Both apps also cross-compile for x86_64 with a macOS 15 minimum. Packaged normal Connect/setup/About and permission accessibility were inspected; full visual/keyboard/accessibility acceptance, permission prompting/revocation, populated inventory, Intel runtime, real media/input, installation and production signing remain Not Verified.
