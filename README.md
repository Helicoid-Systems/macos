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
- `HELICOID_HS_SERVER_PATH` — optional absolute path to a locally built
  development `hs-server` helper (see below)

The script runs the existing Swift tests and macOS 15 package build, builds
Helicoid Computer from `Sources/Package.swift` with a macOS 13 deployment
target, packages both apps, and compiles bundled `.icon` sources with `actool`
into `Assets.car` / `.icns`. The macOS 13 package excludes the three legacy
Manager-only core files that use newer Observation APIs.

### Optional development hs-server helper

The default build packages no server helper. To include a locally built one:

```bash
HELICOID_HS_SERVER_PATH=/absolute/path/to/hs-server ./scripts/build.sh
```

The requested path must be an existing, absolute, regular, executable Mach-O
executable. It must contain the Manager's architecture and every slice must
target macOS 15 or older. Missing, malformed, wrong-architecture, or too-new
inputs fail the build instead of being omitted. The source file is only read,
never modified.

The validated copy is ad-hoc signed and placed at
`Contents/Helpers/hs-server`; a digest and validation record tied to the included
bytes is placed at `Contents/Resources/hs-server-development.json`. Packaging
refuses to replace an existing helper or evidence file, and also refuses a
pre-existing `hs-server-release.json` or `ServerPackage` directory so a stale
release payload cannot survive a rebuild: use a fresh `HELICOID_DIST_DIR` (or
remove the output app yourself) when switching or repeating builds. The build
never deletes pre-existing helper artifacts.

This is development packaging only: the helper is not installed or launched, and
it does not enable local hosting, launchd, TLS trust, deployment identity, service
management, production authentication, or a release security floor. The recorded
digest is not a distribution signature.

Packaging tests use disposable scratch app bundles and fixture Mach-O files:

```bash
./scripts/tests/hs-server-helper-tests.sh
```

### Signed local server install path (gated)

The This Mac release installer path is implemented end-to-end but remains
disabled unless the Manager bundle contains an actual release payload. The
development-only helper flow packaged without a package is never used for
installation. The separately labeled pinned development bundle below is the
only non-release install path, and it never creates release evidence or trust
roots.

Required bundle payload:

- `Contents/Helpers/hs-server` — release-signed helper, executable.
- `Contents/Resources/hs-server-release.json` — release evidence with
  `schema: 1`, `helper: "hs-server"`, `path: "Contents/Helpers/hs-server"`,
  `developmentOnly: false`, `distributionSigned: true`,
  `installationEnabled: true`, `serviceEnabled: true`, a non-ad-hoc
  `signature`, `includedSHA256`, and the contained `architectures`.
- `Contents/Resources/ServerPackage/trust-roots.json` —
  `{"schema": 1, "releaseKeys": ["<64-hex Ed25519 public key>"]}`. This is the
  Manager's independent release root, not a key supplied by the package.
- `Contents/Resources/ServerPackage/package/` — `manifest.json`,
  `manifest.sig`, and `artifacts/hs-server` exactly, matching the server's
  `installer-package-targets-v1` contract. The manifest must be signed by a
  packaged trust root, use product `hs-server`, target `macos-arm64` or
  `macos-x86_64` for this Mac, and contain exactly one
  `artifacts/hs-server` artifact.

Before any privileged call, the Manager verifies the release evidence, helper
digest, trust root, exact package shape, Ed25519 manifest signature, platform,
artifact size, and artifact SHA-256. It then asks the helper for
`installer capabilities-v2` and refuses unless the helper advertises
`macos_launchd`, `loopback_development`, and `install`. The current gated
server source advertises only preflight and plan because no independently
trusted release root is configured, so the Manager refuses honestly even if a
hand-built payload is present. Passing the Manager's checks is not installation
authority: the helper independently re-verifies the package against its own
compiled trusted release root before any host effect.

The install flow is capabilities → privileged `preflight-v2` → privileged
`plan-v2` → privileged `apply-v2`, followed by `status-v2`. Every privileged
command is handed to `/usr/bin/osascript` with `do shell script … with
administrator privileges`; the request is bounded JSON on stdin and the helper
is addressed by its absolute bundle path. macOS may ask for administrator
authorization. A dismissed prompt is reported as a cancellation, not a
success. A timeout or lost helper response after apply may have started is
reported as an unknown outcome; the Manager never retries automatically and
offers `status-v2` plus `cancel-v2` for an incomplete operation.

Operator prerequisites, supplied outside the Manager:

- `/etc/helicoid/tls/fullchain.pem` and `/etc/helicoid/tls/private-key.pem`
  must already exist, be root-owned private (`0700`-class directory,
  `0600`-class regular files), and cover literal `127.0.0.1`.
- The helper creates the fixed `_helicoid` service account/group, product
  paths, executable, configuration, copied TLS material, install receipt, and
  launchd daemon at the paths frozen by `installer-lifecycle-v2`.

Installed is not the same as ready. The macOS helper's status never infers
bootstrap or enrollment readiness from launchd or file presence. Setup reaches
**Server Ready for Enrollment** only when the helper explicitly reports both
`service_installed: true` and `server_ready_for_enrollment: true`.

Unit coverage includes strict package verification, development pin/evidence
binding, development TLS provisioning command construction, bounded osascript
request construction, capability gating, dismissed authorization, timeout and
unknown outcomes, and status/cancel binding. No test claims a successful
install from fake files or a helper that does not advertise install.

### Development-only pinned bundle (disposable machines only)

A separate development path can exercise the real privileged installer without
weakening the release gate. It requires a helper built by the server with
`--features macos-dev-install` and the same `HELICOID_MACOS_DEV_TRUST_KEY` used
to sign the package. The Manager build records that key in Info.plist at build
time; the helper embeds the same key at compile time. Neither side accepts an
arbitrary runtime key.

The server side must produce both artifacts (read the server checkout's
`scripts/package-macos-development.sh` and acceptance workflow for the exact
commands):

1. generate an Ed25519 signing key outside the package;
2. `cargo build --locked --release --features macos-dev-install` with
   `HELICOID_MACOS_DEV_TRUST_KEY` set to its public key hex;
3. ad-hoc sign the development helper for Apple silicon execution; and
4. run `scripts/package-macos-development.sh BINARY 0.1.0 macos-arm64|macos-x86_64 SIGNING_KEY OUTPUT_DIR`.

Use the printed `verification_key_hex` as `HELICOID_MACOS_DEV_TRUST_KEY` for the
Manager build. A helper built with a different key will be refused by the
helper at apply time; the Manager never substitutes a package-local key. This
Manager checkout does not build the server binary or package; those artifacts
must come from the server's development-feature build.

```bash
HELICOID_HS_SERVER_PATH=/absolute/path/to/dev-feature/hs-server \
HELICOID_HS_SERVER_DEVELOPMENT_PACKAGE_DIR=/absolute/path/to/signed-macos-package \
HELICOID_MACOS_DEV_TRUST_KEY=<64-hex key printed by package-macos-development.sh> \
./scripts/build.sh
```

`scripts/hs-server-development-bundle.sh` first runs the helper's
`installer capabilities-v2` and refuses a helper that does not advertise
`install`, `macos_launchd`, and `loopback_development`. It then:

- validates the helper through the existing development helper packager;
- copies the exact signed macOS package to
  `Contents/Resources/ServerPackage/development/package`;
- writes `Contents/Resources/hs-server-development-install.json` binding the
  helper SHA-256, manifest SHA-256, artifact path/size/SHA-256, target, version,
  and pinned key;
- writes `HelicoidServerDevelopmentInstall` and
  `HelicoidServerDevelopmentTrustKey` to Info.plist; and
- refuses any pre-existing development install payload or release payload.

The Manager recognizes this payload only when the build pin is present, the
evidence key equals that pin, the helper bytes match the evidence, and the
package verifies against the pinned Ed25519 key. Release evidence always takes
precedence; a broken or missing release payload never falls back to development.
The helper still re-verifies the package against its own compile-time pin before
any effect. The UI displays a persistent **DEVELOPMENT ONLY** warning.

At execution time the privileged wrapper stages the helper and exact package
into a fresh root-owned `0700` directory, re-computes their SHA-256 digests, and
refuses before running anything if the bytes differ from the UI-verified
payload. The helper then re-verifies the package manifest signature with the
build pin. This closes replacement between the UI check and the administrator
prompt. It is still a development build: an unsigned/ad-hoc Manager cannot
defend against an attacker who can replace the entire app and its Info.plist.
Do not represent this as a signed release or production trust.

For development installs, the Manager generates disposable self-signed TLS for
literal `127.0.0.1`, copies it into a root-owned staging directory, pins the
certificate/key SHA-256 digests in the privileged script, and installs it
root-owned `0600` under a root-owned `0700` `/etc/helicoid/tls`. Existing TLS
material is never overwritten: material without the development marker is left
untouched (exit 42) and the reviewed plan validates it. A failure removes only
files/directories created by that run, using a marker to recognize its own prior
dev material. This is not production or public PKI material. Disposable
machines only: the installer creates a system account/group, product paths, and
a LaunchDaemon, and it does not establish production readiness or enrollment.

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

Mac manager offers **This Mac** read-only preflight and **Existing Linux Server** via verified SSH. A real local install runs only from a verified signed payload; install never claims success from files, launchd, or an unavailable package.

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
stays unavailable unless the signed release payload described above is packaged.

Opening setup creates or loads the initiating Manager's Ed25519 identity through
macOS Keychain only after the signed package verifies and the helper advertises
install. Only its public key is shown. Corrupt or inaccessible stored identities
are refused rather than silently replaced. Package apply is implemented behind
those gates; MFA bootstrap remains pending, so the default build cannot reach
Ready.

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

Guided setup offers **This Mac** and **Existing Linux Server**. This Mac performs bounded, read-only OS/architecture, privilege, disk, product-path, launchd-service and listener checks. Unknown facts block progress. Unprivileged listener inspection is explicitly incomplete; the default no-payload checkpoint does not install or register a launchd service or claim Server Ready for Enrollment. Windows local hosting is offered by the Windows app.

Fresh coordinator verification: 122 Swift tests in 19 suites, both release app bundles, the supplied layered icons, and deep strict ad-hoc signature checks passed. The packaged Manager was exercised through This Mac → Check This Mac and refused incomplete listener inspection. Intel runtime, live privileged installation execution (no signed payload is present in this checkout), live preview/control and production signing remain Not Verified.


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

**Production entry:** a normal `HelicoidManager` launch presents the production
trust screen when no saved deployment trust is installed. It loads the persisted
CA/host/deployment configuration, creates the pinned HTTPS client only after the
operator completes or re-verifies that trust, and then runs the same v2 sign-in
flow. Source fixtures and the explicit loopback development server remain
separate nonproduction paths. Actual-server integration against the built Rust
server remains a coordinator gate.

**Manager authority checkpoint (source only):** `DeploymentAuthorityCheckpoint`
accepts only the server's `dep_<32 lowercase hex>` deployment ID, a canonical
64-character lowercase Ed25519 grant-signing key, and a positive generation.
`NativeV2AuthClient.fetchDeploymentAuthority` observes
`GET /v2/deployment/authority` over the pinned origin but never adopts it.
`ManagerAuthorityTrustStore` persists one atomic `ManagerAuthorityTrustRecord`
per deployment in the unlocked, non-synchronizing login Keychain. That single
record contains both the authority checkpoint and the typed, independently
supplied TLS configuration, so the two can never be read or written as a mixed
pair. Every read-check-write trust operation runs
under one owner-only cross-process `flock` file lock, so all compliant Manager
processes serialize generation checks and updates. The lock walks the trusted
ancestor chain with `openat`/`O_NOFOLLOW` from a password-database home (not
`HOME` or another process environment variable), rejects symlinked or
group/other-writable ancestors, keeps the validated leaf descriptor open, and
opens the lock file relative to that descriptor. Initial adoption and generation
advances require a separate `ManagerAuthorityConfirmation`; rollback, a
same-generation key change, malformed stored bytes, lock failures, and Keychain
failures stay closed. Cancellation immediately before the write leaves the prior
checkpoint intact.

The confirmation type takes only explicit operator-entered values and has no
initializer from an observed checkpoint. That is a policy boundary, not
mechanically proven provenance: the UI/caller must not prefill the comparison
from the reply being verified. `ManagerProductionConnection.makeVerifiedClient`
returns a production client only when an atomic config-bound record exists and
the live authority exactly matches its checkpoint. Core also compares the full
typed TLS binding — deployment ID, host, port, CA DER, and CA pin — at client
creation, record commit, observation composition, session install, and every
production connect/sign-in/MFA gate. `ManagerSession`
uses an immutable launch mode, requires an actual pinned production client plus a
checkpoint store for every production connect/sign-in/inventory path, refuses
generic `ConnectionClient` injection as a production substitute, rechecks the
full checkpoint before required-MFA completion, and fences stale check results.
A production client without a store, or with only a legacy checkpoint-only
record that has no atomically bound TLS configuration, is refused rather than
silently admitted.

**Production bootstrap UI (source only):** normal `HelicoidManager` production
launch now presents `ProductionTrustView`. The operator supplies the CA DER
file, CA SHA-256 pin, hostname, port, deployment ID, grant-signing key SHA-256
fingerprint, and authority generation. The CA pin is deliberately not filled
from the selected file. The Manager observes
`GET /v2/deployment/authority` through the pinned CA, requires the observed
deployment ID, key fingerprint, and generation to match the operator-entered
values, and only then calls `commitProductionTrustRecord`. The checkpoint and
the TLS configuration are written together as one device-only, non-synchronizing
Keychain record. Subsequent launches prefill the saved configuration and offer
**Connect with Saved Trust**, which requires the form to match the exact saved
host, port, CA, and pin before contacting the network, then verifies the live
authority against the saved checkpoint. Editing any of those TLS fields or
switching deployments requires **Replace saved trust checkpoint** plus explicit
independent authority values; a substituted origin or deployment is never
saved silently. A stale window whose loaded record no longer matches the store
fails closed, clears its prefilled trust inputs, and demands explicit
re-entry/reset. A network key that does not match the operator values is never
adopted or connected. Record commits are compare-and-swap operations under the
same cross-process authority lock: the exact pre-network record snapshot,
including any other deployment named in that snapshot, is revalidated before the
single record is written, and network observation is never performed while the
lock is held. A concurrent reset or competing submission therefore fails closed
instead of overwriting or resurrecting trust. Installation also re-reads the
record and refuses a record that changed after verification. A legacy
checkpoint-only record has no bound TLS configuration and is never combined
with a new or substituted origin; the operator must reset or explicitly replace
it. A separate legacy TLS configuration item from the earlier split-store
implementation, if one is present, is left untouched: it is not read, migrated,
or silently deleted. Migration is explicit reset/replacement into the single
atomic record.

The production screen also offers **Set Up Server** navigation and an
always-visible **Reset Production Trust…** action. Reset is same-state checked
under the shared lock: a stale window cannot delete a record that another
window has replaced, and only the relevant or operator-typed deployment is
targeted. A complete reset clears host/deployment/CA/pin/fingerprint/generation
fields; a failed reset preserves the form/operator fields and the saved record
so the reset can be inspected and retried. An unreadable record can be removed
by an explicit reset when the target deployment is unambiguous; transient
Keychain read failures fail closed without deleting anything. If multiple saved
deployments exist and none is typed, reset refuses to guess and preserves all
of them. Settings also offers **Review Production Trust…** to return to that
screen after a successful setup.

Remaining setup is intentionally out of band: the operator must obtain the CA,
pin, hostname, deployment ID, key fingerprint, and generation through a trusted
organization channel. There is still no automated CA comparison/cutover beyond
the bootstrap screen and no verified live-server evidence in this checkpoint.
Changing trust requires the explicit **Review Production Trust…** flow plus
independent verification, replacement confirmation, or clearing saved trust; a
future server-driven cutover workflow is still separate. The checkpoint and TLS
configuration are one Keychain item, so there is no split write that can pair an
old checkpoint with a new origin or vice versa. The shared lock makes
concurrent record commits, replacements, and resets coherent. Crash and
interrupted-write recovery, installed-app behavior, and live-server TLS evidence
remain unverified in this source-only checkpoint. The lock cannot protect
against a process that rewrites the Keychain item without using this store, so
this source must remain the only production-trust record writer. A missing or
legacy checkpoint-only record therefore blocks production connection rather than
learning trust from the network.

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
