# Helicoid macOS apps

Independent native macOS 15 SwiftUI apps for Helicoid Systems computer monitoring.

| App | Role |
| --- | --- |
| **Helicoid Manager** | Operator console: connect, Computers inventory, inclusion/filter/selection, view-only remote window |
| **Helicoid Computer** | Managed computer status: menu bar connection/observer identity and help requests |

This tree builds without sibling path dependencies. The server HTTP contract is
vendored under `Resources/Contracts/`. Brand assets are bundled copies under
`Resources/` and each app target.

## Requirements

- macOS 15 or newer
- Xcode 27 / Swift 6.4 toolchain (`xcrun swift`)
- Intel and Apple Silicon source compatibility

## Build, test, package

```bash
./scripts/build.sh
```

Optional environment:

- `HELICOID_BUILD_DIR` — scratch build directory (default `apps/macos/.build`)
- `HELICOID_DIST_DIR` — packaged `.app` output (default `apps/macos/dist`)

The script runs `swift test`, `swift build -c release`, packages both apps, and
compiles bundled `.icon` sources with `actool` into `Assets.car` / `.icns`.

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

Production mode stays closed until a trusted server identity is implemented.

Fixture mode and development-server mode are independent and must not be conflated.

## Architecture

- `Sources/HelicoidCore` — models, monitoring state, connection boundary, loopback development client, DTOs
- `Sources/HelicoidManager` — SwiftUI manager app
- `Sources/HelicoidComputer` — SwiftUI menu-bar status app
- `Tests/HelicoidCoreTests` — pure Swift and HTTP parsing/denial tests

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

Mac manager offers **Linux SSH only**. Install never claims success without
integrated server packages.

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
