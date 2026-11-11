#!/bin/bash
# Development-only integration of a real `macos-dev-install` hs-server helper
# and its signed package into the Manager bundle.
#
# This is not a release packager. It writes a clearly separate development
# evidence document and Info.plist pin; the normal release path remains
# untouched. The helper binary itself must have been built by the server with
# `--features macos-dev-install` and the same
# HELICOID_MACOS_DEV_TRUST_KEY used here.
#
# The shell packaging step checks exact package shape and records helper,
# manifest, and artifact digests. The Manager runtime (CryptoKit) and the
# helper both re-verify the Ed25519 manifest signature against the pinned key
# before any privileged effect.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER_SCRIPT="$ROOT/scripts/hs-server-helper.sh"
HELPER_RELATIVE_PATH="Contents/Helpers/hs-server"
DEVELOPMENT_EVIDENCE_RELATIVE_PATH="Contents/Resources/hs-server-development-install.json"
DEVELOPMENT_PACKAGE_PARENT_RELATIVE_PATH="Contents/Resources/ServerPackage/development"
DEVELOPMENT_PACKAGE_RELATIVE_PATH="Contents/Resources/ServerPackage/development/package"
MANAGER_RELATIVE_PATH="Contents/MacOS/HelicoidManager"
INFO_KEY="HelicoidServerDevelopmentInstall"
TRUST_KEY_INFO_KEY="HelicoidServerDevelopmentTrustKey"

fail() {
  printf 'ERROR: development hs-server bundle: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  hs-server-development-bundle.sh package --helper ABSOLUTE_PATH \
    --package-dir ABSOLUTE_PATH --trust-key 64_HEX --app APP_PATH \
    --minimum-macos VERSION
  hs-server-development-bundle.sh verify --app APP_PATH
  hs-server-development-bundle.sh assert-absent --app APP_PATH

This development-only command packages a helper built with the server's
macos-dev-install feature, copies its exact signed macOS package, writes
Contents/Resources/hs-server-development-install.json, and records the
build-pinned Ed25519 key in Info.plist. It refuses any pre-existing
development install artifact. It never creates release evidence or trust roots.
Run verify after the containing app has been signed.
USAGE
}

require_absolute_path() {
  local label="$1"
  local path="$2"
  [ -n "$path" ] || fail "$label must not be empty"
  case "$path" in
    /*) ;;
    *) fail "$label must be an absolute path: $path" ;;
  esac
}

require_app_bundle() {
  local app_path="$1"
  [ -d "$app_path" ] || fail "app bundle does not exist: $app_path"
  [ -f "$app_path/$MANAGER_RELATIVE_PATH" ] \
    || fail "app bundle has no Manager executable: $app_path/$MANAGER_RELATIVE_PATH"
  [ -f "$app_path/Contents/Info.plist" ] \
    || fail "app bundle has no Info.plist: $app_path/Contents/Info.plist"
}

sha256_of() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

development_evidence_path() { printf '%s/%s' "$1" "$DEVELOPMENT_EVIDENCE_RELATIVE_PATH"; }
development_package_parent_path() { printf '%s/%s' "$1" "$DEVELOPMENT_PACKAGE_PARENT_RELATIVE_PATH"; }
development_package_path() { printf '%s/%s' "$1" "$DEVELOPMENT_PACKAGE_RELATIVE_PATH"; }

assert_absent_paths() {
  local app_path="$1"
  local evidence package package_parent info_plist
  evidence="$(development_evidence_path "$app_path")"
  package="$(development_package_path "$app_path")"
  package_parent="$(development_package_parent_path "$app_path")"
  info_plist="$app_path/Contents/Info.plist"
  if [ -e "$evidence" ] || [ -L "$evidence" ]; then
    fail "refusing existing development install evidence: $evidence"
  fi
  if [ -e "$package_parent" ] || [ -L "$package_parent" ]; then
    fail "refusing existing development package parent: $package_parent"
  fi
  if [ -e "$package" ] || [ -L "$package" ]; then
    fail "refusing existing development package directory: $package"
  fi
  if [ -f "$info_plist" ] \
    && /usr/bin/plutil -extract "$INFO_KEY" raw "$info_plist" >/dev/null 2>&1; then
    fail "refusing existing development install Info.plist pin: $info_plist"
  fi
  if [ -f "$info_plist" ] \
    && /usr/bin/plutil -extract "$TRUST_KEY_INFO_KEY" raw "$info_plist" >/dev/null 2>&1; then
    fail "refusing existing development trust-key Info.plist pin: $info_plist"
  fi
}

APP_PATH=""
CREATED_HELPER=""
CREATED_DEVELOPMENT_EVIDENCE=""
CREATED_DEVELOPMENT_PACKAGE=""
CREATED_DEVELOPMENT_PACKAGE_PARENT=""
CREATED_INSTALL_EVIDENCE=""
INFO_PIN_ADDED=0
TRUST_KEY_ADDED=0

cleanup() {
  if [ "$TRUST_KEY_ADDED" = 1 ]; then
    /usr/bin/plutil -remove "$TRUST_KEY_INFO_KEY" "$APP_PATH/Contents/Info.plist" >/dev/null 2>&1 || true
  fi
  if [ "$INFO_PIN_ADDED" = 1 ]; then
    /usr/bin/plutil -remove "$INFO_KEY" "$APP_PATH/Contents/Info.plist" >/dev/null 2>&1 || true
  fi
  [ -z "$CREATED_INSTALL_EVIDENCE" ] || /bin/rm -f "$CREATED_INSTALL_EVIDENCE"
  [ -z "$CREATED_DEVELOPMENT_PACKAGE" ] || /bin/rm -rf "$CREATED_DEVELOPMENT_PACKAGE"
  [ -z "$CREATED_DEVELOPMENT_PACKAGE_PARENT" ] || /bin/rmdir "$CREATED_DEVELOPMENT_PACKAGE_PARENT" 2>/dev/null || true
  [ -z "$CREATED_DEVELOPMENT_EVIDENCE" ] || /bin/rm -f "$CREATED_DEVELOPMENT_EVIDENCE"
  [ -z "$CREATED_HELPER" ] || /bin/rm -f "$CREATED_HELPER"
}
trap cleanup EXIT

package_bundle() {
  local helper_path="$1"
  local package_dir="$2"
  local trust_key="$3"
  local app_path="$4"
  local minimum_macos="$5"

  require_absolute_path "--helper" "$helper_path"
  require_absolute_path "--package-dir" "$package_dir"
  require_absolute_path "--app" "$app_path"
  [[ "$trust_key" =~ ^[0-9a-fA-F]{64}$ ]] \
    || fail "--trust-key must be a 64-character Ed25519 public key in hex"
  trust_key="$(printf '%s' "$trust_key" | /usr/bin/tr 'A-F' 'a-f')"
  [[ "$minimum_macos" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] \
    || fail "--minimum-macos must be a numeric macOS version: $minimum_macos"

  require_app_bundle "$app_path"
  command -v python3 >/dev/null 2>&1 || fail "python3 is required"
  [ ! -L "$helper_path" ] || fail "helper must not be a symbolic link: $helper_path"
  [ -f "$helper_path" ] || fail "helper is not a regular file: $helper_path"
  [ -x "$helper_path" ] || fail "helper is not executable: $helper_path"
  [ ! -L "$package_dir" ] || fail "package directory must not be a symbolic link: $package_dir"
  [ -d "$package_dir" ] || fail "package directory does not exist: $package_dir"
  assert_absent_paths "$app_path"

  # Reuse the existing development helper validation/signing/evidence path.
  "$HELPER_SCRIPT" package \
    --source "$helper_path" \
    --app "$app_path" \
    --minimum-macos "$minimum_macos"
  CREATED_HELPER="$(printf '%s/%s' "$app_path" "$HELPER_RELATIVE_PATH")"
  CREATED_DEVELOPMENT_EVIDENCE="$app_path/Contents/Resources/hs-server-development.json"
  [ -f "$CREATED_HELPER" ] || fail "development helper was not placed in the app bundle"

  local capabilities_file
  capabilities_file="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/helicoid-dev-capabilities.XXXXXX")" \
    || fail "cannot create a capabilities staging file"
  if ! /usr/bin/env RUST_LOG=error "$CREATED_HELPER" installer capabilities-v2 \
    > "$capabilities_file" 2>/dev/null; then
    /bin/rm -f "$capabilities_file"
    fail "helper did not answer installer capabilities-v2; it may not be the development-feature build"
  fi
  if ! python3 - "$capabilities_file" <<'PY'
import json
import sys
try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as error:
    raise SystemExit(f"capabilities output is not valid JSON: {error}")
if value.get("contract_version") != 2:
    raise SystemExit("capabilities contract_version is not 2")
if "install" not in value.get("supported_actions", []):
    raise SystemExit("helper does not advertise the install action; rebuild with --features macos-dev-install")
if "macos_launchd" not in value.get("supported_deployment_kinds", []):
    raise SystemExit("helper does not advertise macos_launchd")
if "loopback_development" not in value.get("supported_network_scopes", []):
    raise SystemExit("helper does not advertise loopback_development")
PY
  then
    /bin/rm -f "$capabilities_file"
    fail "helper capabilities are not the expected development install contract"
  fi
  /bin/rm -f "$capabilities_file"


  local destination_package destination_evidence
  destination_package="$(development_package_path "$app_path")"
  destination_evidence="$(development_evidence_path "$app_path")"
  /bin/mkdir -p "$(dirname "$destination_package")"
  CREATED_DEVELOPMENT_PACKAGE_PARENT="$(dirname "$destination_package")"
  [ ! -e "$destination_package" ] && [ ! -L "$destination_package" ] \
    || fail "refusing to replace development package: $destination_package"
  CREATED_DEVELOPMENT_PACKAGE="$destination_package"
  /bin/cp -R "$package_dir" "$destination_package"
  CREATED_INSTALL_EVIDENCE="$destination_evidence"

  local host_target
  case "$(/usr/bin/uname -m)" in
    arm64) host_target="macos-arm64" ;;
    x86_64) host_target="macos-x86_64" ;;
    *) fail "unsupported host architecture: $(/usr/bin/uname -m)" ;;
  esac

  python3 - "$app_path" "$CREATED_HELPER" "$destination_package" "$trust_key" "$host_target" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

app, helper, package, trust_key, host_target = sys.argv[1:6]
helper = pathlib.Path(helper)
package = pathlib.Path(package)

def require_regular(path, label, max_bytes=None):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"{label} is not a regular non-symlink file: {path}")
    if info.st_nlink != 1:
        raise SystemExit(f"{label} must have exactly one link: {path}")
    if max_bytes is not None and info.st_size > max_bytes:
        raise SystemExit(f"{label} exceeds its size bound: {path}")
    return info

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def strict_version(value):
    parts = value.split(".")
    return (len(parts) == 3
            and all(part.isdigit() and (part == "0" or not part.startswith("0")) for part in parts))

helper_info = require_regular(helper, "helper", 512 * 1024 * 1024)
package_info = os.lstat(package)
if not stat.S_ISDIR(package_info.st_mode) or stat.S_ISLNK(package_info.st_mode):
    raise SystemExit("package directory is not a non-symlink directory")

entries = sorted(os.listdir(package))
if entries != ["artifacts", "manifest.json", "manifest.sig"]:
    raise SystemExit("package root must contain exactly artifacts, manifest.json, and manifest.sig")
artifacts = package / "artifacts"
artifacts_info = os.lstat(artifacts)
if not stat.S_ISDIR(artifacts_info.st_mode) or stat.S_ISLNK(artifacts_info.st_mode):
    raise SystemExit("package artifacts path is not a non-symlink directory")
if sorted(os.listdir(artifacts)) != ["hs-server"]:
    raise SystemExit("package artifacts must contain exactly hs-server")

manifest_path = package / "manifest.json"
signature_path = package / "manifest.sig"
require_regular(manifest_path, "manifest.json", 1024 * 1024)
require_regular(signature_path, "manifest.sig", 64)
if os.lstat(signature_path).st_size != 64:
    raise SystemExit("manifest.sig must be exactly 64 bytes")
manifest_bytes = manifest_path.read_bytes()
try:
    manifest = json.loads(manifest_bytes)
except Exception as error:
    raise SystemExit(f"manifest.json is not valid JSON: {error}")

if manifest.get("format_version") != 1:
    raise SystemExit("manifest format_version must be 1")
if manifest.get("product") != "hs-server":
    raise SystemExit("manifest product must be exactly hs-server")
if not strict_version(str(manifest.get("version", ""))):
    raise SystemExit("manifest version must be strict major.minor.patch")
platform = manifest.get("platform")
if platform not in ("macos-arm64", "macos-x86_64"):
    raise SystemExit("manifest platform is not a supported macOS target")
if platform != host_target:
    raise SystemExit(f"package targets {platform}, not this host's {host_target}")
artifacts_list = manifest.get("artifacts")
if not isinstance(artifacts_list, list) or len(artifacts_list) != 1:
    raise SystemExit("manifest must declare exactly one artifact")
artifact = artifacts_list[0]
if artifact.get("path") != "artifacts/hs-server":
    raise SystemExit("manifest artifact path must be artifacts/hs-server")
artifact_path = package / "artifacts/hs-server"
artifact_info = require_regular(artifact_path, "artifact", 512 * 1024 * 1024)
artifact_sha = sha256_file(artifact_path)
if artifact_sha != str(artifact.get("sha256", "")).lower():
    raise SystemExit("artifact digest does not match the signed manifest")
if artifact_info.st_size != artifact.get("size_bytes"):
    raise SystemExit("artifact size does not match the signed manifest")

key_bytes = bytes.fromhex(trust_key)
if len(key_bytes) != 32:
    raise SystemExit("trust key must be 32 bytes")
key_sha = hashlib.sha256(key_bytes).hexdigest()
evidence = {
    "schema": 1,
    "mode": "development-install",
    "developmentOnly": True,
    "distributionSigned": False,
    "installationEnabled": True,
    "helperPath": "Contents/Helpers/hs-server",
    "helperSha256": sha256_file(helper),
    "packageDirectory": "Contents/Resources/ServerPackage/development/package",
    "packageManifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
    "packageArtifactPath": "artifacts/hs-server",
    "packageArtifactSha256": artifact_sha,
    "packageArtifactSizeBytes": artifact_info.st_size,
    "packageTarget": platform,
    "packageProduct": "hs-server",
    "packageVersion": str(manifest["version"]),
    "verificationKeyHex": trust_key,
    "verificationKeySha256": key_sha,
    "note": "Development-only build-pinned helper/package binding. Not a release trust root, notarization, or production acceptance evidence.",
}
evidence_path = pathlib.Path(app) / "Contents/Resources/hs-server-development-install.json"
if evidence_path.exists() or evidence_path.is_symlink():
    raise SystemExit("development evidence path already exists")
with open(evidence_path, "x", encoding="utf-8") as handle:
    json.dump(evidence, handle, indent=2)
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(evidence_path, 0o644)
print(f"development_evidence={evidence_path}")
PY
  /usr/bin/plutil -convert json "$destination_evidence" -o /dev/null \
    || fail "generated development evidence is not valid JSON"

  /usr/bin/plutil -insert "$INFO_KEY" -bool YES "$app_path/Contents/Info.plist" \
    || fail "could not add the development install Info.plist flag"
  INFO_PIN_ADDED=1
  /usr/bin/plutil -insert "$TRUST_KEY_INFO_KEY" -string "$trust_key" "$app_path/Contents/Info.plist" \
    || fail "could not add the development trust-key Info.plist pin"
  TRUST_KEY_ADDED=1

  # Successful commit: disable rollback of created artifacts.
  CREATED_HELPER=""
  CREATED_DEVELOPMENT_EVIDENCE=""
  CREATED_DEVELOPMENT_PACKAGE=""
  CREATED_DEVELOPMENT_PACKAGE_PARENT=""
  CREATED_INSTALL_EVIDENCE=""
  INFO_PIN_ADDED=0
  TRUST_KEY_ADDED=0
  printf 'Packaged DEVELOPMENT-ONLY hs-server installer payload at %s.\n' "$app_path"
  printf 'Pinned Ed25519 key: %s\n' "$trust_key"
  printf 'This is not a release trust root, notarization, or production acceptance.\n'
}

verify_bundle() {
  local app_path="$1"
  require_absolute_path "--app" "$app_path"
  require_app_bundle "$app_path"
  local helper evidence package info_plist key
  helper="$app_path/$HELPER_RELATIVE_PATH"
  evidence="$(development_evidence_path "$app_path")"
  package="$(development_package_path "$app_path")"
  info_plist="$app_path/Contents/Info.plist"
  [ -f "$helper" ] && [ ! -L "$helper" ] || fail "development helper is missing or unsafe"
  [ -f "$evidence" ] && [ ! -L "$evidence" ] || fail "development install evidence is missing or unsafe"
  [ -d "$package" ] && [ ! -L "$package" ] || fail "development package is missing or unsafe"
  /usr/bin/plutil -convert json "$evidence" -o /dev/null \
    || fail "development install evidence is not valid JSON"
  [ "$(/usr/bin/plutil -extract "$INFO_KEY" raw "$info_plist" 2>/dev/null)" = "true" ] \
    || fail "development install Info.plist flag is missing"
  key="$(/usr/bin/plutil -extract "$TRUST_KEY_INFO_KEY" raw "$info_plist" 2>/dev/null)"
  [[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "development trust-key Info.plist pin is malformed"
  [ "$(/usr/bin/plutil -extract verificationKeyHex raw "$evidence")" = "$key" ] \
    || fail "development evidence key does not match the build pin"
  [ "$(/usr/bin/plutil -extract helperSha256 raw "$evidence")" = "$(sha256_of "$helper")" ] \
    || fail "development helper digest does not match the development evidence"
  [ "$(/usr/bin/plutil -extract mode raw "$evidence")" = "development-install" ] \
    || fail "development evidence has an unexpected mode"
  [ "$(/usr/bin/plutil -extract packageManifestSha256 raw "$evidence")" = \
    "$(sha256_of "$package/manifest.json")" ] \
    || fail "development package manifest digest does not match the development evidence"
  [ "$(/usr/bin/plutil -extract packageArtifactSha256 raw "$evidence")" = \
    "$(sha256_of "$package/artifacts/hs-server")" ] \
    || fail "development package artifact digest does not match the development evidence"
  [ "$(/usr/bin/plutil -extract packageArtifactSizeBytes raw "$evidence")" = \
    "$(/usr/bin/stat -f '%z' "$package/artifacts/hs-server")" ] \
    || fail "development package artifact size does not match the development evidence"
  "$HELPER_SCRIPT" verify --app "$app_path"
  # The Swift runtime verifies the Ed25519 manifest signature and package
  # digests again. This shell check only proves the bundle layout is complete.
  printf 'Verified DEVELOPMENT-ONLY hs-server bundle layout and pinned key (%s).\n' "$key"
}

assert_absent_bundle() {
  require_absolute_path "--app" "$1"
  assert_absent_paths "$1"
  printf 'No development hs-server install payload is present in %s.\n' "$1"
}

COMMAND="${1:-}"
if [ -z "$COMMAND" ]; then
  usage >&2
  exit 2
fi
shift

HELPER_PATH=""
PACKAGE_DIR=""
TRUST_KEY=""
APP_PATH=""
MINIMUM_MACOS=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --helper) [ "$#" -ge 2 ] || fail "--helper requires a value"; HELPER_PATH="$2"; shift 2 ;;
    --package-dir) [ "$#" -ge 2 ] || fail "--package-dir requires a value"; PACKAGE_DIR="$2"; shift 2 ;;
    --trust-key) [ "$#" -ge 2 ] || fail "--trust-key requires a value"; TRUST_KEY="$2"; shift 2 ;;
    --app) [ "$#" -ge 2 ] || fail "--app requires a value"; APP_PATH="$2"; shift 2 ;;
    --minimum-macos) [ "$#" -ge 2 ] || fail "--minimum-macos requires a value"; MINIMUM_MACOS="$2"; shift 2 ;;
    -h|--help|help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

case "$COMMAND" in
  package)
    [ -n "$HELPER_PATH" ] || fail "package requires --helper"
    [ -n "$PACKAGE_DIR" ] || fail "package requires --package-dir"
    [ -n "$TRUST_KEY" ] || fail "package requires --trust-key"
    [ -n "$APP_PATH" ] || fail "package requires --app"
    [ -n "$MINIMUM_MACOS" ] || fail "package requires --minimum-macos"
    package_bundle "$HELPER_PATH" "$PACKAGE_DIR" "$TRUST_KEY" "$APP_PATH" "$MINIMUM_MACOS"
    ;;
  verify)
    [ -n "$APP_PATH" ] || fail "verify requires --app"
    verify_bundle "$APP_PATH"
    ;;
  assert-absent)
    [ -n "$APP_PATH" ] || fail "assert-absent requires --app"
    assert_absent_bundle "$APP_PATH"
    ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
