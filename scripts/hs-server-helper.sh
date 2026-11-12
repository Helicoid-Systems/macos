#!/bin/bash
# Development-only packaging for an operator-supplied hs-server helper.
#
# Validates and stages a locally built Mach-O helper, ad-hoc signs the staged
# copy, and links it into an existing Helicoid Manager bundle without replacing
# any pre-existing file. It never installs, launches, or authorizes a service.
set -euo pipefail

HELPER_NAME="hs-server"
HELPER_RELATIVE_PATH="Contents/Helpers/hs-server"
EVIDENCE_RELATIVE_PATH="Contents/Resources/hs-server-development.json"
RELEASE_EVIDENCE_RELATIVE_PATH="Contents/Resources/hs-server-release.json"
RELEASE_PACKAGE_RELATIVE_PATH="Contents/Resources/ServerPackage"
DEVELOPMENT_INSTALL_EVIDENCE_RELATIVE_PATH="Contents/Resources/hs-server-development-install.json"
DEVELOPMENT_INSTALL_PACKAGE_RELATIVE_PATH="Contents/Resources/ServerPackage/development"
MANAGER_RELATIVE_PATH="Contents/MacOS/HelicoidManager"
SCHEMA_VERSION=1

fail() {
  printf 'ERROR: hs-server helper: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage:
  hs-server-helper.sh check-source --source ABSOLUTE_PATH --manager-binary PATH --minimum-macos VERSION
  hs-server-helper.sh package --source ABSOLUTE_PATH --app APP_PATH --minimum-macos VERSION
  hs-server-helper.sh verify --app APP_PATH
  hs-server-helper.sh assert-absent --app APP_PATH

check-source validates a requested helper without copying it. package validates
and ad-hoc signs a staged copy, then links it into Contents/Helpers/hs-server and
writes digest evidence at Contents/Resources/hs-server-development.json. It
refuses any pre-existing helper or evidence file rather than replacing it. The
source binary is never modified.

VERSION is the Manager's minimum macOS version (for example 15.0); every helper
slice must target that version or older. verify checks the staged evidence
digest, architecture compatibility, ad-hoc signature, and the containing app's
deep signature. assert-absent fails if either development-only artifact, a
release evidence/package payload, or a development install payload is present.
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
}

sha256_of() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

plutil_raw() {
  /usr/bin/plutil -extract "$2" raw "$1" 2>/dev/null
}

manager_architectures() {
  local manager_binary="$1"
  [ -f "$manager_binary" ] || fail "Manager executable does not exist: $manager_binary"
  local archs
  archs="$(/usr/bin/xcrun lipo -archs "$manager_binary" 2>/dev/null)" \
    || fail "cannot read Manager architectures: $manager_binary"
  [ -n "$archs" ] || fail "Manager executable has no architectures: $manager_binary"
  local arch
  for arch in $archs; do
    # Apple's lipo names cpusubtype variants with a dot (`arm64e.x1`); accept
    # only that alphabet and reject anything option-like.
    [[ "$arch" =~ ^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$ ]] \
      || fail "unexpected Manager architecture: $arch"
  done
  printf '%s' "$archs"
}

version_le() {
  /usr/bin/awk -v candidate="$1" -v limit="$2" 'BEGIN {
    n = split(candidate, a, ".")
    m = split(limit, b, ".")
    for (i = 1; i <= 3; i++) {
      x = (i <= n ? a[i] : 0) + 0
      y = (i <= m ? b[i] : 0) + 0
      if (x < y) exit 0
      if (x > y) exit 1
    }
    exit 0
  }'
}

json_architectures() {
  local json="[" arch
  for arch in $1; do
    json="${json}\"${arch}\","
  done
  printf '%s' "${json%,}]"
}

json_versions() {
  local json="[" version
  while IFS= read -r version; do
    [ -n "$version" ] || continue
    json="${json}\"${version}\","
  done <<< "$1"
  printf '%s' "${json%,}]"
}

signature_is_adhoc() {
  local details
  details="$(/usr/bin/codesign -dvv "$1" 2>&1)" \
    || fail "cannot read helper code signature: $1"
  printf '%s\n' "$details" | /usr/bin/grep -q 'Signature=adhoc' \
    || fail "helper is not ad-hoc signed: $1"
}

helper_path() { printf '%s/%s' "$1" "$HELPER_RELATIVE_PATH"; }
evidence_path() { printf '%s/%s' "$1" "$EVIDENCE_RELATIVE_PATH"; }

assert_absent_paths() {
  local app_path="$1"
  local helper evidence release_evidence release_package
  local development_install_evidence development_install_package
  helper="$(helper_path "$app_path")"
  evidence="$(evidence_path "$app_path")"
  release_evidence="$app_path/$RELEASE_EVIDENCE_RELATIVE_PATH"
  release_package="$app_path/$RELEASE_PACKAGE_RELATIVE_PATH"
  development_install_evidence="$app_path/$DEVELOPMENT_INSTALL_EVIDENCE_RELATIVE_PATH"
  development_install_package="$app_path/$DEVELOPMENT_INSTALL_PACKAGE_RELATIVE_PATH"
  if [ -e "$helper" ] || [ -L "$helper" ]; then
    fail "refusing to overwrite existing helper: $helper (use a fresh HELICOID_DIST_DIR)"
  fi
  if [ -e "$evidence" ] || [ -L "$evidence" ]; then
    fail "refusing to overwrite existing evidence: $evidence (use a fresh HELICOID_DIST_DIR)"
  fi
  # A stale release payload would be trusted by the Manager if it survived a
  # rebuild. Refuse it in the development packaging path instead of silently
  # carrying it forward.
  if [ -e "$release_evidence" ] || [ -L "$release_evidence" ]; then
    fail "refusing pre-existing release helper evidence: $release_evidence (use a fresh HELICOID_DIST_DIR)"
  fi
  if [ -e "$release_package" ] || [ -L "$release_package" ]; then
    fail "refusing pre-existing signed server package: $release_package (use a fresh HELICOID_DIST_DIR)"
  fi
  if [ -e "$development_install_evidence" ] || [ -L "$development_install_evidence" ]; then
    fail "refusing pre-existing development install evidence: $development_install_evidence (use a fresh HELICOID_DIST_DIR)"
  fi
  if [ -e "$development_install_package" ] || [ -L "$development_install_package" ]; then
    fail "refusing pre-existing development install package: $development_install_package (use a fresh HELICOID_DIST_DIR)"
  fi
  if [ -f "$app_path/Contents/Info.plist" ] \
    && /usr/bin/plutil -extract HelicoidServerDevelopmentInstall raw "$app_path/Contents/Info.plist" >/dev/null 2>&1; then
    fail "refusing pre-existing development install Info.plist pin: $app_path/Contents/Info.plist (use a fresh HELICOID_DIST_DIR)"
  fi
  if [ -f "$app_path/Contents/Info.plist" ] \
    && /usr/bin/plutil -extract HelicoidServerDevelopmentTrustKey raw "$app_path/Contents/Info.plist" >/dev/null 2>&1; then
    fail "refusing pre-existing development trust-key Info.plist pin: $app_path/Contents/Info.plist (use a fresh HELICOID_DIST_DIR)"
  fi
}

validate_helper_macho() {
  local helper_path="$1"
  local manager_archs="$2"
  local minimum_macos="$3"

  [ ! -L "$helper_path" ] || fail "helper path is a symbolic link: $helper_path"
  [ -f "$helper_path" ] || fail "helper path is not a regular file: $helper_path"
  [ -x "$helper_path" ] || fail "helper path is not executable: $helper_path"

  # `lipo -archs` is the authoritative slice list. It can name a cpusubtype
  # variant (`arm64e.x1`), so the accepted alphabet includes dots.
  local helper_archs
  helper_archs="$(/usr/bin/xcrun lipo -archs "$helper_path" 2>/dev/null)" \
    || fail "cannot read helper architectures: $helper_path"
  [ -n "$helper_archs" ] || fail "helper has no architectures: $helper_path"

  local arch required found
  for arch in $helper_archs; do
    [[ "$arch" =~ ^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$ ]] \
      || fail "unexpected helper architecture: $arch"
  done
  for required in $manager_archs; do
    found=0
    for arch in $helper_archs; do
      [ "$arch" = "$required" ] && found=1
    done
    [ "$found" = 1 ] \
      || fail "helper does not contain Manager architecture $required (helper: $helper_archs)"
  done

  # Validate every slice named by lipo explicitly with `-arch`. `otool -hv`
  # and `vtool -show-build` default to the host architecture for a universal
  # file, which hides the foreign slice (and made a two-slice helper look like
  # a one-slice helper on Intel). Each slice must be exactly one Mach-O
  # executable with exactly one macOS deployment target at or below the floor.
  local minos_values="" headers header_count build_info records record_count
  local platform minos
  for arch in $helper_archs; do
    headers="$(/usr/bin/xcrun otool -arch "$arch" -hv "$helper_path" 2>/dev/null)" \
      || fail "helper architecture $arch is not a readable Mach-O file: $helper_path"
    header_count="$(printf '%s\n' "$headers" \
      | /usr/bin/awk '/^MH_MAGIC/ { n++ } END { print n + 0 }')"
    [ "$header_count" -eq 1 ] \
      || fail "helper architecture $arch has $header_count Mach-O headers, expected 1: $helper_path"
    printf '%s\n' "$headers" | /usr/bin/awk '
      /^MH_MAGIC/ {
        filetype = ""
        for (i = 2; i <= NF; i++) {
          if ($i ~ /^(OBJECT|EXECUTE|FVMLIB|CORE|PRELOAD|DYLIB|DYLINKER|BUNDLE|DYLIB_STUB|DSYM|KEXT_BUNDLE|FILESET)$/) filetype = $i
        }
        if (filetype != "EXECUTE") bad = 1
      }
      END { exit bad ? 1 : 0 }
    ' || fail "helper architecture $arch is not a Mach-O executable slice: $helper_path"

    build_info="$(/usr/bin/xcrun vtool -arch "$arch" -show-build "$helper_path" 2>/dev/null)" \
      || fail "cannot read the macOS deployment target for helper architecture $arch: $helper_path"
    records="$(printf '%s\n' "$build_info" | /usr/bin/awk '
      /^Load command/ { build = 0; legacy = 0; next }
      /cmd LC_BUILD_VERSION/ { build = 1; platform = ""; next }
      /cmd LC_VERSION_MIN_MACOSX/ { legacy = 1; next }
      build && /^[[:space:]]*platform[[:space:]]/ { platform = $2; next }
      build && /^[[:space:]]*minos[[:space:]]/ { print platform " " $2; build = 0; next }
      legacy && /^[[:space:]]*version[[:space:]]/ { print "MACOS " $2; legacy = 0; next }
    ')"
    [ -n "$records" ] \
      || fail "helper architecture $arch has no macOS deployment target: $helper_path"
    record_count="$(printf '%s\n' "$records" | /usr/bin/awk 'NF { n++ } END { print n + 0 }')"
    [ "$record_count" -eq 1 ] \
      || fail "helper architecture $arch declares $record_count macOS deployment targets, expected 1: $helper_path"

    while IFS=' ' read -r platform minos; do
      [ -n "$platform" ] || continue
      [ "$platform" = "MACOS" ] || fail "helper slice targets $platform, not macOS: $helper_path"
      [[ "$minos" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] \
        || fail "helper has a malformed minimum macOS version: $minos"
      version_le "$minos" "$minimum_macos" \
        || fail "helper minimum macOS $minos exceeds the Manager minimum $minimum_macos"
      minos_values="${minos_values}${minos}"$'\n'
    done <<< "$records"
  done
  printf '%s' "$minos_values"
}

check_source_helper() {
  local source_path="$1" manager_binary="$2" minimum_macos="$3"
  require_absolute_path "--source" "$source_path"
  require_absolute_path "--manager-binary" "$manager_binary"
  [[ "$minimum_macos" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] \
    || fail "--minimum-macos must be a numeric macOS version: $minimum_macos"
  local manager_archs
  manager_archs="$(manager_architectures "$manager_binary")"
  validate_helper_macho "$source_path" "$manager_archs" "$minimum_macos" >/dev/null
  printf 'Validated development %s helper source (not copied).\n' "$HELPER_NAME"
}

STAGE_DIR=""
CREATED_HELPER=""
CREATED_EVIDENCE=""
COMMITTED=0

cleanup_stage() {
  [ -z "$STAGE_DIR" ] || /bin/rm -rf "$STAGE_DIR"
  if [ "$COMMITTED" != 1 ]; then
    [ -z "$CREATED_HELPER" ] || /bin/rm -f "$CREATED_HELPER"
    [ -z "$CREATED_EVIDENCE" ] || /bin/rm -f "$CREATED_EVIDENCE"
  fi
}
trap cleanup_stage EXIT

package_helper() {
  local source_path="$1" app_path="$2" minimum_macos="$3"
  require_absolute_path "--source" "$source_path"
  require_absolute_path "--app" "$app_path"
  [[ "$minimum_macos" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] \
    || fail "--minimum-macos must be a numeric macOS version: $minimum_macos"
  require_app_bundle "$app_path"

  # Refuse pre-existing output first; no file or directory is removed here.
  assert_absent_paths "$app_path"

  [ ! -L "$source_path" ] || fail "source must not be a symbolic link: $source_path"
  [ -f "$source_path" ] || fail "source is not a regular file: $source_path"
  [ -x "$source_path" ] || fail "source is not executable: $source_path"

  local manager_binary manager_archs source_sha
  manager_binary="$app_path/$MANAGER_RELATIVE_PATH"
  manager_archs="$(manager_architectures "$manager_binary")"
  source_sha="$(sha256_of "$source_path")"
  [[ "$source_sha" =~ ^[0-9a-f]{64}$ ]] || fail "could not compute the source SHA-256"

  STAGE_DIR="$(/usr/bin/mktemp -d "$(/usr/bin/dirname "$app_path")/.hs-server-helper.XXXXXX")"
  local staged_helper="$STAGE_DIR/$HELPER_NAME"
  local staged_evidence="$STAGE_DIR/hs-server-development.json"

  /bin/cp "$source_path" "$staged_helper"
  /bin/chmod 755 "$staged_helper"
  [ "$(sha256_of "$staged_helper")" = "$source_sha" ] \
    || fail "the staged helper does not match the source bytes"
  [ "$(sha256_of "$source_path")" = "$source_sha" ] \
    || fail "the source helper changed during packaging"

  local minos_values
  minos_values="$(validate_helper_macho "$staged_helper" "$manager_archs" "$minimum_macos")"

  /usr/bin/codesign --force --sign - "$staged_helper"
  /usr/bin/codesign --verify --strict "$staged_helper"
  signature_is_adhoc "$staged_helper"
  [ "$(sha256_of "$source_path")" = "$source_sha" ] \
    || fail "the source helper changed during packaging; refusing to include it"

  local included_sha included_bytes helper_archs arch_json manager_json minos_json
  included_sha="$(sha256_of "$staged_helper")"
  [[ "$included_sha" =~ ^[0-9a-f]{64}$ ]] || fail "could not compute the included SHA-256"
  included_bytes="$(/usr/bin/stat -f '%z' "$staged_helper")"
  [[ "$included_bytes" =~ ^[0-9]+$ ]] || fail "could not read the included byte count"
  helper_archs="$(/usr/bin/xcrun lipo -archs "$staged_helper" 2>/dev/null)" \
    || fail "cannot read staged helper architectures"
  arch_json="$(json_architectures "$helper_archs")"
  manager_json="$(json_architectures "$manager_archs")"
  minos_json="$(json_versions "$minos_values")"

  cat > "$staged_evidence" <<EVIDENCE_EOF
{
  "schema": $SCHEMA_VERSION,
  "helper": "$HELPER_NAME",
  "path": "$HELPER_RELATIVE_PATH",
  "developmentOnly": true,
  "distributionSigned": false,
  "securityFloor": false,
  "installationEnabled": false,
  "serviceEnabled": false,
  "signature": "ad-hoc",
  "sourceSHA256": "$source_sha",
  "includedSHA256": "$included_sha",
  "includedBytes": $included_bytes,
  "architectures": $arch_json,
  "minos": $minos_json,
  "managerMinimumMacOS": "$minimum_macos",
  "managerArchitectures": $manager_json,
  "note": "Development packaging only; this ad-hoc signed helper is not a release signature, security floor, installation, or service-launch authorization."
}
EVIDENCE_EOF
  /usr/bin/plutil -convert json "$staged_evidence" -o /dev/null \
    || fail "generated helper evidence is not valid JSON"
  [ "$(sha256_of "$staged_helper")" = "$included_sha" ] \
    || fail "the staged helper changed after its evidence digest was recorded"

  # Recheck immediately before linking; existing artifacts are always refused.
  assert_absent_paths "$app_path"
  local bundle_dir
  for bundle_dir in "$app_path/Contents" "$app_path/Contents/Helpers" "$app_path/Contents/Resources"; do
    [ ! -L "$bundle_dir" ] || fail "refusing symlinked bundle directory: $bundle_dir"
    if [ -e "$bundle_dir" ]; then
      [ -d "$bundle_dir" ] || fail "bundle path is not a directory: $bundle_dir"
    fi
  done
  /bin/mkdir -p "$app_path/Contents/Helpers" "$app_path/Contents/Resources"
  local destination_helper destination_evidence
  destination_helper="$(helper_path "$app_path")"
  destination_evidence="$(evidence_path "$app_path")"
  /bin/ln "$staged_helper" "$destination_helper" \
    || fail "could not place helper without overwriting a path: $destination_helper"
  CREATED_HELPER="$destination_helper"
  /bin/ln "$staged_evidence" "$destination_evidence" \
    || fail "could not place evidence without overwriting a path: $destination_evidence"
  CREATED_EVIDENCE="$destination_evidence"
  COMMITTED=1

  printf 'Packaged development %s helper at %s (minOS %s; sha256 %s).\n' \
    "$HELPER_NAME" "$destination_helper" \
    "$(/usr/bin/tr '\n' ',' <<< "$minos_values" | /usr/bin/sed 's/,$//')" \
    "$included_sha"
  printf 'Evidence: %s. Development only; not a release signature or security floor.\n' \
    "$destination_evidence"
}

verify_helper() {
  local app_path="$1"
  require_absolute_path "--app" "$app_path"
  require_app_bundle "$app_path"

  local helper evidence manager_binary
  helper="$(helper_path "$app_path")"
  evidence="$(evidence_path "$app_path")"
  [ -f "$helper" ] && [ ! -L "$helper" ] \
    || fail "packaged helper is missing or not a regular file: $helper"
  [ -f "$evidence" ] && [ ! -L "$evidence" ] \
    || fail "helper evidence is missing or not a regular file: $evidence"
  /usr/bin/plutil -convert json "$evidence" -o /dev/null \
    || fail "helper evidence is not valid JSON: $evidence"

  [ "$(plutil_raw "$evidence" schema)" = "$SCHEMA_VERSION" ] \
    || fail "helper evidence has an unexpected schema"
  [ "$(plutil_raw "$evidence" path)" = "$HELPER_RELATIVE_PATH" ] \
    || fail "helper evidence names an unexpected bundle path"
  [ "$(plutil_raw "$evidence" developmentOnly)" = "true" ] \
    || fail "helper evidence must be development-only"
  [ "$(plutil_raw "$evidence" distributionSigned)" = "false" ] \
    || fail "helper evidence must not claim a distribution signature"
  [ "$(plutil_raw "$evidence" securityFloor)" = "false" ] \
    || fail "helper evidence must not claim a security floor"
  [ "$(plutil_raw "$evidence" installationEnabled)" = "false" ] \
    || fail "helper evidence must not claim installation is enabled"
  [ "$(plutil_raw "$evidence" serviceEnabled)" = "false" ] \
    || fail "helper evidence must not claim service launch is enabled"
  [ "$(plutil_raw "$evidence" signature)" = "ad-hoc" ] \
    || fail "helper evidence must record the ad-hoc signature"

  local recorded_sha actual_sha recorded_bytes actual_bytes recorded_source minos
  recorded_sha="$(plutil_raw "$evidence" includedSHA256)"
  [[ "$recorded_sha" =~ ^[0-9a-f]{64}$ ]] || fail "helper evidence has no included SHA-256"
  actual_sha="$(sha256_of "$helper")"
  [ "$recorded_sha" = "$actual_sha" ] \
    || fail "packaged helper bytes do not match the recorded evidence digest"
  recorded_bytes="$(plutil_raw "$evidence" includedBytes)"
  actual_bytes="$(/usr/bin/stat -f '%z' "$helper")"
  [ "$recorded_bytes" = "$actual_bytes" ] \
    || fail "packaged helper size does not match the recorded evidence"
  recorded_source="$(plutil_raw "$evidence" sourceSHA256)"
  [[ "$recorded_source" =~ ^[0-9a-f]{64}$ ]] || fail "helper evidence has no source SHA-256"
  minos="$(plutil_raw "$evidence" managerMinimumMacOS)"
  [[ "$minos" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || fail "helper evidence has no Manager minimum macOS"
  manager_binary="$app_path/$MANAGER_RELATIVE_PATH"
  validate_helper_macho "$helper" "$(manager_architectures "$manager_binary")" "$minos" >/dev/null

  /usr/bin/codesign --verify --strict "$helper" || fail "packaged helper signature does not verify"
  signature_is_adhoc "$helper"
  /usr/bin/codesign --verify --deep --strict "$app_path" \
    || fail "app bundle deep signature does not verify with the packaged helper"
  printf 'Verified development %s helper (sha256 %s) and app deep signature.\n' \
    "$HELPER_NAME" "$actual_sha"
}

assert_absent_helper() {
  require_absolute_path "--app" "$1"
  assert_absent_paths "$1"
  printf 'No development %s helper or evidence is present in %s.\n' "$HELPER_NAME" "$1"
}

COMMAND="${1:-}"
if [ -z "$COMMAND" ]; then
  usage >&2
  exit 2
fi
shift

SOURCE_PATH=""
APP_PATH=""
MANAGER_BINARY=""
MINIMUM_MACOS=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) [ "$#" -ge 2 ] || fail "--source requires a value"; SOURCE_PATH="$2"; shift 2 ;;
    --app) [ "$#" -ge 2 ] || fail "--app requires a value"; APP_PATH="$2"; shift 2 ;;
    --manager-binary) [ "$#" -ge 2 ] || fail "--manager-binary requires a value"; MANAGER_BINARY="$2"; shift 2 ;;
    --minimum-macos) [ "$#" -ge 2 ] || fail "--minimum-macos requires a value"; MINIMUM_MACOS="$2"; shift 2 ;;
    -h|--help|help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

case "$COMMAND" in
  check-source)
    [ -n "$SOURCE_PATH" ] || fail "check-source requires --source"
    [ -n "$MANAGER_BINARY" ] || fail "check-source requires --manager-binary"
    [ -n "$MINIMUM_MACOS" ] || fail "check-source requires --minimum-macos"
    check_source_helper "$SOURCE_PATH" "$MANAGER_BINARY" "$MINIMUM_MACOS"
    ;;
  package)
    [ -n "$SOURCE_PATH" ] || fail "package requires --source"
    [ -n "$APP_PATH" ] || fail "package requires --app"
    [ -n "$MINIMUM_MACOS" ] || fail "package requires --minimum-macos"
    package_helper "$SOURCE_PATH" "$APP_PATH" "$MINIMUM_MACOS"
    ;;
  verify)
    [ -n "$APP_PATH" ] || fail "verify requires --app"
    verify_helper "$APP_PATH"
    ;;
  assert-absent)
    [ -n "$APP_PATH" ] || fail "assert-absent requires --app"
    assert_absent_helper "$APP_PATH"
    ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
