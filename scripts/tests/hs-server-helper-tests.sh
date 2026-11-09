#!/bin/bash
# Regression tests for development hs-server helper packaging.
#
# Uses disposable app bundles and locally compiled fixture Mach-O files. It
# never installs, launches, inspects system state outside the scratch directory,
# or deletes pre-existing files.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HELPER_SCRIPT="$ROOT/scripts/hs-server-helper.sh"
SCRATCH="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/helicoid-helper-tests.XXXXXX")"
LOG="$SCRATCH/last-command.log"
PASS_COUNT=0

cleanup() { /bin/rm -rf "$SCRATCH"; }
trap cleanup EXIT

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf 'PASS: %s\n' "$1"; }

fail_test() {
  printf 'FAIL: %s\n' "$1" >&2
  [ ! -f "$LOG" ] || { printf '%s\n' '--- last command output ---' >&2; /bin/cat "$LOG" >&2; }
  exit 1
}

expect_success() {
  local description="$1"
  shift
  if ! "$@" >"$LOG" 2>&1; then fail_test "$description"; fi
  pass "$description"
}

expect_failure() {
  local description="$1"
  shift
  if "$@" >"$LOG" 2>&1; then fail_test "$description (command unexpectedly succeeded)"; fi
  pass "$description"
}

HOST_ARCH="$(/usr/bin/uname -m)"
case "$HOST_ARCH" in
  arm64) OTHER_ARCH="x86_64" ;;
  x86_64) OTHER_ARCH="arm64" ;;
  *) printf 'SKIP: unsupported host architecture %s\n' "$HOST_ARCH"; exit 0 ;;
esac

/bin/cat > "$SCRATCH/main.c" <<'C_EOF'
int main(void) { return 0; }
C_EOF

build_thin() {
  /usr/bin/xcrun clang -mmacosx-version-min="$3" -arch "$2" "$SCRATCH/main.c" -o "$1"
}

build_thin "$SCRATCH/valid-host" "$HOST_ARCH" "15.0"
build_thin "$SCRATCH/valid-other" "$OTHER_ARCH" "14.0"
build_thin "$SCRATCH/wrong-arch" "$OTHER_ARCH" "15.0"
/usr/bin/xcrun clang -dynamiclib -mmacosx-version-min=15.0 -arch "$HOST_ARCH" \
  "$SCRATCH/main.c" -o "$SCRATCH/library.dylib"
/bin/cp "$SCRATCH/valid-host" "$SCRATCH/non-executable"
/bin/chmod 644 "$SCRATCH/non-executable"
printf '#!/bin/sh\nexit 0\n' > "$SCRATCH/script"
/bin/chmod 755 "$SCRATCH/script"
: > "$SCRATCH/empty"
/bin/chmod 755 "$SCRATCH/empty"
/bin/ln -s "$SCRATCH/valid-host" "$SCRATCH/symlink"
/bin/mkdir "$SCRATCH/directory"

/usr/bin/xcrun vtool -set-build-version macos 16.0 26.0 -replace \
  -output "$SCRATCH/too-new" "$SCRATCH/valid-host"
/usr/bin/xcrun vtool -set-build-version ios 15.0 26.0 -replace \
  -output "$SCRATCH/ios-target" "$SCRATCH/valid-host"
/usr/bin/xcrun vtool -remove-build-version macos \
  -output "$SCRATCH/no-build-target" "$SCRATCH/valid-host"
/usr/bin/xcrun lipo -create "$SCRATCH/valid-host" "$SCRATCH/valid-other" \
  -output "$SCRATCH/universal-valid"
/usr/bin/xcrun lipo -create "$SCRATCH/valid-host" "$SCRATCH/valid-other" \
  -output "$SCRATCH/universal-bad"
/usr/bin/xcrun vtool -arch "$OTHER_ARCH" -set-build-version macos 16.0 26.0 \
  -replace -output "$SCRATCH/universal-too-new" "$SCRATCH/universal-bad"

new_app() {
  local app_path="$1"
  /bin/mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"
  /bin/cp "$SCRATCH/valid-host" "$app_path/Contents/MacOS/HelicoidManager"
  /bin/cat > "$app_path/Contents/Info.plist" <<'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>HelicoidManager</string>
  <key>CFBundleIdentifier</key><string>systems.helicoid.manager.dev.helper-test</string>
  <key>CFBundleName</key><string>Helper Test</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
</dict>
</plist>
PLIST_EOF
  if ! /usr/bin/codesign --force --sign - "$app_path" >"$LOG" 2>&1; then
    fail_test "could not ad-hoc sign fixture app: $app_path"
  fi
}

package_file() {
  "$HELPER_SCRIPT" package --source "$1" --app "$2" --minimum-macos 15.0
}

check_file() {
  "$HELPER_SCRIPT" check-source --source "$1" \
    --manager-binary "$2/Contents/MacOS/HelicoidManager" --minimum-macos 15.0
}

sha_of() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }

assert_evidence() {
  local app_path="$1" source_path="$2"
  local evidence="$app_path/Contents/Resources/hs-server-development.json"
  local helper="$app_path/Contents/Helpers/hs-server"
  [ -f "$helper" ] && [ -f "$evidence" ] || fail_test "helper or evidence missing"
  [ "$(/usr/bin/plutil -extract schema raw "$evidence")" = "1" ] || fail_test "evidence schema"
  [ "$(/usr/bin/plutil -extract path raw "$evidence")" = "Contents/Helpers/hs-server" ] || fail_test "evidence path"
  [ "$(/usr/bin/plutil -extract developmentOnly raw "$evidence")" = "true" ] || fail_test "developmentOnly"
  [ "$(/usr/bin/plutil -extract distributionSigned raw "$evidence")" = "false" ] || fail_test "distributionSigned"
  [ "$(/usr/bin/plutil -extract securityFloor raw "$evidence")" = "false" ] || fail_test "securityFloor"
  [ "$(/usr/bin/plutil -extract installationEnabled raw "$evidence")" = "false" ] || fail_test "installationEnabled"
  [ "$(/usr/bin/plutil -extract serviceEnabled raw "$evidence")" = "false" ] || fail_test "serviceEnabled"
  [ "$(/usr/bin/plutil -extract signature raw "$evidence")" = "ad-hoc" ] || fail_test "signature"
  [ "$(/usr/bin/plutil -extract includedSHA256 raw "$evidence")" = "$(sha_of "$helper")" ] || fail_test "included digest"
  [ "$(/usr/bin/plutil -extract includedBytes raw "$evidence")" = "$(/usr/bin/stat -f '%z' "$helper")" ] || fail_test "included bytes"
  [ "$(/usr/bin/plutil -extract sourceSHA256 raw "$evidence")" = "$(sha_of "$source_path")" ] || fail_test "source digest"
  pass "evidence is tied to the included bytes"
}

# Default state and source validation.
APP="$SCRATCH/Test Manager.app"
new_app "$APP"
expect_success "default app has no helper" \
  "$HELPER_SCRIPT" assert-absent --app "$APP"
expect_success "assert-absent accepts a not-yet-created app path" \
  "$HELPER_SCRIPT" assert-absent --app "$SCRATCH/Fresh.app"
expect_success "check-source accepts a valid helper" \
  check_file "$SCRATCH/valid-host" "$APP"
expect_failure "check-source rejects a missing helper" \
  check_file "$SCRATCH/missing" "$APP"
expect_failure "check-source rejects a wrong-architecture helper" \
  check_file "$SCRATCH/wrong-arch" "$APP"
expect_failure "check-source rejects a too-new helper" \
  check_file "$SCRATCH/too-new" "$APP"

# Successful packaging and verification.
SOURCE_SHA_BEFORE="$(sha_of "$SCRATCH/valid-host")"
expect_success "packages a compatible helper" \
  package_file "$SCRATCH/valid-host" "$APP"
expect_failure "verify refuses before the app is signed" \
  "$HELPER_SCRIPT" verify --app "$APP"
expect_success "sign app after packaging" \
  /usr/bin/codesign --force --sign - "$APP"
expect_success "verify accepts helper and app deep signature" \
  "$HELPER_SCRIPT" verify --app "$APP"
assert_evidence "$APP" "$SCRATCH/valid-host"
[ "$SOURCE_SHA_BEFORE" = "$(sha_of "$SCRATCH/valid-host")" ] \
  || fail_test "packaging modified the source helper"
pass "packaging does not modify the source helper"

UNIVERSAL_APP="$SCRATCH/Universal.app"
new_app "$UNIVERSAL_APP"
expect_success "packages a universal helper containing the Manager architecture" \
  package_file "$SCRATCH/universal-valid" "$UNIVERSAL_APP"
expect_success "sign universal app" \
  /usr/bin/codesign --force --sign - "$UNIVERSAL_APP"
expect_success "verify universal helper" \
  "$HELPER_SCRIPT" verify --app "$UNIVERSAL_APP"

ODD_SOURCE="$SCRATCH/helper \$(touch injected).bin"
/bin/cp "$SCRATCH/valid-host" "$ODD_SOURCE"
ODD_APP="$SCRATCH/Odd Helper.app"
new_app "$ODD_APP"
expect_success "packages a path containing shell metacharacters" \
  package_file "$ODD_SOURCE" "$ODD_APP"
[ ! -e "$SCRATCH/injected" ] || fail_test "source path was evaluated by the shell"
pass "source path metacharacters are never evaluated"

# Invalid requested helpers fail without touching existing output.
INVALID_APP="$SCRATCH/Invalid.app"
new_app "$INVALID_APP"
for spec in \
  "missing:$SCRATCH/missing" \
  "relative:valid-host" \
  "empty::$SCRATCH/empty" \
  "directory:$SCRATCH/directory" \
  "symlink:$SCRATCH/symlink" \
  "non-executable:$SCRATCH/non-executable" \
  "shell-script:$SCRATCH/script" \
  "dylib:$SCRATCH/library.dylib" \
  "wrong-architecture:$SCRATCH/wrong-arch" \
  "too-new:$SCRATCH/too-new" \
  "universal-too-new:$SCRATCH/universal-too-new" \
  "non-macOS:$SCRATCH/ios-target" \
  "missing-deployment-target:$SCRATCH/no-build-target"
do
  label="${spec%%:*}"
  source_path="${spec#*:}"
  expect_failure "$label helper fails" package_file "$source_path" "$INVALID_APP"
done
expect_success "failed requests leave no helper behind" \
  "$HELPER_SCRIPT" assert-absent --app "$INVALID_APP"

# Existing artifacts are refused and preserved, never replaced or deleted.
CONFLICT_APP="$SCRATCH/Conflict.app"
new_app "$CONFLICT_APP"
expect_success "prepare existing helper artifacts" \
  package_file "$SCRATCH/valid-host" "$CONFLICT_APP"
CONFLICT_HELPER="$CONFLICT_APP/Contents/Helpers/hs-server"
CONFLICT_EVIDENCE="$CONFLICT_APP/Contents/Resources/hs-server-development.json"
CONFLICT_HELPER_SHA="$(sha_of "$CONFLICT_HELPER")"
CONFLICT_EVIDENCE_SHA="$(sha_of "$CONFLICT_EVIDENCE")"
expect_failure "package refuses an existing helper" \
  package_file "$SCRATCH/valid-host" "$CONFLICT_APP"
[ "$CONFLICT_HELPER_SHA" = "$(sha_of "$CONFLICT_HELPER")" ] \
  || fail_test "existing helper was replaced"
[ "$CONFLICT_EVIDENCE_SHA" = "$(sha_of "$CONFLICT_EVIDENCE")" ] \
  || fail_test "existing evidence was replaced"
pass "existing helper and evidence are preserved"
expect_failure "assert-absent refuses existing helper" \
  "$HELPER_SCRIPT" assert-absent --app "$CONFLICT_APP"
[ -f "$CONFLICT_HELPER" ] || fail_test "assert-absent deleted the existing helper"
pass "assert-absent does not delete existing artifacts"
expect_failure "invalid request cannot disturb an existing helper" \
  package_file "$SCRATCH/too-new" "$CONFLICT_APP"
[ "$CONFLICT_HELPER_SHA" = "$(sha_of "$CONFLICT_HELPER")" ] \
  || fail_test "invalid request changed the existing helper"
pass "invalid request leaves the existing helper intact"

EVIDENCE_APP="$SCRATCH/EvidenceOnly.app"
new_app "$EVIDENCE_APP"
/bin/mkdir -p "$EVIDENCE_APP/Contents/Resources"
printf '{"stale":true}\n' > "$EVIDENCE_APP/Contents/Resources/hs-server-development.json"
EVIDENCE_SHA="$(sha_of "$EVIDENCE_APP/Contents/Resources/hs-server-development.json")"
expect_failure "package refuses pre-existing evidence" \
  package_file "$SCRATCH/valid-host" "$EVIDENCE_APP"
[ "$EVIDENCE_SHA" = "$(sha_of "$EVIDENCE_APP/Contents/Resources/hs-server-development.json")" ] \
  || fail_test "pre-existing evidence was replaced"
[ ! -e "$EVIDENCE_APP/Contents/Helpers/hs-server" ] \
  || fail_test "partially packaged helper was left behind"
pass "pre-existing evidence is preserved"
expect_failure "assert-absent refuses pre-existing evidence" \
  "$HELPER_SCRIPT" assert-absent --app "$EVIDENCE_APP"
[ "$EVIDENCE_SHA" = "$(sha_of "$EVIDENCE_APP/Contents/Resources/hs-server-development.json")" ] \
  || fail_test "assert-absent changed pre-existing evidence"
pass "assert-absent does not change pre-existing evidence"

# A symlinked bundle directory is refused instead of writing through it.
SYMLINK_APP="$SCRATCH/Symlink.app"
new_app "$SYMLINK_APP"
/bin/rm -rf "$SYMLINK_APP/Contents/Resources"
/bin/mkdir "$SCRATCH/symlink-target"
/bin/ln -s "$SCRATCH/symlink-target" "$SYMLINK_APP/Contents/Resources"
expect_failure "refuses a symlinked bundle resource directory" \
  package_file "$SCRATCH/valid-host" "$SYMLINK_APP"
[ ! -e "$SCRATCH/symlink-target/hs-server-development.json" ] \
  || fail_test "package wrote through a symlinked bundle directory"
pass "symlinked bundle directory is not written through"

# A failed commit rolls back only files created by this run.
ROLLBACK_APP="$SCRATCH/Rollback.app"
new_app "$ROLLBACK_APP"
/bin/chmod 555 "$ROLLBACK_APP/Contents/Resources"
expect_failure "failed commit rolls back the linked helper" \
  package_file "$SCRATCH/valid-host" "$ROLLBACK_APP"
/bin/chmod 755 "$ROLLBACK_APP/Contents/Resources"
[ ! -e "$ROLLBACK_APP/Contents/Helpers/hs-server" ] \
  || fail_test "failed commit left a newly created helper"
[ ! -e "$ROLLBACK_APP/Contents/Resources/hs-server-development.json" ] \
  || fail_test "failed commit left newly created evidence"
pass "failed commit rolls back only newly created files"

# Tampering is refused.
TAMPER_APP="$SCRATCH/Tamper.app"
new_app "$TAMPER_APP"
expect_success "prepare digest tamper fixture" package_file "$SCRATCH/valid-host" "$TAMPER_APP"
expect_success "sign digest tamper fixture" /usr/bin/codesign --force --sign - "$TAMPER_APP"
TAMPER_EVIDENCE="$TAMPER_APP/Contents/Resources/hs-server-development.json"
TAMPER_DIGEST="$(/usr/bin/plutil -extract includedSHA256 raw "$TAMPER_EVIDENCE")"
/usr/bin/sed -i '' "s/$TAMPER_DIGEST/0000000000000000000000000000000000000000000000000000000000000000/" "$TAMPER_EVIDENCE"
expect_success "re-sign tampered evidence" /usr/bin/codesign --force --sign - "$TAMPER_APP"
expect_failure "tampered evidence digest fails verification" \
  "$HELPER_SCRIPT" verify --app "$TAMPER_APP"

BYTE_APP="$SCRATCH/Byte.app"
new_app "$BYTE_APP"
expect_success "prepare byte tamper fixture" package_file "$SCRATCH/valid-host" "$BYTE_APP"
expect_success "sign byte tamper fixture" /usr/bin/codesign --force --sign - "$BYTE_APP"
printf 'tamper' >> "$BYTE_APP/Contents/Helpers/hs-server"
expect_failure "tampered helper bytes fail verification" \
  "$HELPER_SCRIPT" verify --app "$BYTE_APP"

if /usr/bin/find "$SCRATCH" -maxdepth 1 -type d -name '.hs-server-helper.*' -print -quit | /usr/bin/grep -q .; then
  fail_test "staging directory was left behind"
fi
pass "no staging directory was left behind"

printf '\n%s development hs-server helper packaging tests passed.\n' "$PASS_COUNT"
