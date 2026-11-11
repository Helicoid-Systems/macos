#!/bin/bash
# Build and package the legacy Helicoid Manager and retained Computer app.
# Independent of sibling repositories: only reads under apps/macos, except for
# optional operator-supplied development hs-server artifacts (see README).
#
# Development install bundle (disposable machines only):
#   HELICOID_HS_SERVER_PATH=/abs/hs-server
#   HELICOID_HS_SERVER_DEVELOPMENT_PACKAGE_DIR=/abs/signed-macos-package
#   HELICOID_MACOS_DEV_TRUST_KEY=<64-hex build-pinned key>
# A helper without a package remains development packaging only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${HELICOID_BUILD_DIR:-$ROOT/.build}"
DIST_DIR="${HELICOID_DIST_DIR:-$ROOT/dist}"
case "$DIST_DIR" in
  /*) ;;
  *) DIST_DIR="$ROOT/$DIST_DIR" ;;
esac
DERIVED="$BUILD_DIR/DerivedData"
MANAGER_MINIMUM_MACOS="15.0"

HS_SERVER_HELPER_SOURCE=""
if [ -n "${HELICOID_HS_SERVER_PATH+x}" ]; then
  HS_SERVER_HELPER_SOURCE="${HELICOID_HS_SERVER_PATH}"
  if [ -z "$HS_SERVER_HELPER_SOURCE" ]; then
    echo "ERROR: HELICOID_HS_SERVER_PATH is set but empty. Unset it for a no-helper build." >&2
    exit 1
  fi
  case "$HS_SERVER_HELPER_SOURCE" in
    /*) ;;
    *)
      echo "ERROR: HELICOID_HS_SERVER_PATH must be an absolute path." >&2
      exit 1
      ;;
  esac
fi

HS_SERVER_DEVELOPMENT_PACKAGE_DIR=""
HS_SERVER_DEVELOPMENT_TRUST_KEY=""
if [ -n "${HELICOID_HS_SERVER_DEVELOPMENT_PACKAGE_DIR+x}" ]; then
  HS_SERVER_DEVELOPMENT_PACKAGE_DIR="${HELICOID_HS_SERVER_DEVELOPMENT_PACKAGE_DIR:-}"
  HS_SERVER_DEVELOPMENT_TRUST_KEY="${HELICOID_MACOS_DEV_TRUST_KEY:-}"
  if [ -z "$HS_SERVER_DEVELOPMENT_PACKAGE_DIR" ] \
    || [ -z "$HS_SERVER_DEVELOPMENT_TRUST_KEY" ]; then
    echo "ERROR: development install requires both HELICOID_HS_SERVER_DEVELOPMENT_PACKAGE_DIR and HELICOID_MACOS_DEV_TRUST_KEY." >&2
    exit 1
  fi
  if [ -z "$HS_SERVER_HELPER_SOURCE" ]; then
    echo "ERROR: development install requires HELICOID_HS_SERVER_PATH to the matching macos-dev-install helper." >&2
    exit 1
  fi
  case "$HS_SERVER_DEVELOPMENT_PACKAGE_DIR" in
    /*) ;;
    *)
      echo "ERROR: HELICOID_HS_SERVER_DEVELOPMENT_PACKAGE_DIR must be an absolute path." >&2
      exit 1
      ;;
  esac
  if ! printf '%s' "$HS_SERVER_DEVELOPMENT_TRUST_KEY" \
    | /usr/bin/grep -Eq '^[0-9a-fA-F]{64}$'; then
    echo "ERROR: HELICOID_MACOS_DEV_TRUST_KEY must be 64 hex characters." >&2
    exit 1
  fi
fi

echo "== Helicoid macOS build =="
echo "Root: $ROOT"
echo "Swift: $(xcrun swift --version | head -1)"

cd "$ROOT"

echo "== swift test (HelicoidCoreTests) =="
xcrun swift test \
  --scratch-path "$BUILD_DIR" \
  --package-path "$ROOT"

echo "== swift build (release) =="
xcrun swift build \
  -c release \
  --scratch-path "$BUILD_DIR" \
  --package-path "$ROOT"

MANAGER_BIN="$(xcrun swift build \
  --configuration release \
  --show-bin-path \
  --scratch-path "$BUILD_DIR" \
  --package-path "$ROOT")"
if [ -n "$HS_SERVER_HELPER_SOURCE" ]; then
  "$ROOT/scripts/hs-server-helper.sh" check-source \
    --source "$HS_SERVER_HELPER_SOURCE" \
    --manager-binary "$MANAGER_BIN/HelicoidManager" \
    --minimum-macos "$MANAGER_MINIMUM_MACOS"
fi
COMPUTER_BUILD_DIR="$BUILD_DIR/computer-macos13"
HOST_ARCH="$(uname -m)"
echo "== swift build (Computer, macOS 13 deployment target) =="
xcrun swift build \
  -c release \
  --scratch-path "$COMPUTER_BUILD_DIR" \
  --package-path "$ROOT/Sources" \
  --triple "$HOST_ARCH-apple-macosx13.0" \
  --product HelicoidComputer

COMPUTER_BIN="$(xcrun swift build \
  --configuration release \
  --show-bin-path \
  --scratch-path "$COMPUTER_BUILD_DIR" \
  --package-path "$ROOT/Sources" \
  --triple "$HOST_ARCH-apple-macosx13.0" \
  --product HelicoidComputer)"
mkdir -p "$DIST_DIR"

package_app() {
  local name="$1"
  local binary="$2"
  local bundle_id="$3"
  local icon_source="$4"
  local binary_dir="$5"
  local minimum_system_version="$6"
  local helper_source="${7:-}"
  local app="$DIST_DIR/$name.app"

  if [ "$binary" = "HelicoidManager" ]; then
    # Refuse pre-existing development helper artifacts before touching the app.
    "$ROOT/scripts/hs-server-helper.sh" assert-absent --app "$app"
  fi

  echo "== Packaging $name =="
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  cp "$binary_dir/$binary" "$app/Contents/MacOS/$binary"
  chmod +x "$app/Contents/MacOS/$binary"

  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>$name</string>
  <key>CFBundleDisplayName</key>
  <string>$name</string>
  <key>CFBundleExecutable</key>
  <string>$binary</string>
  <key>CFBundleIdentifier</key>
  <string>$bundle_id</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>$minimum_system_version</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.utilities</string>
  <key>NSHumanReadableCopyright</key>
  <string>Helicoid Systems</string>
</dict>
</plist>
PLIST

  # Keep the independent SwiftPM resource bundle available inside the app.
  local resource_bundle="$binary_dir/HelicoidMac_${binary}.bundle"
  if [ -d "$resource_bundle" ]; then
    cp -R "$resource_bundle" "$app/Contents/Resources/"
  fi
  cp -R "$ROOT/Sources/$binary/Resources/Brand" "$app/Contents/Resources/"

  local icon_dir="$ROOT/Sources/$binary/Resources/Brand/$icon_source"
  local icon_name="${icon_source%.icon}"
  local icon_out
  icon_out="$(mktemp -d "$BUILD_DIR/icon-$binary-XXXXXX")"
  local compiled=0
  if [ "${HELICOID_FORCE_ICON_FALLBACK:-0}" != 1 ]; then
    if xcrun actool "$icon_dir" \
        --compile "$icon_out" \
        --platform macosx \
        --minimum-deployment-target "$minimum_system_version" \
        --target-device mac \
        --app-icon "$icon_name" \
        --output-partial-info-plist "$icon_out/Info.plist" \
        >"$icon_out/actool.log" 2>&1; then
      if [ -s "$icon_out/Assets.car" ] && [ -s "$icon_out/$icon_name.icns" ]; then
        cp "$icon_out/Assets.car" "$app/Contents/Resources/Assets.car"
        cp "$icon_out/$icon_name.icns" "$app/Contents/Resources/AppIcon.icns"
        compiled=1
        echo "Compiled layered icon and .icns: $icon_source"
      fi
    else
      cat "$icon_out/actool.log" >&2
    fi
  fi
  if [ "$compiled" != 1 ]; then
    local role="Computer"
    if [ "$binary" = HelicoidManager ]; then role="Manager"; fi
    local fallback="$ROOT/Resources/Brand/CompiledFallback/$role.icns"
    local provenance="$ROOT/Resources/Brand/CompiledFallback/PROVENANCE.json"
    local file_index=1
    if [ "$role" = Manager ]; then file_index=0; fi
    local expected actual
    expected="$(plutil -extract "files.$file_index.sha256" raw "$provenance")"
    actual="$(shasum -a 256 "$fallback" | awk '{print $1}')"
    if [ ! -s "$fallback" ] || [ "$actual" != "$expected" ]; then
      echo "ERROR: approved icon fallback missing or checksum mismatch" >&2
      return 1
    fi
    cp "$fallback" "$app/Contents/Resources/AppIcon.icns"
    echo "Packaged verified artwork fallback: $role.icns"
  fi
  /usr/bin/plutil -replace CFBundleIconFile -string AppIcon "$app/Contents/Info.plist"
  if [ "$binary" = "HelicoidManager" ]; then
    if [ -n "$HS_SERVER_DEVELOPMENT_PACKAGE_DIR" ]; then
      "$ROOT/scripts/hs-server-development-bundle.sh" package \
        --helper "$helper_source" \
        --package-dir "$HS_SERVER_DEVELOPMENT_PACKAGE_DIR" \
        --trust-key "$HS_SERVER_DEVELOPMENT_TRUST_KEY" \
        --app "$app" \
        --minimum-macos "$minimum_system_version"
    elif [ -n "$helper_source" ]; then
      "$ROOT/scripts/hs-server-helper.sh" package \
        --source "$helper_source" \
        --app "$app" \
        --minimum-macos "$minimum_system_version"
    fi
  fi
  /usr/bin/codesign --force --sign - "$app"
  /usr/bin/codesign --verify --deep --strict "$app"

  if [ "$binary" = "HelicoidManager" ]; then
    if [ -n "$HS_SERVER_DEVELOPMENT_PACKAGE_DIR" ]; then
      "$ROOT/scripts/hs-server-development-bundle.sh" verify --app "$app"
    elif [ -n "$helper_source" ]; then
      "$ROOT/scripts/hs-server-helper.sh" verify --app "$app"
    else
      "$ROOT/scripts/hs-server-helper.sh" assert-absent --app "$app"
    fi
  fi

  echo "Packaged $app"
  return 0
}

# Working identifiers only — durable release package IDs await B01.
package_app "Helicoid Manager" "HelicoidManager" \
  "systems.helicoid.manager.dev" \
  "HS Manager App icon.icon" \
  "$MANAGER_BIN" "$MANAGER_MINIMUM_MACOS" "$HS_SERVER_HELPER_SOURCE"

package_app "Helicoid Computer" "HelicoidComputer" \
  "systems.helicoid.computer.dev" \
  "HS App icon.icon" \
  "$COMPUTER_BIN" "13.0"

if [ -n "$HS_SERVER_DEVELOPMENT_PACKAGE_DIR" ]; then
  echo "== DEVELOPMENT-ONLY pinned hs-server install payload included in Manager =="
  echo "== Not a release trust root, notarization, or production acceptance =="
elif [ -n "$HS_SERVER_HELPER_SOURCE" ]; then
  echo "== Development hs-server helper included in Manager (install disabled) =="
fi
echo "== Done. Apps in $DIST_DIR =="
