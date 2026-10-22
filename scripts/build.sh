#!/bin/bash
# Build and package the legacy Helicoid Manager and retained Computer app.
# Independent of sibling repositories: only reads under apps/macos.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${HELICOID_BUILD_DIR:-$ROOT/.build}"
DIST_DIR="${HELICOID_DIST_DIR:-$ROOT/dist}"
DERIVED="$BUILD_DIR/DerivedData"

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
  local app="$DIST_DIR/$name.app"

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
  /usr/bin/codesign --force --sign - "$app"
  /usr/bin/codesign --verify --deep --strict "$app"

  echo "Packaged $app"
  return 0
}

# Working identifiers only — durable release package IDs await B01.
package_app "Helicoid Manager" "HelicoidManager" \
  "systems.helicoid.manager.dev" \
  "HS Manager App icon.icon" \
  "$MANAGER_BIN" "15.0"

package_app "Helicoid Computer" "HelicoidComputer" \
  "systems.helicoid.computer.dev" \
  "HS App icon.icon" \
  "$COMPUTER_BIN" "13.0"

echo "== Done. Apps in $DIST_DIR =="
