#!/bin/bash
# Build and package Helicoid Manager and Helicoid Computer.
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

BIN="$BUILD_DIR/release"
mkdir -p "$DIST_DIR"

package_app() {
  local name="$1"
  local binary="$2"
  local bundle_id="$3"
  local icon_source="$4"
  local app="$DIST_DIR/$name.app"

  echo "== Packaging $name =="
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  cp "$BIN/$binary" "$app/Contents/MacOS/$binary"
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
  <string>15.0</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.utilities</string>
  <key>NSHumanReadableCopyright</key>
  <string>Helicoid Systems</string>
</dict>
</plist>
PLIST

  # Independent brand resources (copied source; V51 native icon compilation is NOT claimed here).
  if [ -d "$ROOT/Sources/$binary/Resources/Brand" ]; then
    cp -R "$ROOT/Sources/$binary/Resources/Brand" "$app/Contents/Resources/"
  fi

  # Approved icon compile from this tree's bundled exact copy (no /tmp dependency).
  # Proven actool invocation uses the icon name without the .icon extension:
  #   --target-device mac --app-icon 'HS Manager App icon'
  local icon_dir="$ROOT/Sources/$binary/Resources/Brand/$icon_source"
  if [ -d "$icon_dir" ]; then
    local icon_name="${icon_source%.icon}"
    local icon_out
    icon_out="$(mktemp -d "$BUILD_DIR/icon-$binary-XXXXXX")"
    local partial_plist="$icon_out/Info.plist"
    if xcrun actool "$icon_dir" \
        --compile "$icon_out" \
        --platform macosx \
        --minimum-deployment-target 15.0 \
        --target-device mac \
        --app-icon "$icon_name" \
        --output-partial-info-plist "$partial_plist" \
        >"$icon_out/actool.log" 2>&1; then
      local car_ok=0 icns_ok=0
      if [ -f "$icon_out/Assets.car" ]; then
        cp "$icon_out/Assets.car" "$app/Contents/Resources/Assets.car"
        echo "actool Assets.car: $(wc -c < "$app/Contents/Resources/Assets.car") bytes"
        car_ok=1
      else
        echo "ERROR: actool did not emit Assets.car for $icon_source (see $icon_out/actool.log)"
      fi
      local icns
      icns="$(find "$icon_out" -maxdepth 1 -name '*.icns' | head -1 || true)"
      if [ -n "$icns" ]; then
        cp "$icns" "$app/Contents/Resources/AppIcon.icns"
        /usr/bin/plutil -replace CFBundleIconFile -string "AppIcon" "$app/Contents/Info.plist"
        echo "actool icns: $(basename "$icns") ($(wc -c < "$app/Contents/Resources/AppIcon.icns") bytes)"
        icns_ok=1
      else
        echo "ERROR: actool did not emit .icns for $icon_source (see $icon_out/actool.log)"
      fi
      if [ "$car_ok" -ne 1 ] || [ "$icns_ok" -ne 1 ]; then
        echo "ERROR: packaging $name failed — compiled icon outputs missing. Not claiming icon success."
        return 1
      fi
    else
      echo "actool failed for $icon_source (see $icon_out/actool.log)"
      echo "Brand sources remain bundled. Full display/fallback matrix is NOT claimed."
    fi
  fi

  echo "Packaged $app"
  return 0
}

# Working identifiers only — durable release package IDs await B01.
package_app "Helicoid Manager" "HelicoidManager" \
  "systems.helicoid.manager.dev" \
  "HS Manager App icon.icon"

package_app "Helicoid Computer" "HelicoidComputer" \
  "systems.helicoid.computer.dev" \
  "HS App icon.icon"

echo "== Done. Apps in $DIST_DIR =="
