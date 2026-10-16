#!/usr/bin/env bash
# Build the Mycel app for iPhone and iPad and copy it into dist-release/.
#
#   scripts/package-ios.sh                    # device build: signed .ipa
#   scripts/package-ios.sh --install [NAME]   # ...and install it on a connected
#                                             #    iPhone/iPad (default: the first one)
#   scripts/package-ios.sh --simulator        # Simulator build (.app, unsigned)
#   scripts/package-ios.sh --unsigned         # unsigned device .ipa, for re-signing
#                                             #    (Sideloadly, AltStore, `codesign`)
#   scripts/package-ios.sh --testflight N     # archive with build number N (higher
#                                             #    than the last upload) and open it in
#                                             #    Xcode's Organizer to upload to TestFlight
#
# Device builds are signed with the Apple development team in
# apps/host/src-tauri/tauri.conf.json (bundle > iOS > developmentTeam). Xcode
# must be signed in to that team (Xcode > Settings > Accounts) so it can make
# the provisioning profile; with a free Apple ID the app runs for 7 days and
# only on devices connected to this Mac. The first launch on a device needs
# Settings > General > VPN & Device Management > trust the developer.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE=device
INSTALL=""
DEVICE=""
case "${1:-}" in
  "") ;;
  --install) INSTALL=1; DEVICE="${2:-}" ;;
  --simulator) MODE=simulator ;;
  --unsigned) MODE=unsigned ;;
  --testflight) MODE=testflight; BUILD="${2:-}" ;;
  -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
  *) echo "unknown option: $1 (use --install, --simulator, --unsigned, --testflight N or nothing)" >&2; exit 2 ;;
esac

command -v xcodebuild >/dev/null || { echo "Xcode not found: install it from the App Store" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }
cargo tauri --version >/dev/null 2>&1 || { echo "cargo-tauri not found: cargo install tauri-cli --version '^2' --locked" >&2; exit 1; }
# swift-rs needs llvm-objcopy to link Tauri's Swift code with Xcode 27+
# (vendor/swift-rs/MYCEL_PATCH.md).
rustup component add llvm-tools >/dev/null 2>&1 || true

cd "$ROOT"
[ -d node_modules ] || npm install
# Keep this machine's paths (home directory, Cargo registry, toolchain) out of
# the binaries.
source "$ROOT/scripts/remap-paths.sh"

VERSION="$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$ROOT/apps/host/src-tauri/tauri.conf.json" | head -1)"
OUT="$ROOT/dist-release"
APPLE="$ROOT/apps/host/src-tauri/gen/apple"
mkdir -p "$OUT"
# Tauri moves the archived app into build/<arch>/ and fails if an older one
# is there ("Directory not empty"), or leaves the older one in place.
rm -rf "$APPLE/build"

if [ "$MODE" = simulator ]; then
  rustup target add aarch64-apple-ios-sim >/dev/null
  (cd apps/host && cargo tauri ios build --target aarch64-sim)
  APP="$APPLE/build/arm64-sim/Mycel.app"
  [ -d "$APP" ] || { echo "no Simulator build found" >&2; exit 1; }
  rm -rf "$OUT/ios-simulator/Mycel.app" && mkdir -p "$OUT/ios-simulator"
  ditto "$APP" "$OUT/ios-simulator/Mycel.app"
  echo
  echo "Built $OUT/ios-simulator/Mycel.app"
  echo "Install: xcrun simctl install booted \"$OUT/ios-simulator/Mycel.app\""
  exit 0
fi

rustup target add aarch64-apple-ios >/dev/null
if [ "$MODE" = unsigned ]; then
  (cd apps/host && cargo tauri ios build --target aarch64 --no-sign --archive-only)
  APP="$APPLE/build/mycel-host_iOS.xcarchive/Products/Applications/Mycel.app"
  [ -d "$APP" ] || { echo "no archive found" >&2; exit 1; }
  STAGE="$(mktemp -d)"
  trap 'rm -rf "$STAGE"' EXIT
  mkdir "$STAGE/Payload" && ditto "$APP" "$STAGE/Payload/Mycel.app"
  DEST="$OUT/Mycel_${VERSION}_ios-unsigned.ipa"
  rm -f "$DEST"
  (cd "$STAGE" && zip -qry "$DEST" Payload)
  echo
  echo "Built $DEST ($(du -h "$DEST" | cut -f1)), unsigned: re-sign it to install."
  exit 0
fi
if [ "$MODE" = testflight ]; then
  # The command line can't upload: Xcode 27's account sign-in doesn't reach
  # xcodebuild. So archive here (development-signed), and Xcode's Organizer
  # re-signs it for the App Store and uploads it.
  case "$BUILD" in
    '' | *[!0-9]*) echo "give a build number higher than the last upload, e.g. --testflight 2" >&2; exit 2 ;;
  esac
  (cd apps/host && cargo tauri ios build --target aarch64 --archive-only --build-number "$BUILD")
  ARCHIVE="$APPLE/build/mycel-host_iOS.xcarchive"
  [ -d "$ARCHIVE" ] || { echo "no archive found" >&2; exit 1; }
  # where the Organizer lists archives (a fresh name each time: the
  # Organizer caches an archive's details by its path)
  DEST="$HOME/Library/Developer/Xcode/Archives/$(date +%Y-%m-%d)/Mycel $VERSION ($BUILD) $(date +%H.%M.%S).xcarchive"
  mkdir -p "$(dirname "$DEST")" && rm -rf "$DEST" && ditto "$ARCHIVE" "$DEST"
  open "$DEST"
  echo
  echo "Archived $DEST"
  echo "In Xcode's Organizer: select it > Distribute App > TestFlight Internal Only > Distribute."
  exit 0
fi

(cd apps/host && cargo tauri ios build --target aarch64 --export-method debugging)
IPA="$(ls -t "$APPLE"/build/arm64/*.ipa 2>/dev/null | head -1)"
[ -f "$IPA" ] || { echo "no .ipa produced (see the Xcode output above)" >&2; exit 1; }
DEST="$OUT/Mycel_${VERSION}_ios.ipa"
cp "$IPA" "$DEST"
echo
echo "Built $DEST ($(du -h "$DEST" | cut -f1))"

if [ -n "$INSTALL" ]; then
  if [ -z "$DEVICE" ]; then
    # First paired physical device.
    DEVICE="$(xcrun devicectl list devices 2>/dev/null | awk '/physical/ && /available/ {print $0}' | grep -oE '[0-9A-F]{8}-[0-9A-F]{16}' | head -1)"
    [ -n "$DEVICE" ] || { echo "no connected iPhone/iPad found (xcrun devicectl list devices)" >&2; exit 1; }
  fi
  xcrun devicectl device install app --device "$DEVICE" "$DEST"
fi
