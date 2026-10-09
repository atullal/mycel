#!/usr/bin/env bash
# Build the Mycel app for iPhone and iPad and copy it into dist-release/.
#
#   scripts/package-ios.sh                    # device build: signed .ipa
#   scripts/package-ios.sh --install [NAME]   # ...and install it on a connected
#                                             #    iPhone/iPad (default: the first one)
#   scripts/package-ios.sh --simulator        # Simulator build (.app, unsigned)
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
  -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  *) echo "unknown option: $1 (use --install, --simulator or nothing)" >&2; exit 2 ;;
esac

command -v xcodebuild >/dev/null || { echo "Xcode not found: install it from the App Store" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }
cargo tauri --version >/dev/null 2>&1 || { echo "cargo-tauri not found: cargo install tauri-cli --version '^2' --locked" >&2; exit 1; }
# swift-rs needs llvm-objcopy to link Tauri's Swift code with Xcode 27+
# (vendor/swift-rs/MYCEL_PATCH.md).
rustup component add llvm-tools >/dev/null 2>&1 || true

cd "$ROOT"
[ -d node_modules ] || npm install

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
