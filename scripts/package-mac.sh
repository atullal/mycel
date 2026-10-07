#!/usr/bin/env bash
# Build the Mycel macOS app (.app + .dmg) and copy it into dist-release/.
#
#   scripts/package-mac.sh              # this Mac's architecture (arm64 or x86_64)
#   scripts/package-mac.sh --universal  # one app that runs on Apple silicon AND Intel Macs
#
# The app is unsigned. See docs/TWO_LAPTOPS.md for how to open it on another Mac.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=""
case "${1:-}" in
  "") ;;
  --universal) TARGET="universal-apple-darwin" ;;
  -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
  *) echo "unknown option: $1 (use --universal or nothing)" >&2; exit 2 ;;
esac

command -v cargo >/dev/null || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }
cargo tauri --version >/dev/null 2>&1 || { echo "cargo-tauri not found: cargo install tauri-cli --version '^2' --locked" >&2; exit 1; }

cd "$ROOT"
# Frontend deps (the frontend itself is built by tauri.conf.json's beforeBuildCommand).
[ -d node_modules ] || npm install

cd "$ROOT/apps/host"
if [ -n "$TARGET" ]; then
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  cargo tauri build --bundles app --target "$TARGET"
  BUNDLE="$ROOT/target/$TARGET/release/bundle"
  LABEL="universal"
else
  cargo tauri build --bundles app
  BUNDLE="$ROOT/target/release/bundle"
  case "$(uname -m)" in arm64) LABEL="aarch64" ;; x86_64) LABEL="x64" ;; *) LABEL="$(uname -m)" ;; esac
fi

VERSION="$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$ROOT/apps/host/src-tauri/tauri.conf.json" | head -1)"
OUT="$ROOT/dist-release"
mkdir -p "$OUT/$LABEL"
rm -rf "$OUT/$LABEL/Mycel.app"
ditto "$BUNDLE/macos/Mycel.app" "$OUT/$LABEL/Mycel.app"
# A zip of the .app is the easiest thing to AirDrop / copy on a USB stick.
rm -f "$OUT/Mycel_${VERSION}_${LABEL}.app.zip"
ditto -c -k --keepParent "$BUNDLE/macos/Mycel.app" "$OUT/Mycel_${VERSION}_${LABEL}.app.zip"
# Plain drag-to-Applications disk image. (Tauri's own dmg bundler drives Finder
# with AppleScript, which fails without Automation permission / in headless shells.)
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ditto "$BUNDLE/macos/Mycel.app" "$STAGE/Mycel.app"
ln -s /Applications "$STAGE/Applications"
DMG="$OUT/Mycel_${VERSION}_${LABEL}.dmg"
rm -f "$DMG"
hdiutil create -quiet -volname "Mycel" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG"

echo
echo "Built Mycel $VERSION ($LABEL):"
ls -lh "$OUT" "$OUT/$LABEL"
lipo -archs "$OUT/$LABEL/Mycel.app/Contents/MacOS/"* 2>/dev/null || true
