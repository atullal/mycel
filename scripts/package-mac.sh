#!/usr/bin/env bash
# Build the Mycel macOS app (.app + .dmg) and copy it into dist-release/.
#
#   scripts/package-mac.sh              # this Mac's architecture (arm64 or x86_64)
#   scripts/package-mac.sh --universal  # one app that runs on Apple silicon AND Intel Macs
#
# By default the app is unsigned (docs/USER_GUIDE.md says how to open it on
# another Mac). To sign it with a Developer ID and have Apple notarise it, so
# that it opens anywhere without a warning, set:
#
#   MYCEL_SIGN_IDENTITY    "Developer ID Application: Name (TEAMID)"
#   MYCEL_SIGN_KEYCHAIN    the keychain file that holds it (default: your own)
#
# and, to notarise as well, one of:
#
#   MYCEL_NOTARY_PROFILE   a profile saved with `xcrun notarytool store-credentials`
#   MYCEL_NOTARY_KEY       an App Store Connect API key (path to the .p8), with
#                          MYCEL_NOTARY_KEY_ID and MYCEL_NOTARY_ISSUER
#   MYCEL_NOTARY_APPLE_ID  an Apple ID, with MYCEL_NOTARY_PASSWORD (an
#                          app-specific password) and MYCEL_NOTARY_TEAM_ID
#
# TAURI_CLI, if set, is the npm package to run with npx instead of `cargo tauri`
# (the Apps workflow pins one).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET=""
case "${1:-}" in
  "") ;;
  --universal) TARGET="universal-apple-darwin" ;;
  -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
  *) echo "unknown option: $1 (use --universal or nothing)" >&2; exit 2 ;;
esac

command -v cargo >/dev/null || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }
if [ -n "${TAURI_CLI:-}" ]; then
  tauri() { npx --yes "$TAURI_CLI" "$@"; }
else
  cargo tauri --version >/dev/null 2>&1 || { echo "cargo-tauri not found: cargo install tauri-cli --version '^2' --locked" >&2; exit 1; }
  tauri() { cargo tauri "$@"; }
fi

# Signing and notarisation (see the top of this file).
IDENTITY="${MYCEL_SIGN_IDENTITY:-}"
sign=(codesign --force --timestamp --sign "$IDENTITY")
[ -z "${MYCEL_SIGN_KEYCHAIN:-}" ] || sign+=(--keychain "$MYCEL_SIGN_KEYCHAIN")
notary=()
if [ -n "${MYCEL_NOTARY_PROFILE:-}" ]; then
  notary=(--keychain-profile "$MYCEL_NOTARY_PROFILE")
elif [ -n "${MYCEL_NOTARY_KEY:-}" ]; then
  notary=(--key "$MYCEL_NOTARY_KEY" --key-id "${MYCEL_NOTARY_KEY_ID:?set MYCEL_NOTARY_KEY_ID}" --issuer "${MYCEL_NOTARY_ISSUER:?set MYCEL_NOTARY_ISSUER}")
elif [ -n "${MYCEL_NOTARY_APPLE_ID:-}" ]; then
  notary=(--apple-id "$MYCEL_NOTARY_APPLE_ID" --password "${MYCEL_NOTARY_PASSWORD:?set MYCEL_NOTARY_PASSWORD}" --team-id "${MYCEL_NOTARY_TEAM_ID:?set MYCEL_NOTARY_TEAM_ID}")
fi
if [ ${#notary[@]} -gt 0 ] && [ -z "$IDENTITY" ]; then
  echo "notarisation needs a signed app: set MYCEL_SIGN_IDENTITY" >&2; exit 2
fi

# Have Apple notarise a .zip or .dmg; fails unless it is accepted.
notarise() {
  local out id status
  out="$(xcrun notarytool submit "$1" "${notary[@]}" --wait --output-format json)" || { echo "$out" >&2; return 1; }
  id="$(printf '%s' "$out" | /usr/bin/plutil -extract id raw -o - - 2>/dev/null || true)"
  status="$(printf '%s' "$out" | /usr/bin/plutil -extract status raw -o - - 2>/dev/null || true)"
  echo "notarisation of $(basename "$1"): ${status:-no answer}"
  if [ "$status" != "Accepted" ]; then
    [ -z "$id" ] || xcrun notarytool log "$id" "${notary[@]}" >&2 || true
    return 1
  fi
}

cd "$ROOT"
# Frontend deps (the frontend itself is built by tauri.conf.json's beforeBuildCommand).
[ -d node_modules ] || npm ci  # exactly package-lock.json
# Keep this machine's paths (home directory, Cargo registry, toolchain) out of
# the binaries.
source "$ROOT/scripts/remap-paths.sh"

cd "$ROOT/apps/host"
if [ -n "$TARGET" ]; then
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  tauri build --bundles app --target "$TARGET"
  BUNDLE="$ROOT/target/$TARGET/release/bundle"
  LABEL="universal"
else
  tauri build --bundles app
  BUNDLE="$ROOT/target/release/bundle"
  case "$(uname -m)" in arm64) LABEL="aarch64" ;; x86_64) LABEL="x64" ;; *) LABEL="$(uname -m)" ;; esac
fi

VERSION="$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$ROOT/apps/host/src-tauri/tauri.conf.json" | head -1)"

# The build signs the app ad hoc. With an identity: sign it again with the
# hardened runtime and the entitlements the microphone and camera need, have
# Apple notarise it, and staple the ticket to it so that it also opens on a
# Mac that is offline.
if [ -n "$IDENTITY" ]; then
  "${sign[@]}" --options runtime --entitlements "$ROOT/apps/host/src-tauri/Entitlements.plist" "$BUNDLE/macos/Mycel.app"
  codesign --verify --strict --verbose=2 "$BUNDLE/macos/Mycel.app"
  if [ ${#notary[@]} -gt 0 ]; then
    SUBMIT="$(mktemp -d)"
    ditto -c -k --keepParent "$BUNDLE/macos/Mycel.app" "$SUBMIT/Mycel.zip"
    notarise "$SUBMIT/Mycel.zip"
    rm -rf "$SUBMIT"
    xcrun stapler staple "$BUNDLE/macos/Mycel.app"
  fi
fi

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
# The disk image is what people download: sign and notarise it too.
if [ -n "$IDENTITY" ]; then
  "${sign[@]}" "$DMG"
  if [ ${#notary[@]} -gt 0 ]; then
    notarise "$DMG"
    xcrun stapler staple "$DMG"
    # What Gatekeeper will say on someone else's Mac.
    spctl --assess --type execute --verbose=2 "$OUT/$LABEL/Mycel.app"
    spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
  fi
fi

echo
if [ -z "$IDENTITY" ]; then SIGNED="unsigned"
elif [ ${#notary[@]} -gt 0 ]; then SIGNED="signed and notarised"
else SIGNED="signed, not notarised"; fi
echo "Built Mycel $VERSION ($LABEL, $SIGNED):"
ls -lh "$OUT" "$OUT/$LABEL"
lipo -archs "$OUT/$LABEL/Mycel.app/Contents/MacOS/"* 2>/dev/null || true
