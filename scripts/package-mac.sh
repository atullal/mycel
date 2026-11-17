#!/usr/bin/env bash
# Build the Mycel macOS app (.app + .dmg) and copy it into dist-release/.
#
#   scripts/package-mac.sh              # this Mac's architecture (arm64 or x86_64)
#   scripts/package-mac.sh --universal  # one app that runs on Apple silicon AND Intel Macs
#
# Public packages require a Developer ID signature and Apple notarization.
# Missing credentials stop the build. For local development use cargo tauri dev.
# Set:
#
#   MYCEL_SIGN_IDENTITY    "Developer ID Application: Name (TEAMID)"
#   MYCEL_SIGN_KEYCHAIN    the keychain file that holds it (default: your own)
#
# and one of:
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
case "$IDENTITY" in
  "Developer ID Application: "*) ;;
  *) echo "Public Mac packages require MYCEL_SIGN_IDENTITY (Developer ID Application). See docs/PLATFORMS.md." >&2; exit 2 ;;
esac
if [ ${#notary[@]} -eq 0 ]; then
  echo "Public Mac packages require notarization credentials. See docs/PLATFORMS.md." >&2; exit 2
fi
export MYCEL_SIGN_IDENTITY
# Fail before compiling or touching distribution files if credentials are absent.
identities=(security find-identity -v -p codesigning)
[ -z "${MYCEL_SIGN_KEYCHAIN:-}" ] || identities+=("$MYCEL_SIGN_KEYCHAIN")
"${identities[@]}" | grep -F -- "\"$IDENTITY\"" >/dev/null
xcrun notarytool history "${notary[@]}" >/dev/null

command -v cargo >/dev/null || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }
if [ -n "${TAURI_CLI:-}" ]; then
  tauri() { npx --yes "$TAURI_CLI" "$@"; }
else
  cargo tauri --version >/dev/null 2>&1 || { echo "cargo-tauri not found: cargo install tauri-cli --version '^2' --locked" >&2; exit 1; }
  tauri() { cargo tauri "$@"; }
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
  tauri build --bundles app --target "$TARGET" -- --locked
  BUNDLE="$ROOT/target/$TARGET/release/bundle"
  LABEL="universal"
else
  tauri build --bundles app -- --locked
  BUNDLE="$ROOT/target/release/bundle"
  case "$(uname -m)" in arm64) LABEL="aarch64" ;; x86_64) LABEL="x64" ;; *) LABEL="$(uname -m)" ;; esac
fi

VERSION="$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$ROOT/apps/host/src-tauri/tauri.conf.json" | head -1)"

# Work privately until every final container has passed verification. A failed
# submission must never leave a new file under a public release filename.
OUT="$ROOT/dist-release"
mkdir -p "$OUT"
STAGE="$(mktemp -d "$OUT/.mac-release.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/image" "$STAGE/packages"
APP="$STAGE/image/Mycel.app"
ditto "$BUNDLE/macos/Mycel.app" "$APP"
ln -s /Applications "$STAGE/image/Applications"
"${sign[@]}" --options runtime --entitlements "$ROOT/apps/host/src-tauri/Entitlements.plist" "$APP"
ditto -c -k --keepParent "$APP" "$STAGE/Mycel.zip"
notarise "$STAGE/Mycel.zip"
xcrun stapler staple "$APP"
"$ROOT/scripts/verify-mac.sh" "$APP"

# ZIPs cannot carry a stapled ticket; recreate the archive after stapling the
# app, then check the extracted copy, exactly as a recipient will see it.
ZIP="$STAGE/packages/Mycel_${VERSION}_${LABEL}_notarized.app.zip"
ditto -c -k --keepParent "$APP" "$ZIP"
mkdir "$STAGE/extracted"
ditto -x -k "$ZIP" "$STAGE/extracted"
"$ROOT/scripts/verify-mac.sh" "$STAGE/extracted/Mycel.app"

# Headless drag-to-Applications image, signed and notarized as a container too.
DMG="$STAGE/packages/Mycel_${VERSION}_${LABEL}_notarized.dmg"
hdiutil create -quiet -volname "Mycel" -srcfolder "$STAGE/image" -fs HFS+ -format UDZO -ov "$DMG"
"${sign[@]}" "$DMG"
notarise "$DMG"
xcrun stapler staple "$DMG"
"$ROOT/scripts/verify-mac.sh" "$DMG"

# Only verified packages receive the filenames accepted by CI and the website.
mkdir -p "$OUT/$LABEL"
rm -rf "$OUT/$LABEL/Mycel.app"
ditto "$APP" "$OUT/$LABEL/Mycel.app"
mv -f "$ZIP" "$DMG" "$OUT/"
echo "Built signed and notarized Mycel $VERSION ($LABEL) in $OUT"
