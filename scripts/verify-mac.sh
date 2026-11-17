#!/usr/bin/env bash
# Verify a public Mycel .app or .dmg, including the app inside the final DMG.
set -euo pipefail
# Pin the certificate team as well as its Developer ID Application type.
: "${MYCEL_SIGN_IDENTITY:?Set MYCEL_SIGN_IDENTITY to the expected Developer ID identity.}"
TEAM="$(printf '%s' "$MYCEL_SIGN_IDENTITY" | sed -n 's/.*(\([A-Z0-9]\{10\}\))$/\1/p')"
[ -n "$TEAM" ] || { echo "Cannot determine the signing team from MYCEL_SIGN_IDENTITY" >&2; exit 2; }
[ "$#" -eq 1 ] || { echo "Usage: MYCEL_SIGN_IDENTITY=<identity> scripts/verify-mac.sh <app-or-dmg>" >&2; exit 2; }
FILE="$1"
REQUIREMENT="anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$TEAM\""

verify_signature() {
  codesign --verify --deep --strict --verbose=2 "-R=$REQUIREMENT" "$1"
  local details
  details="$(codesign -dvvv "$1" 2>&1)"
  echo "$details"
  echo "$details" | grep -q '^Timestamp='
}
verify_app() {
  verify_signature "$1"
  codesign -dvvv "$1" 2>&1 | grep -q 'flags=.*(.*runtime.*)'
  xcrun stapler validate "$1"
  spctl --assess --type execute --verbose=2 "$1"
}

case "$FILE" in
  *.app) verify_app "$FILE" ;;
  *.dmg)
    verify_signature "$FILE"
    xcrun stapler validate "$FILE"
    spctl --assess --type open --context context:primary-signature --verbose=2 "$FILE"
    MOUNT="$(mktemp -d)"
    MOUNTED=false
    cleanup() {
      if "$MOUNTED"; then hdiutil detach -quiet "$MOUNT"; fi
      rmdir "$MOUNT"
    }
    trap cleanup EXIT
    hdiutil attach -quiet -readonly -nobrowse -mountpoint "$MOUNT" "$FILE"
    MOUNTED=true
    verify_app "$MOUNT/Mycel.app"
    ;;
  *) echo "Expected a .app or .dmg" >&2; exit 2 ;;
esac
