#!/usr/bin/env bash
# Build the Mycel Android app (one APK for phones, tablets and emulators) and
# copy it into dist-release/.
#
#   scripts/package-android.sh            # signed release APK (arm64, armv7, x86_64)
#   scripts/package-android.sh --debug    # debug APK, arm64 only (fast; slow app)
#
# Needs a JDK 17+, the Android SDK and NDK (Android Studio or Homebrew's
# android-commandlinetools). Release builds are signed with a key kept outside
# the repo, in ~/.mycel-signing/android/ (made on first run: back it up; every
# later build must use the same key or phones won't accept the update).
# Install on a phone: enable "Install unknown apps", then open the APK, or
# `adb install -r dist-release/Mycel_<version>_android.apk`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODE=release
case "${1:-}" in
  "") ;;
  --debug) MODE=debug ;;
  -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
  *) echo "unknown option: $1 (use --debug or nothing)" >&2; exit 2 ;;
esac

# Toolchain: honour the environment, else the usual install locations.
first_dir() { for d in "$@"; do [ -d "$d" ] && { echo "$d"; return; }; done; }
export ANDROID_HOME="${ANDROID_HOME:-$(first_dir "$HOME/Library/Android/sdk" /opt/homebrew/share/android-commandlinetools "$HOME/Android/Sdk")}"
[ -n "$ANDROID_HOME" ] || { echo "Android SDK not found: install Android Studio, or set ANDROID_HOME" >&2; exit 1; }
export NDK_HOME="${NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)}"
[ -d "$NDK_HOME" ] || { echo "Android NDK not found: sdkmanager 'ndk;27.2.12479018' (or set NDK_HOME)" >&2; exit 1; }
if [ -z "${JAVA_HOME:-}" ]; then
  JAVA_HOME="$(first_dir /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home "/Applications/Android Studio.app/Contents/jbr/Contents/Home" || true)"
  [ -n "$JAVA_HOME" ] || JAVA_HOME="$(/usr/libexec/java_home 2>/dev/null || true)"
  export JAVA_HOME
fi
[ -x "${JAVA_HOME:-}/bin/java" ] || { echo "JDK not found: brew install openjdk@17 (or set JAVA_HOME)" >&2; exit 1; }
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"

command -v cargo >/dev/null || { echo "cargo not found: install Rust from https://rustup.rs" >&2; exit 1; }
cargo tauri --version >/dev/null 2>&1 || { echo "cargo-tauri not found: cargo install tauri-cli --version '^2' --locked" >&2; exit 1; }

cd "$ROOT"
[ -d node_modules ] || npm install

GEN="$ROOT/apps/host/src-tauri/gen/android"
VERSION="$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$ROOT/apps/host/src-tauri/tauri.conf.json" | head -1)"
OUT="$ROOT/dist-release"
mkdir -p "$OUT"

if [ "$MODE" = release ]; then
  # Signing key, made once and kept out of the repo.
  KEYDIR="${MYCEL_ANDROID_SIGNING:-$HOME/.mycel-signing/android}"
  KEYSTORE="$KEYDIR/release.jks"
  PROPS="$KEYDIR/keystore.properties"
  if [ ! -f "$KEYSTORE" ]; then
    echo "Making the Android signing key in $KEYDIR (back this folder up)."
    mkdir -p "$KEYDIR" && chmod 700 "$KEYDIR"
    PASS="$(openssl rand -hex 24)"
    keytool -genkeypair -v -keystore "$KEYSTORE" -alias mycel -keyalg RSA -keysize 4096 -validity 10000 \
      -storepass "$PASS" -keypass "$PASS" -dname "CN=Mycel" >/dev/null
    printf 'storeFile=%s\nkeyAlias=mycel\npassword=%s\n' "$KEYSTORE" "$PASS" > "$PROPS"
    chmod 600 "$KEYSTORE" "$PROPS"
  fi
  cp "$PROPS" "$GEN/keystore.properties"
  trap 'rm -f "$GEN/keystore.properties"' EXIT

  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android >/dev/null
  (cd apps/host && cargo tauri android build --apk --target aarch64 armv7 x86_64)
  APK="$GEN/app/build/outputs/apk/universal/release/app-universal-release.apk"
  DEST="$OUT/Mycel_${VERSION}_android.apk"
else
  rustup target add aarch64-linux-android >/dev/null
  (cd apps/host && cargo tauri android build --apk --debug --target aarch64)
  APK="$GEN/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
  DEST="$OUT/Mycel_${VERSION}_android-debug.apk"
fi

cp "$APK" "$DEST"
echo
echo "Built $DEST ($(du -h "$DEST" | cut -f1))"
if [ "$MODE" = release ]; then
  APKSIGNER="$(ls -d "$ANDROID_HOME"/build-tools/*/apksigner 2>/dev/null | sort -V | tail -1)"
  [ -n "$APKSIGNER" ] && "$APKSIGNER" verify --print-certs "$DEST" | grep -m1 "SHA-256" || true
fi
