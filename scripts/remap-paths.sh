#!/usr/bin/env bash
# Keep the build machine's paths out of release binaries.
#
# Panic locations and file!() embed the path each crate was compiled from:
# the user's home directory, the Cargo registry and the Rust toolchain
# (/Users/<name>/.cargo/registry/src/..., .../.rustup/toolchains/...). This
# adds --remap-path-prefix to every rustc invocation, so they become:
#
#   <repository>   -> .
#   $CARGO_HOME    -> /cargo
#   $RUSTUP_HOME   -> /rustup
#   $HOME          -> ~        (anything else under it)
#
# Usage, before a release build (bash):
#
#   source scripts/remap-paths.sh
#
# macOS and Linux: this script becomes Cargo's rustc wrapper and adds the
# flags to each rustc call. It is set as CARGO_BUILD_RUSTC_WRAPPER because the
# Tauri CLI forwards CARGO_* variables (and not RUSTC_WRAPPER) to the Xcode and
# Gradle builds of the iOS and Android apps. RUSTFLAGS can't be used: it would
# replace the per-target rustflags Tauri passes for Android and break the link.
# Windows (Git Bash): a shell script can't be a wrapper there, so the flags go
# into CARGO_ENCODED_RUSTFLAGS; Windows builds are desktop-only, with no other
# rustflags.
# (Cargo's `trim-paths` profile option would do all this, but it is still
# unstable on the pinned toolchain.)

# The flags, from the environment of whichever process runs this. Later
# prefixes win when several match, so the catch-all ($HOME) comes first.
_mycel_remap_flags() {
  local root="$1" native="$2"
  local home="$HOME" cargo="${CARGO_HOME:-$HOME/.cargo}" rustup="${RUSTUP_HOME:-$HOME/.rustup}"
  if [ "$native" = windows ]; then
    home="$(cygpath -w "$home")" cargo="$(cygpath -w "$cargo")" rustup="$(cygpath -w "$rustup")" root="$(cygpath -w "$root")"
  fi
  _mycel_flags=(
    "--remap-path-prefix=$home=~"
    "--remap-path-prefix=$cargo=/cargo"
    "--remap-path-prefix=$rustup=/rustup"
    "--remap-path-prefix=$root=."
  )
}

if [ "${BASH_SOURCE[0]}" != "$0" ]; then
  # Sourced: install the remapping for the builds this shell starts.
  _mycel_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*)
      _mycel_remap_flags "$_mycel_root" windows
      _mycel_joined="$(IFS=$'\x1f'; printf '%s' "${_mycel_flags[*]}")"
      export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS:+$CARGO_ENCODED_RUSTFLAGS$'\x1f'}$_mycel_joined"
      unset _mycel_joined
      ;;
    *)
      # A wrapper already set (sccache, say) still runs, behind this one.
      if [ -n "${RUSTC_WRAPPER:-}" ]; then
        export MYCEL_INNER_RUSTC_WRAPPER="$RUSTC_WRAPPER"
        unset RUSTC_WRAPPER
      fi
      export CARGO_BUILD_RUSTC_WRAPPER="$_mycel_root/scripts/remap-paths.sh"
      ;;
  esac
  unset _mycel_root _mycel_flags
  unset -f _mycel_remap_flags
  return 0
fi

# Run by Cargo as the rustc wrapper: <this script> <rustc> <args...>
set -euo pipefail
_mycel_remap_flags "$(cd "$(dirname "$0")/.." && pwd)" unix
# Cargo doesn't fingerprint the wrapper, so artifacts built without it would be
# reused as they are. It does fingerprint `rustc -vV`, so the remapping goes
# into that output: switching it on or off, or changing a path, rebuilds.
# (An extra "key: value" line; Cargo reads only the lines it knows.)
if [ "$#" -eq 2 ] && [ "$2" = "-vV" ]; then
  "$1" -vV
  echo "mycel-remap-paths: ${_mycel_flags[*]}"
  exit 0
fi
if [ -n "${MYCEL_INNER_RUSTC_WRAPPER:-}" ]; then
  exec "$MYCEL_INNER_RUSTC_WRAPPER" "$@" "${_mycel_flags[@]}"
fi
exec "$@" "${_mycel_flags[@]}"
