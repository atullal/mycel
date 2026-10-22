#!/usr/bin/env bash
# Fail if a release package would build any first-party crate with a test-only
# feature: `model` (Debug-able internals and a planted bug for the model
# checker, crates/mycel-check) or `sim` (`buggify!` fault injection). Cargo
# unifies features across the packages of one build, so
# `cargo build --workspace` turns them on for everything; release artifacts
# must be built per package (`tauri build` builds only mycel-host), and this
# checks the feature set such a build resolves.
#
#   scripts/ci/check-release-features.sh [package ...]   (default: mycel-host)
set -euo pipefail

packages=("$@")
[ "${#packages[@]}" -gt 0 ] || packages=(mycel-host)

status=0
for p in "${packages[@]}"; do
  found="$(cargo tree --locked -p "$p" -e features --prefix none --target all \
    | grep -E '^mycel-[a-z0-9-]+ feature "(model|sim)"' | sort -u || true)"
  if [ -n "$found" ]; then
    echo "::error::$p would be built with test-only features:"
    echo "$found"
    status=1
  else
    echo "$p: no test-only features"
  fi
done
exit "$status"
