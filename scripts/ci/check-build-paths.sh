#!/usr/bin/env bash
# Fail if a release binary still contains the build machine's paths: the home
# directory or the checkout (scripts/remap-paths.sh rewrites them).
#
#   scripts/ci/check-build-paths.sh target/release/mycel-host [more binaries]
set -euo pipefail

native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
prefixes=("$(native "$HOME")" "$(native "${GITHUB_WORKSPACE:-$PWD}")")

status=0
for bin in "$@"; do
  for prefix in "${prefixes[@]}"; do
    # Case-insensitive: Windows paths may differ in drive-letter case.
    count="$({ grep -aoiF -- "$prefix" "$bin" || true; } | wc -l | tr -d ' ')"
    if [ "$count" -gt 0 ]; then
      echo "::error::$bin contains $count paths under $prefix"
      grep -aoiE -- "$(printf '%s' "$prefix" | sed 's/[][\.*^$/+?(){}|]/\\&/g')[^[:cntrl:]]{0,100}" "$bin" | sort -u | head -5 || true
      status=1
    fi
  done
  if [ "$status" -eq 0 ]; then echo "$bin: no build-machine paths"; fi
done
exit "$status"
