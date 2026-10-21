#!/usr/bin/env bash
# Check this build against the real pre-release code it claims to speak
# wire version 1 with (docs/PROTOCOL.md §5):
#   1. golden vectors: main 98d9b7b's own encoders print every vector in
#      crates/mycel-net/src/mesh/v1_vectors.rs, byte for byte;
#   2. cross-build: a node built from 98d9b7b and a node of this build sync
#      a space both ways and fetch each other's cards over loopback.
#
# Usage: scripts/v1-compat/run.sh [WORK_DIR]   (default: target/v1-compat)
# BASE=<commit> checks another pre-release commit (the generator and old
# peer must still compile there). The first run builds 98d9b7b's
# mycel-net from scratch in WORK_DIR (several minutes, a few GB of disk).
set -euo pipefail

BASE=${BASE:-98d9b7b}
REPO=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
HERE="$REPO/scripts/v1-compat"
WORK=${1:-$REPO/target/v1-compat}
OLD="$WORK/old"
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-3}

echo "== checkout of $BASE in $OLD"
rm -rf "$OLD"
mkdir -p "$OLD"
git -C "$REPO" archive "$BASE" | tar -x -C "$OLD"
cp "$HERE/gen_vectors.rs" "$OLD/crates/mycel-net/src/mesh/v1_gen.rs"
printf '\n#[cfg(test)]\nmod v1_gen;\n' >> "$OLD/crates/mycel-net/src/mesh/mod.rs"
cp "$HERE/old_peer.rs" "$OLD/crates/mycel-net/tests/v1_compat_peer.rs"

echo "== 1. golden vectors printed by $BASE"
(cd "$OLD" && CARGO_TARGET_DIR="$WORK/target-old" cargo test -q -p mycel-net --lib v1_gen -- --nocapture) \
    | grep '^VECTOR ' > "$WORK/vectors.txt"
python3 -I "$HERE/compare.py" "$WORK/vectors.txt" "$REPO/crates/mycel-net/src/mesh/v1_vectors.rs"

echo "== 2. a $BASE node and a node of this build"
OLD_BIN=$(cd "$OLD" && CARGO_TARGET_DIR="$WORK/target-old" cargo test -p mycel-net --test v1_compat_peer --no-run 2>&1 \
    | sed -n 's/.*Executable .*(\(.*v1_compat_peer-[0-9a-f]*\)).*/\1/p' | tail -1)
(cd "$REPO" && cargo test -q -p mycel-net --test v1_compat --no-run)
RUN="$WORK/run"
rm -rf "$RUN"
mkdir -p "$RUN"
export MYCEL_V1_COMPAT_DIR="$RUN"
"$OLD_BIN" --ignored --exact old_peer --nocapture &
OLD_PID=$!
NEW_STATUS=0
(cd "$REPO" && cargo test -q -p mycel-net --test v1_compat -- --ignored --nocapture) || NEW_STATUS=$?
OLD_STATUS=0
wait "$OLD_PID" || OLD_STATUS=$?
if [ "$NEW_STATUS" -ne 0 ] || [ "$OLD_STATUS" -ne 0 ]; then
    echo "cross-build test FAILED (this build: $NEW_STATUS, $BASE: $OLD_STATUS)"
    exit 1
fi
echo "== v1 compatibility with $BASE: OK"
