#!/usr/bin/env bash
# Builds every fuzz target once, then runs each for SECONDS (docs/TESTING.md,
# "Fuzzing"). With no TARGETs, runs them all.
#
#   fuzz/run.sh 600                     # every target, 10 minutes each
#   JOBS=1 fuzz/run.sh 60 mesh_wire     # one target, one minute
#
# JOBS fuzzers run at once (default 2; each takes a core and up to RSS_MB of
# memory). FUZZ_TOOLCHAIN is the nightly to build with. Corpora grow in
# fuzz/corpus/<target> (seeded from fuzz/seeds/<target>), logs go to
# fuzz/logs/<target>.log, and a crash, hang (10 s for one input), memory
# blow-up or excessive allocation leaves its input in fuzz/artifacts/<target>/
# and fails the run.
set -euo pipefail

seconds=${1:?usage: fuzz/run.sh SECONDS [TARGET...]}
shift
cd "$(dirname "$0")"
toolchain=${FUZZ_TOOLCHAIN:-nightly}
jobs=${JOBS:-2}
# libFuzzer's defaults, except a smaller single-allocation limit: no input
# of a few KiB should make a decoder allocate this much at once.
rss_mb=${RSS_MB:-2048}
malloc_mb=${MALLOC_MB:-512}

if [ $# -eq 0 ]; then
  # (target names are single words)
  # shellcheck disable=SC2046
  set -- $(cargo "+$toolchain" fuzz list)
fi

# One build for every target, with overflow checks and debug assertions on
# (`cargo fuzz run` would check the build once per target).
cargo "+$toolchain" fuzz build --debug-assertions
host=$(rustc "+$toolchain" -vV | sed -n 's/^host: //p')
bin="target/$host/release"

mkdir -p logs
# shellcheck disable=SC2329 # (run by xargs, below)
run_one() {
  local t=$1 status=0 seeds=()
  mkdir -p "corpus/$t" "artifacts/$t"
  if [ -d "seeds/$t" ]; then seeds=("seeds/$t"); fi
  # (`time` appends the CPU seconds used to the log: max_total_time is wall
  # time, which runs on while a laptop sleeps)
  local TIMEFORMAT='cpu: user %U s, sys %S s, wall %R s'
  { time "$bin/$t" "corpus/$t" ${seeds[@]+"${seeds[@]}"} \
    -max_total_time="$seconds" -timeout=10 -rss_limit_mb="$rss_mb" -malloc_limit_mb="$malloc_mb" \
    -artifact_prefix="artifacts/$t/" -print_final_stats=1 >"logs/$t.log" 2>&1 || status=$?; } 2>>"logs/$t.log"
  local summary
  summary=$(grep -E '^#[0-9]+[[:space:]]+DONE' "logs/$t.log" | tail -1 || true)
  echo "$t: exit $status ${summary:-(stopped early: see fuzz/logs/$t.log)}"
  return "$status"
}
export -f run_one
export bin seconds rss_mb malloc_mb

status=0
# shellcheck disable=SC2016 # (expanded by the inner shell)
printf '%s\n' "$@" | xargs -P "$jobs" -I{} bash -c 'run_one "$1"' _ {} || status=$?
if [ "$status" -ne 0 ]; then
  echo "== failing inputs:"
  for t in "$@"; do grep -h 'Test unit written to' "logs/$t.log" || true; done
fi
exit "$status"
