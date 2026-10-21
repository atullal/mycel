#!/usr/bin/env bash
# Builds every fuzz target once, then runs each for SECONDS (docs/TESTING.md,
# "Fuzzing"). With no TARGETs, runs them all.
#
#   fuzz/run.sh 600                     # every target, 10 minutes each
#   JOBS=1 fuzz/run.sh 60 mesh_wire     # one target, one minute
#
# JOBS fuzzers run at once (default 2; each takes a core and up to RSS_MB of
# memory). FUZZ_TOOLCHAIN is the nightly to build with. Corpora grow in
# fuzz/corpus/<target> (seeded from fuzz/seeds/<target>), the last run's log
# goes to fuzz/logs/<target>.log, every run adds a line to fuzz/logs/runs.tsv
# (target, start, seconds asked, exit status, CPU and wall seconds, inputs
# run), and a crash, hang (10 s for one input), memory blow-up or excessive
# allocation leaves its input in fuzz/artifacts/<target>/ and fails the run.
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

# Structure-aware targets (`arbitrary`) build a whole scenario from one
# input: up to 64 edits, 24 messages or 128 steps. libFuzzer's length
# control would keep inputs a few hundred bytes long for most of a short
# run, so these start at their full length.
structured=" blob_ranges call_media dtn link_ble mesh_router sync_doc sync_replica trust_graph video_media "

mkdir -p logs
ledger=logs/runs.tsv
if [ ! -s "$ledger" ]; then
  printf 'target\tstart_utc\tseconds\texit\tcpu_user_s\tcpu_sys_s\twall_s\tinputs\trevision\n' >"$ledger"
fi
revision=$(git describe --always --dirty --abbrev=8 2>/dev/null || echo unknown)
# shellcheck disable=SC2329 # (run by xargs, below)
run_one() {
  local t=$1 status=0 seeds=() length=() start
  mkdir -p "corpus/$t" "artifacts/$t"
  if [ -d "seeds/$t" ]; then seeds=("seeds/$t"); fi
  case "$structured" in *" $t "*) length=(-max_len=16384 -len_control=0) ;; esac
  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  # (`time` appends the CPU seconds used to the log: max_total_time is wall
  # time, which runs on while a laptop sleeps)
  local TIMEFORMAT='cpu: user %U s, sys %S s, wall %R s'
  { time "$bin/$t" "corpus/$t" ${seeds[@]+"${seeds[@]}"} \
    -max_total_time="$seconds" -timeout=10 -rss_limit_mb="$rss_mb" -malloc_limit_mb="$malloc_mb" \
    ${length[@]+"${length[@]}"} -artifact_prefix="artifacts/$t/" -print_final_stats=1 >"logs/$t.log" 2>&1 \
    || status=$?; } 2>>"logs/$t.log"
  local summary cpu inputs
  summary=$(grep -E '^#[0-9]+[[:space:]]+DONE' "logs/$t.log" | tail -1 || true)
  # (user, sys and wall seconds, tab-separated; empty if the run was killed)
  cpu=$(awk '/^cpu: user /{u=$3; s=$6; w=$9} END{printf "%s\t%s\t%s", u, s, w}' "logs/$t.log")
  inputs=$(sed -n 's/^stat::number_of_executed_units: *//p' "logs/$t.log" | tail -1)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$start" "$seconds" "$status" "$cpu" "${inputs:-}" "$revision" >>"$ledger"
  echo "$t: exit $status ${summary:-(stopped early: see fuzz/logs/$t.log)}"
  return "$status"
}
export -f run_one
export bin seconds rss_mb malloc_mb structured ledger revision

status=0
# shellcheck disable=SC2016 # (expanded by the inner shell)
printf '%s\n' "$@" | xargs -P "$jobs" -I{} bash -c 'run_one "$1"' _ {} || status=$?
if [ "$status" -ne 0 ]; then
  echo "== failing inputs:"
  for t in "$@"; do grep -h 'Test unit written to' "logs/$t.log" || true; done
fi
exit "$status"
