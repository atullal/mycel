#!/usr/bin/env python3
"""Measures the real carrier's policy knobs (`DtnConfig::tune`, docs/BENCHMARKS.md
§6) one variant at a time, on the same traces and workloads as bench/run.py
(run that first: it makes the inputs). Each variant is a set of dtn-replay
flags; `default` is the carrier as shipped.

  cargo build --profile replay -p mycel-bench
  bench/ablation.py                      # the default grid below
  bench/ablation.py --only helsinki --workloads heavy --variants default focus-both
  bench/ablation.py --summary-only       # results/knobs/knobs.md from what has run

results/ablation/ is the historical record of the first round, measured on
an experimental copy of the carrier before the fixes were applied.

MYCEL_REPLAY=<path> runs another dtn-replay build.
"""
import argparse
import concurrent.futures as cf
import csv
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run as bench  # noqa: E402

OUT = os.path.join(bench.RESULTS, "knobs")
VARIANTS = {
    "default": [],
    # the simulator's first carrier changes: Spray-and-Focus, max(P(dst), P(internet))
    "focus-both": ["--knobs", "spray=focus,gradient=both"],
    "fallback": ["--knobs", "spray=fallback"],
    "first-both": ["--knobs", "gradient=both"],
    "first-destination": ["--knobs", "gradient=destination"],
    "first-off": ["--knobs", "gradient=off"],
    "copies-4": ["--copies", "4"],
    "no-resume": ["--no-resume"],
}
SCENARIOS = list(bench.SCENARIOS)


def one(scen, wl, variant, force):
    name = f"{scen}-{wl}"
    out = os.path.join(OUT, f"{name}--{variant}.txt")
    if os.path.exists(out) and not force:
        return out
    _, _, gws = bench.SCENARIOS[scen]
    _, _, ttl = bench.WORKLOADS[wl]
    trace = bench.trace_name(scen)
    cmd = [bench.REPLAY, "--contacts", os.path.join(bench.OUT, f"{trace}.csv"),
           "--messages", os.path.join(bench.OUT, f"{trace}-{wl}-msgs.csv"),
           "--ttl-min", str(ttl), "--label", f"{name}-{variant}",
           "--latencies", out.replace(".txt", "-lat.csv")] + VARIANTS[variant]
    if gws:
        cmd += ["--gateways", gws]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{name} {variant}: {r.stderr[-2000:]}")
    open(out, "w").write(r.stdout + "# " + r.stderr)
    return out


def within(lat_csv, secs):
    rows = list(csv.DictReader(open(lat_csv)))
    return [100 * sum(1 for r in rows if r["latency_s"] and float(r["latency_s"]) <= s) / len(rows) for s in secs]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--only", nargs="*", default=SCENARIOS)
    p.add_argument("--workloads", nargs="*", default=list(bench.WORKLOADS))
    p.add_argument("--variants", nargs="*", default=list(VARIANTS))
    p.add_argument("--jobs", type=int, default=2)
    p.add_argument("--force", action="store_true")
    p.add_argument("--summary-only", action="store_true")
    a = p.parse_args()
    os.makedirs(OUT, exist_ok=True)
    jobs = [(s, w, v) for s in a.only for w in a.workloads for v in a.variants]
    if not a.summary_only:
        with cf.ThreadPoolExecutor(a.jobs) as ex:
            for fu in cf.as_completed([ex.submit(one, *j, a.force) for j in jobs]):
                print("done", os.path.basename(fu.result()), flush=True)
    secs = [60, 600, 3600]
    lines = ["| Scenario | Variant | Delivered | Median (s) | ≤ 1 min | ≤ 10 min | ≤ 1 h | Overhead | Offers | Refused | Cut |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for s in a.only:
        for w in a.workloads:
            for v in a.variants:
                f = os.path.join(OUT, f"{s}-{w}--{v}.txt")
                if not os.path.exists(f):
                    continue
                st = bench.parse_stats(f)
                w1, w10, w60 = within(f.replace(".txt", "-lat.csv"), secs)
                lines.append(f"| {s}-{w} | {v} | {100 * float(st['delivery_prob']):.1f} % | "
                             f"{float(st['latency_med']):.0f} | {w1:.1f} % | {w10:.1f} % | {w60:.1f} % | "
                             f"{float(st['overhead_ratio']):.1f} | {st['offers']} | {st['refused']} | {st['aborted']} |")
    table = "\n".join(lines) + "\n"
    open(os.path.join(OUT, "knobs.md"), "w").write(table)
    print(table)


if __name__ == "__main__":
    main()
