#!/usr/bin/env python3
"""Measures the carrier fixes proposed in docs/BENCHMARKS.md §6, one at a time,
on the same traces and workloads as bench/run.py (run that first: it makes
the inputs). Each variant is `dtn-replay --carrier fixed --fixes <list>`
(bench/mycel-bench/src/carrier_fixed.rs); `real` is the carrier in
crates/mycel-net/src/mesh/dtn.rs.

  cargo build --release -p mycel-bench
  bench/ablation.py                      # the default grid below
  bench/ablation.py --only helsinki --workloads heavy --variants real all
  bench/ablation.py --summary-only --only cambridge infocom2005 infocom2006 infocom2006-gw helsinki helsinki-gw \
      --workloads heavy chat         # results/ablation/ablation.md from what has run

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

OUT = os.path.join(bench.RESULTS, "ablation")
VARIANTS = ["real", "own", "free", "expiry", "resume", "own,free", "own,free,expiry", "all", "all,spray",
            "all,evict", "all,fallback", "all,fallback,evict", "all,spray,evict", "all,spray,evict,inet", "all,spray,nograd", "all,spray,evict,nograd"]
SCENARIOS = ["cambridge", "infocom2005", "helsinki", "helsinki-gw"]


def one(scen, wl, variant, force):
    name = f"{scen}-{wl}"
    out = os.path.join(OUT, f"{name}--{variant.replace(',', '+')}.txt")
    if os.path.exists(out) and not force:
        return out
    _, _, gws = bench.SCENARIOS[scen]
    _, _, ttl = bench.WORKLOADS[wl]
    trace = bench.trace_name(scen)
    cmd = [bench.REPLAY, "--contacts", os.path.join(bench.OUT, f"{trace}.csv"),
           "--messages", os.path.join(bench.OUT, f"{trace}-{wl}-msgs.csv"),
           "--ttl-min", str(ttl), "--label", f"{name}-{variant}",
           "--latencies", out.replace(".txt", "-lat.csv")]
    if gws:
        cmd += ["--gateways", gws]
    if variant != "real":
        cmd += ["--carrier", "fixed", "--fixes", variant]
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
    p.add_argument("--workloads", nargs="*", default=["heavy"])
    p.add_argument("--variants", nargs="*", default=VARIANTS)
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
    lines = ["| Scenario | Variant | Delivered | Median (s) | ≤ 1 min | ≤ 10 min | ≤ 1 h | Started | Refused | Aborted |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for s in a.only:
        for w in a.workloads:
            for v in a.variants:
                f = os.path.join(OUT, f"{s}-{w}--{v.replace(',', '+')}.txt")
                if not os.path.exists(f):
                    continue
                st = bench.parse_stats(f)
                w1, w10, w60 = within(f.replace(".txt", "-lat.csv"), secs)
                lines.append(f"| {s}-{w} | {v} | {100 * float(st['delivery_prob']):.1f} % | "
                             f"{float(st['latency_med']):.0f} | {w1:.1f} % | {w10:.1f} % | {w60:.1f} % | "
                             f"{st['started']} | {st['refused']} | {st['aborted']} |")
    table = "\n".join(lines) + "\n"
    open(os.path.join(OUT, "ablation.md"), "w").write(table)
    print(table)


if __name__ == "__main__":
    main()
