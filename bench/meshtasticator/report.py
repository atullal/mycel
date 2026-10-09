#!/usr/bin/env python3
"""Tables for docs/BENCHMARKS.md from bench/results/meshtasticator/
(summary.csv from run.py, mycel-routing.csv from mesh-routing)."""
import csv
import os
from collections import defaultdict
from statistics import mean

D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "meshtasticator")
ANN_BYTES = 170  # signed announcement ~130 B (wire.rs) + QUIC datagram framing


def main():
    mt = list(csv.DictReader(open(os.path.join(D, "summary.csv"))))
    my = list(csv.DictReader(open(os.path.join(D, "mycel-routing.csv"))))
    out = []

    out.append("#### Meshtastic managed flooding, broadcasts (Meshtasticator)\n")
    out.append("| Nodes | Hop limit | Reach | Usefulness | Transmissions per message |")
    out.append("|---:|---:|---:|---:|---:|")
    g = defaultdict(list)
    for r in mt:
        if r["mode"] == "broadcast":
            g[(int(r["nodes"]), int(r["hop_limit"]))].append(r)
    for (n, h), rs in sorted(g.items()):
        out.append(f"| {n} | {h} | {100 * mean(float(r['reach']) for r in rs):.0f} % | "
                   f"{100 * mean(float(r['usefulness']) for r in rs):.0f} % | "
                   f"{mean(int(r['transmissions']) / int(r['messages']) for r in rs):.1f} |")

    out.append("\n#### Direct messages: Meshtastic (hop limit 3) vs Mycel's router, same topologies and messages\n")
    out.append("| Nodes | Links | Meshtastic delivered | Meshtastic tx per delivered | Mycel delivered | "
               "Mycel data tx per delivered | Mycel announcements per node per min | Mycel control traffic per node | "
               "Announcement airtime on LoRa LongFast |")
    out.append("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    mtd = defaultdict(list)
    for r in mt:
        if r["mode"] == "dm" and r["hop_limit"] == "3":
            mtd[int(r["nodes"])].append(r)
    myd = defaultdict(list)
    for r in my:
        myd[int(r["nodes"])].append(r)
    for n in sorted(mtd):
        a, b = mtd[n], myd.get(n, [])
        if not b:
            continue
        simtime_s = 30 * 60
        ctrl_kbps = mean(int(r["ann_unicast"]) * ANN_BYTES * 8 / (n * simtime_s) / 1000 for r in b)
        out.append(
            f"| {n} | {mean(int(r['links']) for r in a):.0f} "
            f"| {100 * mean(int(r['dm_delivered']) / int(r['dm_sent']) for r in a):.0f} % "
            f"| {mean(int(r['transmissions']) / max(1, int(r['dm_delivered'])) for r in a):.1f} "
            f"| {100 * mean(int(r['delivered']) / int(r['messages']) for r in b):.1f} % "
            f"| {mean(float(r['data_tx_per_delivered']) for r in b):.1f} "
            f"| {mean(float(r['ann_bcast_per_node_min']) for r in b):.0f} "
            f"| {ctrl_kbps:.0f} kbit/s "
            f"| {100 * mean(float(r['lora_ann_airtime_share']) for r in b):.0f} % of the channel |"
        )
    text = "\n".join(out) + "\n"
    open(os.path.join(D, "report.md"), "w").write(text)
    print(text)


if __name__ == "__main__":
    main()
