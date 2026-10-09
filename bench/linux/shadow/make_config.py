#!/usr/bin/env python3
"""Writes a Shadow (https://shadow.github.io) experiment: real `mycel`
binaries spread over world cities, connected by a simulated internet.
Untested: written on macOS; see bench/linux/README.md.

  python3 make_config.py --nodes 200 --cities cities.csv --mycel target/release/mycel > shadow.yaml

Latency between cities: great-circle distance at 5 µs/km (light in fibre)
× 1.5 (routes aren't straight lines), plus 2 ms access latency at each end.
"""
import argparse
import csv
import math
import random


def km(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--nodes", type=int, default=100)
    p.add_argument("--cities", default="cities.csv")
    p.add_argument("--mycel", default="target/release/mycel")
    p.add_argument("--stop", default="10 min")
    p.add_argument("--seed", type=int, default=1)
    a = p.parse_args()
    cities = [(r["city"], float(r["lat"]), float(r["lon"])) for r in csv.DictReader(open(a.cities))]
    gml = ["graph [", "  directed 0"]
    for i, (name, _, _) in enumerate(cities):
        gml.append(f'  node [ id {i} label "{name}" host_bandwidth_down "100 Mbit" host_bandwidth_up "20 Mbit" ]')
    for i in range(len(cities)):
        for j in range(i, len(cities)):
            ms = 2.0 if i == j else 4.0 + km(cities[i][1:], cities[j][1:]) * 0.005 * 1.5
            gml.append(f'  edge [ source {i} target {j} latency "{ms:.1f} ms" packet_loss 0.0 ]')
    gml.append("]")
    rng = random.Random(a.seed)
    print("general:")
    print(f"  stop_time: {a.stop}")
    print(f"  seed: {a.seed}")
    print("network:")
    print("  graph:")
    print("    type: gml")
    print("    inline: |")
    for line in gml:
        print("      " + line)
    print("hosts:")
    for n in range(a.nodes):
        c = rng.randrange(len(cities))
        print(f"  node{n}:")
        print(f"    network_node_id: {c}")
        print("    processes:")
        print(f"    - path: {a.mycel}")
        print(f"      args: keeper --data ./mycel-node{n} --name node{n} --net internet --port 4433")
        print(f"      start_time: {rng.randint(1, 30)}s")
        print("      expected_final_state: running")


if __name__ == "__main__":
    main()
