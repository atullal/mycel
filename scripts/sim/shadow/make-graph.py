#!/usr/bin/env python3
"""A Shadow GML world graph: one node per city, latency between them from the
great-circle fibre model mycel-sim uses (5 us/km x 1.4 inflation), or with
--measured from WonderNetwork's ping sample (scripts/sim/fetch-wondernetwork.sh;
credit: WonderNetwork, https://wonderproxy.com/blog/a-day-in-the-life-of-the-internet/).
"""
import csv
import math
import sys

CITIES = [("New York", 40.71, -74.01), ("London", 51.51, -0.13), ("Frankfurt", 50.11, 8.68), ("Tokyo", 35.68, 139.69),
          ("Sao Paulo", -23.55, -46.63), ("Lagos", 6.52, 3.38), ("Mumbai", 19.08, 72.88), ("Sydney", -33.87, 151.21)]


def km(a, b):
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


measured = {}
if "--measured" in sys.argv:
    servers = {r["id"]: (float(r["latitude"]), float(r["longitude"])) for r in csv.DictReader(open("target/data/wondernetwork/servers.csv"))}
    acc = {}
    for r in csv.DictReader(open("target/data/wondernetwork/pings.csv")):
        acc.setdefault((r["source"], r["destination"]), []).append(float(r["avg"]))
    for (a, b), v in acc.items():
        if a in servers and b in servers:
            measured[(servers[a], servers[b])] = sorted(v)[len(v) // 2]


def one_way_ms(a, b):
    if measured:
        best = min(measured, key=lambda k: km(k[0], a[1:]) + km(k[1], b[1:]))
        return measured[best] / 2
    return km(a[1:], b[1:]) * 5 * 1.4 / 1000


print("graph [\n  directed 0")
for i, (name, la, lo) in enumerate(CITIES):
    print(f'  node [ id {i} label "{name}" host_bandwidth_down "100 Mbit" host_bandwidth_up "20 Mbit" ]')
for i, a in enumerate(CITIES):
    print(f'  edge [ source {i} target {i} latency "2 ms" packet_loss 0.0 ]')
    for j, b in enumerate(CITIES[i + 1:], i + 1):
        print(f'  edge [ source {i} target {j} latency "{max(1, round(one_way_ms(a, b)))} ms" packet_loss 0.001 ]')
print("]")
