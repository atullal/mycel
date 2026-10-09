#!/usr/bin/env python3
"""NUS Bluetooth (CRAWDAD nus/bluetooth) SQL dump on stdin -> "a,b,start,end" CSV.

The dump's anon_logdata rows are scans: (probe, seen device, timestamp, ...).
Scans of the same pair less than GAP seconds apart are one contact. Column
order is read from the CREATE TABLE statement; adjust NAMES if the dump uses
other column names.
"""
import re
import sys
from datetime import datetime

GAP = 90  # seconds; scans are ~30 s apart
NAMES = {"probe": ("probe_id", "probe", "mac1", "logger"), "seen": ("device_id", "mac", "mac2", "device"), "time": ("timestamp", "time", "ts", "logtime")}

cols = None
rows = []
for line in sys.stdin:
    if cols is None and line.upper().startswith("CREATE TABLE") and "anon_logdata" in line:
        cols = []
        continue
    if cols is not None and not rows and line.strip().startswith("`"):
        cols.append(line.strip().split("`")[1].lower())
        continue
    if line.startswith("INSERT INTO") and "anon_logdata" in line:
        for tup in re.findall(r"\(([^()]*)\)", line):
            rows.append([v.strip().strip("'") for v in tup.split(",")])
if not cols:
    sys.exit("no anon_logdata table found")


def col(kind):
    for n in NAMES[kind]:
        if n in cols:
            return cols.index(n)
    sys.exit(f"no {kind} column among {cols}")


ip, isn, it = col("probe"), col("seen"), col("time")
ids = {}


def idx(x):
    return ids.setdefault(x, len(ids))


def ts(v):
    try:
        return float(v)
    except ValueError:
        return datetime.fromisoformat(v).timestamp()


last = {}
out = []
for r in sorted(rows, key=lambda r: ts(r[it])):
    a, b, t = idx(r[ip]), idx(r[isn]), ts(r[it])
    k = (min(a, b), max(a, b))
    if k in last and t - last[k][1] <= GAP:
        last[k][1] = t
    else:
        if k in last:
            out.append((k[0], k[1], *last[k]))
        last[k] = [t, t]
for k, (s, e) in last.items():
    out.append((k[0], k[1], s, e))
print("# a,b,start,end (seconds) from CRAWDAD nus/bluetooth, doi:10.15783/C74K5N")
for a, b, s, e in sorted(out, key=lambda x: x[2]):
    print(f"{a},{b},{s:.0f},{e:.0f}")
