#!/usr/bin/env python3
"""Contact traces and message workloads shared by The ONE and Mycel's bench.

One trace + one workload feed every simulator, so results are comparable:

  contacts CSV  t_start,t_end,a,b          seconds; undirected; a < b; ids 0..N-1
  messages CSV  t,id,src,dst,size          seconds, bytes; ids 0..N-1
  ONE events    <t> CONN <a> <b> up|down   StandardEventsReader syntax
                <t> C <id> <src> <dst> <size>

Subcommands:
  crawdad   CRAWDAD cambridge/haggle contacts.ExpN.dat -> contacts CSV
  one-conn  ONE ConnectivityONEReport                  -> contacts CSV
  one-msgs  ONE CreatedMessagesReport                  -> messages CSV
  workload  contacts CSV -> messages CSV (ONE MessageEventGenerator rules)
  one-events contacts + messages (+ gateways) -> ONE external events file
  stats     print a trace's summary

Gateways (devices with the internet) are permanently connected to each
other: `one-events --gateways` adds those CONN up events at t=0 and drops
trace contacts between two gateways, so the link is never cut. Mycel's bench
reads the same `--gateways` list and applies the same rule.
"""
import argparse
import csv
import random
import re
import sys
from collections import defaultdict


def merge(intervals):
    out = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def write_contacts(path, rows):
    rows = sorted(rows)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_start", "t_end", "a", "b"])
        for s, e, a, b in rows:
            w.writerow([fmt(s), fmt(e), a, b])


def read_contacts(path):
    with open(path) as f:
        r = csv.DictReader(f)
        return [(float(x["t_start"]), float(x["t_end"]), int(x["a"]), int(x["b"])) for x in r]


def fmt(t):
    return str(int(t)) if float(t).is_integer() else f"{t:.2f}"


def parse_ranges(spec):
    """'1-17,20' -> {1..17, 20}"""
    out = set()
    for part in filter(None, (spec or "").split(",")):
        if "-" in part:
            a, b = part.split("-")
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out


def cmd_crawdad(a):
    """iMote sightings -> undirected contacts between the experiment's own
    devices. A sighting `id1 id2 first last` means id1 saw id2 from `first`
    to `last` (seconds, 120 s scan granularity). Both directions count; a
    single sighting (first == last) is given --min-dur seconds."""
    excluded = parse_ranges(a.exclude)
    per_pair = defaultdict(list)
    for line in open(a.input):
        f = line.split()
        if len(f) < 4:
            continue
        i, j, first, last = int(f[0]), int(f[1]), float(f[2]), float(f[3])
        if i == j or not (1 <= i <= a.internal_max and 1 <= j <= a.internal_max):
            continue
        if i in excluded or j in excluded:
            continue
        per_pair[(min(i, j), max(i, j))].append((first, max(last, first + a.min_dur)))
    ids = sorted({x for p in per_pair for x in p})
    index = {orig: n for n, orig in enumerate(ids)}
    t0 = min(s for iv in per_pair.values() for s, _ in iv)
    rows = []
    for (i, j), iv in per_pair.items():
        for s, e in merge(iv):
            rows.append((s - t0, e - t0, index[i], index[j]))
    write_contacts(a.out, rows)
    if a.map:
        with open(a.map, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["id", "crawdad_id"])
            for orig, n in index.items():
                w.writerow([n, orig])
    print(f"{a.out}: {len(ids)} devices, {len(rows)} contacts, t0 = {t0:.0f} s in the original trace", file=sys.stderr)


def cmd_one_conn(a):
    up = {}
    rows = []
    end = 0.0
    for line in open(a.input):
        f = line.split()
        if len(f) < 5 or f[1] != "CONN":
            continue
        t, i, j, what = float(f[0]), int(f[2]), int(f[3]), f[4]
        end = max(end, t)
        key = (min(i, j), max(i, j))
        if what == "up":
            up.setdefault(key, t)
        elif key in up:
            rows.append((up.pop(key), t, *key))
    end = a.end if a.end is not None else end
    for key, s in up.items():  # still up when the run ended
        rows.append((s, end, *key))
    write_contacts(a.out, rows)
    print(f"{a.out}: {len(rows)} contacts", file=sys.stderr)


def cmd_one_msgs(a):
    host = re.compile(r"(\d+)$")
    with open(a.out, "w", newline="") as out:
        w = csv.writer(out)
        w.writerow(["t", "id", "src", "dst", "size"])
        n = 0
        for line in open(a.input):
            if line.startswith("#"):
                continue
            f = line.split()
            if len(f) < 5:
                continue
            t, mid, size, src, dst = float(f[0]), f[1], int(f[2]), f[3], f[4]
            w.writerow([fmt(t), mid, host.search(src).group(1), host.search(dst).group(1), size])
            n += 1
    print(f"{a.out}: {n} messages", file=sys.stderr)


def cmd_workload(a):
    """Like ONE's MessageEventGenerator: a message every U(interval) s from a
    uniformly random device to another one, size U(size) bytes."""
    rows = read_contacts(a.contacts)
    n = a.nodes or (max(max(r[2], r[3]) for r in rows) + 1)
    end = a.end if a.end is not None else max(r[1] for r in rows)
    lo, hi = (float(x) for x in a.interval.split(","))
    smin, smax = (int(x) for x in a.size.split(","))
    rng = random.Random(a.seed)
    t = a.start + rng.uniform(lo, hi)
    k = 0
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "id", "src", "dst", "size"])
        while t < end:
            src = rng.randrange(n)
            dst = rng.randrange(n - 1)
            dst += dst >= src
            k += 1
            w.writerow([fmt(round(t, 1)), f"M{k}", src, dst, rng.randint(smin, smax)])
            t += rng.uniform(lo, hi)
    print(f"{a.out}: {k} messages over {end - a.start:.0f} s, {n} devices", file=sys.stderr)


def cmd_one_events(a):
    contacts = read_contacts(a.contacts)
    gws = sorted(parse_ranges(a.gateways))
    gw = set(gws)
    ev = []  # (time, order, line); downs before ups at the same instant
    for s, e, i, j in contacts:
        if i in gw and j in gw:
            continue  # always connected
        ev.append((s, 1, f"{fmt(s)} CONN {i} {j} up"))
        ev.append((e, 0, f"{fmt(e)} CONN {i} {j} down"))
    for x in range(len(gws)):
        for y in range(x + 1, len(gws)):
            ev.append((0.0, 1, f"0 CONN {gws[x]} {gws[y]} up"))
    if a.messages:
        with open(a.messages) as f:
            for m in csv.DictReader(f):
                t = float(m["t"])
                ev.append((t, 2, f"{fmt(t)} C {m['id']} {m['src']} {m['dst']} {m['size']}"))
    ev.sort(key=lambda x: (x[0], x[1]))
    with open(a.out, "w") as f:
        for _, _, line in ev:
            f.write(line + "\n")
    print(f"{a.out}: {len(ev)} events ({len(gws)} gateways)", file=sys.stderr)


def cmd_stats(a):
    rows = read_contacts(a.contacts)
    n = max(max(r[2], r[3]) for r in rows) + 1
    durs = sorted(e - s for s, e, _, _ in rows)
    end = max(r[1] for r in rows)
    pairs = len({(r[2], r[3]) for r in rows})
    print(f"devices {n}, contacts {len(rows)}, pairs {pairs}, span {end/3600:.1f} h, "
          f"median contact {durs[len(durs)//2]:.0f} s, mean {sum(durs)/len(durs):.0f} s")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = p.add_subparsers(dest="cmd", required=True)

    c = sp.add_parser("crawdad")
    c.add_argument("input")
    c.add_argument("--internal-max", type=int, required=True, help="highest id of the experiment's own iMotes")
    c.add_argument("--exclude", default="", help="ids to leave out, e.g. 1-20")
    c.add_argument("--min-dur", type=float, default=60.0)
    c.add_argument("--out", required=True)
    c.add_argument("--map")
    c.set_defaults(f=cmd_crawdad)

    c = sp.add_parser("one-conn")
    c.add_argument("input")
    c.add_argument("--end", type=float)
    c.add_argument("--out", required=True)
    c.set_defaults(f=cmd_one_conn)

    c = sp.add_parser("one-msgs")
    c.add_argument("input")
    c.add_argument("--out", required=True)
    c.set_defaults(f=cmd_one_msgs)

    c = sp.add_parser("workload")
    c.add_argument("--contacts", required=True)
    c.add_argument("--nodes", type=int)
    c.add_argument("--interval", default="25,35")
    c.add_argument("--size", default="500000,1000000")
    c.add_argument("--start", type=float, default=0.0)
    c.add_argument("--end", type=float)
    c.add_argument("--seed", type=int, default=1)
    c.add_argument("--out", required=True)
    c.set_defaults(f=cmd_workload)

    c = sp.add_parser("one-events")
    c.add_argument("--contacts", required=True)
    c.add_argument("--messages")
    c.add_argument("--gateways", default="")
    c.add_argument("--out", required=True)
    c.set_defaults(f=cmd_one_events)

    c = sp.add_parser("stats")
    c.add_argument("contacts")
    c.set_defaults(f=cmd_stats)

    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
