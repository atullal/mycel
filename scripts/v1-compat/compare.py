"""Check the vectors a pre-release build printed against v1_vectors.rs.

Usage: python3 -I compare.py VECTORS_TXT V1_VECTORS_RS

VECTORS_TXT holds `VECTOR <NAME> <hex>` lines (gen_vectors.rs). Every
constant in V1_VECTORS_RS must have been printed with exactly its bytes,
and every printed vector must be pinned there. Exits non-zero otherwise.
"""

import re
import sys


def pinned(path):
    src = open(path, encoding="utf-8").read()
    out = {}
    for m in re.finditer(r"const (\w+): &\[&str\] = &\[(.*?)\];", src, re.S):
        out[m.group(1)] = "".join(re.findall(r'"([0-9a-f]*)"', m.group(2)))
    return out


def printed(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        parts = line.split()
        if len(parts) == 3 and parts[0] == "VECTOR":
            out[parts[1]] = parts[2]
    return out


def main():
    got, want = printed(sys.argv[1]), pinned(sys.argv[2])
    bad = 0
    for name in sorted(set(got) | set(want)):
        if name not in want:
            print(f"printed but not pinned: {name}")
            bad += 1
        elif name not in got:
            print(f"pinned but not printed: {name}")
            bad += 1
        elif got[name] != want[name]:
            print(f"DIFFERENT: {name}\n  printed {got[name]}\n  pinned  {want[name]}")
            bad += 1
    print(f"{len(want)} pinned vectors, {len(got)} printed, {bad} problems")
    sys.exit(1 if bad else 0)


main()
