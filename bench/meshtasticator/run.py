#!/usr/bin/env python3
"""Meshtasticator (Meshtastic's discrete-event simulator) without its GUI:
managed flooding over LoRa, as in its batchSim.py, plus a dump of each run's
topology and direct messages so Mycel's router can be run on the same graph
(bench/mycel-bench `mesh-routing`).

  bench/external/venv/bin/python bench/meshtasticator/run.py [--quick]

Writes bench/results/meshtasticator/<mode>-n<nodes>-h<hops>-r<rep>.json and
bench/results/meshtasticator/summary.csv.

Differences from batchSim.py's defaults, so both simulators see one fixed
graph: node movement off and asymmetric links off. Everything else is
Meshtasticator's default (LONG_FAST, 3GPP suburban path loss, 15 x 15 km,
40-byte payloads, a message per node every 100 s on average, 30 minutes).
"""
import argparse
import csv
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MT = os.path.join(HERE, "..", "external", "Meshtasticator")
OUT = os.path.join(HERE, "..", "results", "meshtasticator")
sys.path.insert(0, MT)

from lib.common import find_random_position  # noqa: E402
from lib.config import Config  # noqa: E402
from lib.discrete_event_sim import DiscreteEventSim  # noqa: E402
from lib.node import NodeConfig  # noqa: E402
from lib.phy import airtime  # noqa: E402
from lib.point import Point  # noqa: E402


class TempNode:
    def __init__(self, conf, x, y):
        self.position = Point(x, y, conf.HM)


def config(nodes, hops, dms, seed):
    c = Config()
    c.NR_NODES = nodes
    c.hopLimit = hops
    c.DMs = dms
    c.MOVEMENT_ENABLED = False
    c.MODEL_ASYMMETRIC_LINKS = False
    c.SEED = seed
    c.update_router_dependencies()
    return c


def placement(conf, nodes, rep):
    """batchSim.py's placement: seeded by repetition, each node in range of another."""
    random.seed(rep)
    while True:
        placed = []
        for _ in range(nodes):
            x, y = find_random_position(conf, placed)
            if x is None:
                break
            placed.append(TempNode(conf, x, y))
        if len(placed) == nodes:
            return [(t.position.x, t.position.y) for t in placed]


def run(nodes, hops, dms, rep):
    seed = rep
    conf = config(nodes, hops, dms, seed)
    coords = placement(conf, nodes, rep)
    random.seed(seed)
    cfgs = [
        NodeConfig(node_id=i, position=Point(x, y, conf.HM), period=conf.PERIOD, tx_power=conf.PTX,
                   freq=conf.FREQ, antenna_gain=conf.GL, hop_limit=conf.hopLimit)
        for i, (x, y) in enumerate(coords)
    ]
    sim = DiscreteEventSim(conf, cfgs)
    sim.run_simulation()
    r = sim.get_results()
    nodes_ = r["nodes"]
    packets = r["packets"]
    sens = conf.current_preset["sensitivity"]
    pl = sim.mutated_state.baseline_pathloss_matrix
    links = [
        [i, j]
        for i in range(nodes)
        for j in range(i + 1, nodes)
        if conf.PTX + 2 * conf.GL - pl[i][j] >= sens
    ]
    msgs = r["messages"]
    out = {
        "mode": "dm" if dms else "broadcast",
        "nodes": nodes,
        "hop_limit": hops,
        "rep": rep,
        "simtime_ms": conf.SIMTIME,
        "packet_len": conf.PACKETLENGTH,
        "airtime_ms": airtime(conf, conf.current_preset["sf"], conf.current_preset["cr"], conf.PACKETLENGTH, conf.current_preset["bw"]),
        "positions": coords,
        "links": links,
        "messages": [[m.origTxNodeId, m.destId, m.genTime, m.seq] for m in msgs],
        "transmissions": sum(n.nrPacketsSent for n in nodes_),
        "collision_rate": float(r["collisionRate"]),
        "mean_delay_ms": float(r["meanDelay"]),
        "tx_air_utilization": float(r["txAirUtilizationRate"]),
    }
    if dms:
        got = {(p.seq) for p in packets if not p.isAck and p.receivedAtN[p.destId]}
        out["dm_sent"] = len(msgs)
        out["dm_delivered"] = sum(1 for m in msgs if m.seq in got)
    else:
        out["reach"] = float(r["nodeReach"])
        out["usefulness"] = float(r["usefulness"])
    # airtime of a Mycel-sized announcement (~180 B signed) on the same modem
    out["airtime_180b_ms"] = airtime(conf, conf.current_preset["sf"], conf.current_preset["cr"], 180, conf.current_preset["bw"])
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--quick", action="store_true")
    a = p.parse_args()
    os.makedirs(OUT, exist_ok=True)
    reps = 2 if a.quick else 3
    sizes = [10, 25] if a.quick else [10, 25, 50]
    plans = [("broadcast", n, h) for n in sizes for h in (1, 3, 5, 7)]
    plans += [("dm", n, h) for n in sizes for h in (3, 7)]
    rows = []
    for mode, n, h in plans:
        for rep in range(reps):
            name = f"{mode}-n{n}-h{h}-r{rep}"
            path = os.path.join(OUT, name + ".json")
            if os.path.exists(path):
                res = json.load(open(path))
            else:
                res = run(n, h, mode == "dm", rep)
                json.dump(res, open(path, "w"))
            row = {k: res.get(k) for k in ("mode", "nodes", "hop_limit", "rep", "transmissions", "collision_rate",
                                           "mean_delay_ms", "reach", "usefulness", "dm_sent", "dm_delivered")}
            row["links"] = len(res["links"])
            row["messages"] = len(res["messages"])
            rows.append(row)
            print(name, {k: row[k] for k in ("transmissions", "reach", "usefulness", "dm_sent", "dm_delivered")}, flush=True)
    with open(os.path.join(OUT, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
