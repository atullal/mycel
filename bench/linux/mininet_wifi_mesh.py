#!/usr/bin/env python3
"""Mycel's mesh vs batman-adv / OLSR / Babel on one emulated 802.11 ad-hoc
chain (Mininet-WiFi). Untested: written on macOS; see bench/linux/README.md.

  sudo python3 bench/linux/mininet_wifi_mesh.py --nodes 10 --proto babeld
  sudo python3 bench/linux/mininet_wifi_mesh.py --nodes 10 --proto mycel [--kill-middle]

Stations sit on a line, `--spacing` metres apart with a range that only
reaches the next one, so the ends are N-1 hops apart. Output: one JSON line
with time-to-reachable, end-to-end loss and RTT (ping), throughput (iperf3)
for the IP routers; for Mycel, time until the far end shows up as a mesh
peer (`mycel call network_status`) and its route.
"""
import argparse
import json
import os
import time

from mininet.log import setLogLevel
from mn_wifi.link import adhoc, wmediumd
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference

MYCEL = os.environ.get("MYCEL_BIN", os.path.abspath("target/release/mycel"))


def build(n, spacing, proto):
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
    stas = []
    for i in range(n):
        ip = f"10.0.0.{i + 1}/8"
        stas.append(net.addStation(f"sta{i}", ip=ip, position=f"{10 + i * spacing},10,0", range=spacing * 1.2))
    net.setPropagationModel(model="logDistance", exp=4)
    net.configureNodes()
    for s in stas:
        kw = {"proto": proto} if proto in ("batman_adv", "olsrd", "babeld") else {}
        net.addLink(s, cls=adhoc, intf=f"{s.name}-wlan0", ssid="mycelmesh", mode="g", channel=5, ht_cap="HT40+", **kw)
    net.build()
    return net, stas


def wait_ping(src, dst_ip, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if "1 received" in src.cmd(f"ping -c1 -W1 {dst_ip}"):
            return time.time() - t0
    return None


def run_ip(net, stas, a):
    far = stas[-1]
    reach = wait_ping(stas[0], far.IP())
    ping = stas[0].cmd(f"ping -c 50 -i 0.2 {far.IP()}")
    far.cmd("iperf3 -s -D")
    iperf = stas[0].cmd(f"iperf3 -c {far.IP()} -t 10 -J")
    out = {"time_to_reachable_s": reach, "ping": ping.strip().splitlines()[-2:]}
    try:
        out["iperf_mbps"] = json.loads(iperf)["end"]["sum_received"]["bits_per_second"] / 1e6
    except Exception:
        out["iperf_raw"] = iperf[-500:]
    if a.kill_middle:
        mid = stas[len(stas) // 2]
        mid.cmd(f"ip link set {mid.name}-wlan0 down")
        out["time_to_recover_s"] = wait_ping(stas[0], far.IP())
    return out


def run_mycel(net, stas, a):
    for s in stas:
        s.cmd(f"MYCEL_LINKS=iface MYCEL_IP=0 {MYCEL} serve --data /tmp/mycel-{s.name} --name {s.name} --net lan "
              f"--http 127.0.0.1:7777 > /tmp/mycel-{s.name}.log 2>&1 &")
    far = stas[-1]
    far_id = None
    t0 = time.time()
    while time.time() - t0 < 30 and not far_id:
        far_id = far.cmd(f"{MYCEL} id --data /tmp/mycel-{far.name}").strip() or None
        time.sleep(1)
    reach = None
    t0 = time.time()
    while time.time() - t0 < 180:
        st = stas[0].cmd(f"{MYCEL} call network_status --data /tmp/mycel-{stas[0].name}")
        if far.name in st:
            reach = time.time() - t0
            break
        time.sleep(1)
    return {"time_to_reachable_s": reach, "status": stas[0].cmd(f"{MYCEL} call network_status --data /tmp/mycel-{stas[0].name}")[-2000:]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--nodes", type=int, default=10)
    p.add_argument("--spacing", type=float, default=40.0)
    p.add_argument("--proto", choices=["mycel", "batman_adv", "olsrd", "babeld"], default="mycel")
    p.add_argument("--kill-middle", action="store_true")
    a = p.parse_args()
    setLogLevel("warning")
    net, stas = build(a.nodes, a.spacing, a.proto)
    try:
        res = run_mycel(net, stas, a) if a.proto == "mycel" else run_ip(net, stas, a)
        res.update({"proto": a.proto, "nodes": a.nodes, "hops": a.nodes - 1})
        print(json.dumps(res))
    finally:
        net.stop()


if __name__ == "__main__":
    main()
