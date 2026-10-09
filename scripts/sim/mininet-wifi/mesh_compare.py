#!/usr/bin/env python3
"""Mininet-WiFi (https://github.com/intrig-unicamp/mininet-wifi): the same
ad-hoc topology four times, routed by batman-adv, olsrd, babeld, and Mycel's
mesh (mycel serve on each station, IP over the 802.11s/ad-hoc interface as a
network-interface link). Linux with root, mac80211_hwsim; run:

    sudo python3 scripts/sim/mininet-wifi/mesh_compare.py --proto batman_adv
    sudo python3 scripts/sim/mininet-wifi/mesh_compare.py --proto olsrd
    sudo python3 scripts/sim/mininet-wifi/mesh_compare.py --proto babeld
    sudo python3 scripts/sim/mininet-wifi/mesh_compare.py --proto mycel

Topology: a line of N stations 40 m apart (range 60 m), plus the same
positions mycel-sim's `city-block` scenario uses, so tier 1 numbers can be
compared with real kernels and real 802.11 MAC behaviour (collisions, rate
adaptation) that EmuNet doesn't model. Measures ping RTT end to end and
iperf3 throughput over 1..N-1 hops.
"""
import argparse
import time

from mininet.log import setLogLevel
from mn_wifi.cli import CLI
from mn_wifi.link import adhoc, wmediumd
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference

p = argparse.ArgumentParser()
p.add_argument("--proto", default="batman_adv", choices=["batman_adv", "olsrd", "babeld", "mycel"])
p.add_argument("-n", type=int, default=10)
p.add_argument("--cli", action="store_true")
a = p.parse_args()

setLogLevel("info")
net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
stas = [net.addStation(f"sta{i}", position=f"{10 + 40 * i},50,0", range=60) for i in range(a.n)]
net.setPropagationModel(model="logDistance", exp=4)
net.configureNodes()
for s in stas:
    proto = None if a.proto == "mycel" else a.proto
    net.addLink(s, cls=adhoc, intf=f"{s.name}-wlan0", ssid="mesh", mode="g", channel=5, proto=proto)
net.build()
if a.proto == "mycel":
    for i, s in enumerate(stas):
        s.cmd(f"../../../target/release/mycel serve --data /tmp/mycel-sta{i} --net lan --port 4000 &")
time.sleep(20)
src, dst = stas[0], stas[-1]
print(src.cmd(f"ping -c 20 {dst.IP()}"))
dst.cmd("iperf3 -s -D")
print(src.cmd(f"iperf3 -c {dst.IP()} -t 10"))
if a.cli:
    CLI(net)
net.stop()
