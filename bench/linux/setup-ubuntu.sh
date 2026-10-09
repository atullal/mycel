#!/usr/bin/env bash
# Installs the Linux-only benchmark tools (bench/linux/README.md) on Ubuntu 24.04.
# Untested: written on macOS. Everything is built under ~/mycel-bench.
set -euo pipefail
W="$HOME/mycel-bench"
mkdir -p "$W"

sudo apt-get update
sudo apt-get install -y build-essential cmake git curl pkg-config python3 python3-pip python3-venv \
  libglib2.0-dev libdbus-1-dev iperf3 tcpdump iw wireless-tools \
  babeld olsrd batctl

# Rust (for the mycel binary)
command -v cargo >/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Shadow (https://shadow.github.io/docs/guide/install_shadow.html)
if [ ! -d "$W/shadow" ]; then
  git clone https://github.com/shadow/shadow.git "$W/shadow"
  (cd "$W/shadow" && ./setup build --clean && ./setup install)
fi

# Mininet-WiFi (https://mininet-wifi.github.io/get-started/)
if [ ! -d "$W/mininet-wifi" ]; then
  git clone https://github.com/intrig-unicamp/mininet-wifi.git "$W/mininet-wifi"
  (cd "$W/mininet-wifi" && sudo util/install.sh -Wlnfv && sudo util/install.sh -B -E -O)
fi

echo "Done. Shadow: ~/.local/bin/shadow; Mininet-WiFi: sudo python3 bench/linux/mininet_wifi_mesh.py"
