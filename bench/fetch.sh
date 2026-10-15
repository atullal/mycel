#!/usr/bin/env bash
# Fetch the external tools and datasets the benchmarks and the simulator use
# (docs/BENCHMARKS.md, docs/SIMULATION.md). Everything lands in
# bench/external/ and bench/data/ (both gitignored: none of it may be
# redistributed from this repository).
#
#   bench/fetch.sh            # tools + traces
#   bench/fetch.sh traces     # CRAWDAD Haggle contact traces only
#   bench/fetch.sh tools      # The ONE only
#   bench/fetch.sh latency    # WonderNetwork's global ping sample (mycel-sim's internet latency)
#   bench/fetch.sh dataport <haggle.tar.gz> [nus.sql.gz]
#                             # unpack archives downloaded from IEEE DataPort
#                             # (free account): every Haggle experiment, the
#                             # Cambridge city traces, the NUS Bluetooth trace
#
# The simulator replays these with MYCEL_TRACE, e.g.
#   MYCEL_TRACE=bench/data/infocom2006/contacts.Exp6.dat cargo run --release -p mycel-sim -- trace-replay
set -euo pipefail
cd "$(dirname "$0")"
WHAT="${1:-all}"

# Pinned upstream commits (the versions BENCHMARKS.md reports).
ONE_REPO=https://github.com/akeranen/the-one.git
ONE_COMMIT=c973bfb892ee3d624549a0142018f4d1dedf17d7

# CRAWDAD cambridge/haggle iMote traces (Scott, Gass, Crowcroft, Hui, Diot,
# Chaintreau; CRAWDAD, doi:10.15783/C70011, CC BY 4.0 per IEEE DataPort).
# IEEE DataPort needs a login, so we take the unmodified files from the mobemu
# repository (Ciobanu et al.), which redistributes them. Terms: cite the
# dataset, don't try to identify people, don't re-share the data.
TRACES=https://raw.githubusercontent.com/raduciobanu/mobemu/master/traces

# WonderNetwork / WonderProxy, "A day in the life of the internet" (19-20 July
# 2020, ~250 servers pinging each other hourly):
# https://wonderproxy.com/blog/a-day-in-the-life-of-the-internet/
# Their terms: credit and link to them as the source. Their published sample
# only; never scrape wondernetwork.com's live pages.
PINGS=https://wp-public-data.s3.amazonaws.com/pings

fetch() { # url dest
  [ -s "$2" ] && return 0
  mkdir -p "$(dirname "$2")"
  curl -sfL --retry 3 -o "$2.part" "$1" && mv "$2.part" "$2"
  echo "fetched $2"
}

clone() { # repo commit dir
  if [ ! -d "$3/.git" ]; then
    git clone -q "$1" "$3"
  fi
  git -C "$3" fetch -q --depth 1 origin "$2" 2>/dev/null || true
  git -C "$3" checkout -q "$2"
  echo "$3 at $(git -C "$3" rev-parse --short HEAD)"
}

if [ "$WHAT" = all ] || [ "$WHAT" = traces ]; then
  fetch "$TRACES/cambridge-haggle-imote-infocom2006/contacts.Exp6.dat" data/infocom2006/contacts.Exp6.dat
  fetch "$TRACES/cambridge-haggle-imote-infocom2006/Exp6.README"       data/infocom2006/Exp6.README
  fetch "$TRACES/cambridge-haggle-imote-infocom2006/General.README"    data/infocom2006/General.README
  fetch "$TRACES/cambridge-haggle-imote-infocom/contacts.Exp3.dat"     data/infocom2005/contacts.Exp3.dat
  fetch "$TRACES/cambridge-haggle-imote-infocom/Exp3.README.txt"       data/infocom2005/Exp3.README.txt
  fetch "$TRACES/cambridge-haggle-imote-cambridge/contacts.Exp2.dat"   data/cambridge/contacts.Exp2.dat
  fetch "$TRACES/cambridge-haggle-imote-cambridge/Exp2.README.txt"     data/cambridge/Exp2.README.txt
fi

if [ "$WHAT" = all ] || [ "$WHAT" = tools ]; then
  mkdir -p external
  clone "$ONE_REPO" "$ONE_COMMIT" external/the-one
fi

if [ "$WHAT" = latency ]; then
  fetch "$PINGS/servers-2020-07-19.csv" data/wondernetwork/servers.csv
  if [ ! -s data/wondernetwork/pings.csv ]; then
    curl -fsSL "$PINGS/pings-2020-07-19-2020-07-20.csv.gz" | gunzip > data/wondernetwork/pings.csv.part
    mv data/wondernetwork/pings.csv.part data/wondernetwork/pings.csv
  fi
  wc -l data/wondernetwork/servers.csv data/wondernetwork/pings.csv
  echo "then: MYCEL_PINGS=bench/data/wondernetwork cargo run --release -p mycel-sim -- fit-latency"
fi

if [ "$WHAT" = dataport ]; then
  # 1. cambridge/haggle, doi:10.15783/C70011:
  #    https://ieee-dataport.org/open-access/crawdad-cambridgehaggle-v-2009-05-29
  # 2. nus/bluetooth (Natarajan, Motani, Srinivasan), doi:10.15783/C74K5N:
  #    https://ieee-dataport.org/open-access/crawdad-nusbluetooth
  [ $# -ge 2 ] || { sed -n '2,17p' "$0"; exit 1; }
  out=data/dataport
  mkdir -p "$out"
  tmp=$(mktemp -d)
  tar -xzf "$2" -C "$tmp"
  # contacts.ExpN.dat for the four experiments; city traces are per-node N.dat dirs
  find "$tmp" -name 'contacts.Exp*.dat' -exec cp {} "$out/" \;
  for d in $(find "$tmp" -type d -iname '*cambridge*city*' -o -type d -iname 'students' 2>/dev/null); do
    mkdir -p "$out/city-$(basename "$d")" && cp "$d"/*.dat "$out/city-$(basename "$d")/" 2>/dev/null || true
  done
  if [ $# -ge 3 ]; then
    # NUS Bluetooth: a SQL dump (table anon_logdata) -> "a,b,start,end"
    gunzip -c "$3" | python3 traces/nus_to_csv.py > "$out/nus-bluetooth.csv"
  fi
  ls -la "$out"
fi
