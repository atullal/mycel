#!/usr/bin/env bash
# Get the CRAWDAD contact traces the simulator replays (they can't be
# redistributed, so they aren't in the repository).
#
# 1. cambridge/haggle (Scott, Gass, Crowcroft, Hui, Diot, Chaintreau),
#    doi:10.15783/C70011 — iMote Bluetooth sightings: Intel (Exp1), Cambridge
#    Computer Lab (Exp2), Infocom 2005 (Exp3), Infocom 2006 (Exp6), Cambridge city.
#    https://ieee-dataport.org/open-access/crawdad-cambridgehaggle-v-2009-05-29
# 2. nus/bluetooth (Natarajan, Motani, Srinivasan), doi:10.15783/C74K5N
#    https://ieee-dataport.org/open-access/crawdad-nusbluetooth
#
# Both need a (free) IEEE DataPort account: log in in a browser, download the
# archives, and pass them to this script. Terms: cite the dataset, don't try
# to identify people, don't re-share the data (point people to CRAWDAD).
#
#   scripts/traces/fetch-crawdad.sh ~/Downloads/cambridge-haggle-imote.tar.gz [nus.sql.gz]
#   MYCEL_TRACE=target/data/traces/contacts.Exp6.dat cargo run --release -p mycel-sim -- trace-replay
set -euo pipefail
cd "$(dirname "$0")/../.."
out=target/data/traces
mkdir -p "$out"
if [ $# -lt 1 ]; then
  sed -n '2,20p' "$0"
  exit 1
fi
haggle="$1"
tmp=$(mktemp -d)
tar -xzf "$haggle" -C "$tmp"
# contacts.ExpN.dat for the four experiments; city traces are per-node N.dat dirs
find "$tmp" -name 'contacts.Exp*.dat' -exec cp {} "$out/" \;
for d in $(find "$tmp" -type d -iname '*cambridge*city*' -o -type d -iname 'students' 2>/dev/null); do
  mkdir -p "$out/city-$(basename "$d")" && cp "$d"/*.dat "$out/city-$(basename "$d")/" 2>/dev/null || true
done
if [ $# -ge 2 ]; then
  # NUS Bluetooth: a SQL dump (table anon_logdata). Convert sightings to
  # "a,b,start,end": consecutive scans (~30 s apart) of the same pair merge.
  gunzip -c "$2" | python3 "$(dirname "$0")/nus_to_csv.py" > "$out/nus-bluetooth.csv"
fi
ls -la "$out"
