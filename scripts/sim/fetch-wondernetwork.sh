#!/usr/bin/env bash
# Fetch WonderNetwork's public sample of global pings (19–20 July 2020, ~250
# servers pinging each other hourly) for the simulator's internet latency.
#
# Source and credit: WonderNetwork / WonderProxy, "A day in the life of the
# internet", https://wonderproxy.com/blog/a-day-in-the-life-of-the-internet/
# Their terms: "If you do anything with these data, please credit & link to
# us as a data source." No redistribution licence is given, so the data stays
# out of the repository: this script downloads it into target/data/ (never
# scrape wondernetwork.com's live pages; this is their published sample).
#
# Then: cargo run --release -p mycel-sim -- fit-latency
set -euo pipefail
cd "$(dirname "$0")/../.."
out=target/data/wondernetwork
mkdir -p "$out"
base=https://wp-public-data.s3.amazonaws.com/pings
[ -s "$out/servers.csv" ] || curl -fsSL "$base/servers-2020-07-19.csv" -o "$out/servers.csv"
[ -s "$out/pings.csv" ] || curl -fsSL "$base/pings-2020-07-19-2020-07-20.csv.gz" | gunzip > "$out/pings.csv"
wc -l "$out"/servers.csv "$out"/pings.csv
