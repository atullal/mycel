#!/usr/bin/env bash
# Rebuild the guest rules bundles and copy them into the host crate's test fixtures.
# Requires: rustup target add wasm32-unknown-unknown
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
fixtures="$here/../crates/mycel-rules/fixtures"

# cd so that rules/.cargo/config.toml (guest link flags) applies.
cd "$here"
cargo build --release --target wasm32-unknown-unknown -p chat-rules -p counter-rules

mkdir -p "$fixtures"
for name in chat_rules counter_rules; do
  cp "$here/target/wasm32-unknown-unknown/release/$name.wasm" "$fixtures/$name.wasm"
  printf '%-18s %6d bytes\n' "$name.wasm" "$(wc -c < "$fixtures/$name.wasm")"
done
