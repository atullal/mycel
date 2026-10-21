#!/usr/bin/env bash
# Writes the seed corpora in fuzz/seeds/ (docs/TESTING.md, "Fuzzing"):
# deterministically, so rerunning changes nothing unless an encoding did, and
# without deleting anything (regression-* inputs are never touched). See
# examples/seeds.rs.
#
#   fuzz/seeds.sh
#
# The generator is built with getrandom's `custom` backend (a fixed stream
# it defines itself) and with `fuzzing` (mycel-sync's helper that seals at a
# chosen time). Both flags go through RUSTFLAGS with an explicit --target,
# so they reach the generator and the crates it links but not build scripts
# or proc macros, and the build lands in its own directory
# (target/<host>/debug), apart from cargo-fuzz's.
set -euo pipefail
cd "$(dirname "$0")"
host=$(rustc -vV | sed -n 's/^host: //p')
RUSTFLAGS='--cfg fuzzing --cfg getrandom_backend="custom"' \
  exec cargo run --quiet --locked --example seeds --target "$host"
