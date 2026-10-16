#!/usr/bin/env bash
# Run on a configured development machine with Rust, Node, and cargo-audit.
# No retries: a failed security regression must remain a failure.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo test --locked --no-fail-fast \
  -p mycel-crypto -p mycel-trust -p mycel-sync -p mycel-rules \
  -p mycel-net -p mycel-node --lib
cargo test --locked -p mycel-net --test blob_security
cargo test --locked -p mycel-node --test attachment_security
cargo test --locked -p mycel-host --lib
npm run typecheck
npm run build
npm audit --audit-level=low
# RustSec advisories, including unsound and unmaintained crates, through the
# same policy CI uses (deny.toml: each accepted advisory has its reason there).
cargo deny --locked check advisories
