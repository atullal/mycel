# Wire version 1 against real pre-release code

`run.sh` checks the claims of docs/PROTOCOL.md §5 against the pre-release
code itself, not against this build pretending to be it:

1. **Golden vectors.** It checks out main `98d9b7b` (the commit before
   versioning) with `git archive`, drops in `gen_vectors.rs`, which prints
   every vector with that commit's own encoders from the inputs of
   `crates/mycel-net/src/mesh/v1_vectors.rs`, and `compare.py` checks the
   two match byte for byte (and that neither has a vector the other lacks).
2. **Cross-build.** It builds `old_peer.rs` in that checkout and runs it
   beside `crates/mycel-net/tests/v1_compat.rs` of this build. They swap
   addresses and contact cards through files and talk over loopback: the
   connection lands on wire version 1, a space created by this build syncs
   to the old one, the old one's entry syncs back, and each fetches the
   other's card.

```sh
scripts/v1-compat/run.sh                      # against 98d9b7b, in target/v1-compat
BASE=dev-2026-10-09-apps scripts/v1-compat/run.sh target/v1-compat-release
```

The first run builds the old `mycel-net` from scratch in the work directory
(a few minutes and a few GB of disk; `CARGO_BUILD_JOBS` defaults to 3).

Last run (2026-10-21, branch `v2/wire-versioning`): both steps passed
against `98d9b7b` and against the `dev-2026-10-09-apps` release (33 of 33
vectors, cross-build scenario in under a second).

Not covered: mesh hops and store-and-forward between builds, calls, and
everything a build *accepts* beyond these exchanges (the release validates
some data differently from `98d9b7b`, see PROTOCOL.md §5). A vector added
to `v1_vectors.rs` must be added to `gen_vectors.rs` too, with the same
inputs, and printed by the old code, never by this build.
