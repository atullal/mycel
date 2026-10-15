# Contributing to Mycel

Thank you for helping. This page covers how to build and test Mycel, and
what we look for in a change.

By taking part, you agree to the [code of conduct](CODE_OF_CONDUCT.md).

## Bugs, ideas and vulnerabilities

- **Security vulnerabilities:** never in a public issue. Report them
  privately, as [SECURITY.md](SECURITY.md) describes.
- **Bugs:** open an issue with the bug report form. Say which platform and
  build you ran, what you did, what you expected, and what happened. Attach
  `mycel.log` from the data folder if you can, after removing anything
  private.
- **Ideas and larger changes:** open an issue first, so we can agree on the
  approach before you spend time on code.

## What you need

- **Rust**, through [rustup](https://rustup.rs). The toolchain version,
  rustfmt, clippy and the WebAssembly target are pinned in
  `rust-toolchain.toml`; rustup installs them the first time you run `cargo`
  in the repository.
- **Node.js 22.18 or later**, with npm. The TypeScript tests use Node's
  built-in type stripping.
- **On Linux**, the libraries for the webview, D-Bus and audio. On Debian or
  Ubuntu:

  ```sh
  sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
    librsvg2-dev libdbus-1-dev libasound2-dev libssl-dev pkg-config
  ```

- **To run the desktop app:** the Tauri CLI,
  `cargo install tauri-cli --version '^2' --locked`.
- **For the iPhone, iPad and Android apps:** Xcode, or the Android SDK, NDK
  and a JDK. The header of each `scripts/package-*.sh` lists what it needs.

## Build and run

```sh
npm ci                             # web dependencies
cargo build --workspace            # every Rust crate
(cd apps/host && cargo tauri dev)  # the desktop app, with live reload
```

The command-line device, with the web UI on <http://127.0.0.1:7777>:

```sh
npm run build                      # the web UI it serves
cargo run -p mycel-cli -- serve
```

The rules bundles (WebAssembly) are built separately, and copied into the
rules runtime's test fixtures:

```sh
rules/build.sh
```

Packaged apps: `scripts/package-mac.sh`, `scripts/package-ios.sh` and
`scripts/package-android.sh`. Linux and Windows installers are built by the
`Apps` workflow.

## Test

```sh
cargo test --workspace             # Rust
npm run typecheck && npm test      # TypeScript
```

Things to know:

- **macOS asks for Local Network permission.** Three LAN discovery tests
  (`lan_discovery_via_mdns`, `one_path_per_interface`,
  `sync_over_an_interface_with_ip_off`) fail with "No route to host" if your
  terminal doesn't have it. Allow it in System Settings > Privacy & Security
  > Local Network.
- **Some tests time real work** (sync throughput, calls, multipath). They can
  miss their deadline on a loaded machine. CI builds tests with
  `CARGO_PROFILE_DEV_OPT_LEVEL=2` and retries a failed test twice; locally,
  rerun a failed test on its own before assuming it's broken.
- **Security regression tests are never retried.** If one fails, it's a
  real failure.

## Before you open a pull request

CI runs all of these; running them first saves a round trip.

```sh
cargo fmt --all
cargo fmt --all --manifest-path rules/Cargo.toml
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run typecheck && npm test && npm run build
```

Also run, if you have them installed: `cargo deny check` (dependencies,
licences and advisories), `typos` (spelling), and `actionlint` and `zizmor`
if you changed a workflow.

## Style

- **Formatting** is whatever `rustfmt` produces with `rustfmt.toml`. Don't
  format by hand, and don't mix reformatting with other changes.
- **Lints:** clippy must pass with `-D warnings`. The workspace lints are in
  the root `Cargo.toml`. If you must silence a lint, use `#[expect(...)]` on
  the smallest item, with a comment that says why.
- **`unsafe`:** only where there is no safe way, with a `// SAFETY:` comment
  that explains why it is sound.
- **Errors:** return them; don't panic on input from a peer, a file or the
  network. Everything a peer sends is untrusted.
- **Comments and docs** say why, in plain, short sentences.

## Commits and pull requests

- Keep a pull request to one change. Split refactors from behaviour changes.
- Write commit subjects in the imperative ("Fix…", "Add…"), under 72
  characters. Use the body to explain why.
- Add or update tests for every behaviour change, and docs for every
  user-visible one.
- **Wire and storage compatibility.** Mycel doesn't yet promise
  compatibility between builds: every device has to run the same build. If
  your change alters what goes over the network or what is stored on disk,
  say so in the pull request.
- Don't commit secrets, signing keys, personal data or build output.
  `.gitignore` covers the usual files; check `git status` anyway.
- New dependencies need a reason. They must pass `cargo deny check`; prefer
  crates that are widely used and maintained.

### Sign your commits off (DCO)

Every commit needs a `Signed-off-by` line, which `git commit -s` adds:

```text
Signed-off-by: Your Name <you@example.com>
```

It certifies the [Developer Certificate of Origin](https://developercertificate.org):
that you wrote the change, or otherwise have the right to submit it under
the project's licence. Use your real name, or the name you are known by.
To sign off commits you already made: `git rebase --signoff main`.

## Vendored code

`vendor/` holds patched copies of a few upstream crates (Iroh, its QUIC
stack, and others). Before you touch anything there:

1. Read that crate's `MYCEL_PATCH.md`.
2. Keep the change as small as possible, mark it `MYCEL PATCH`, describe it in
   `MYCEL_PATCH.md`, and add a test.
3. Never reformat vendored files or remove their licence files and notices.

[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) lists each vendored crate,
its upstream and its licence.

## Licence

Mycel is licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT), at your option. Unless you explicitly state otherwise,
any contribution you intentionally submit for inclusion in the work, as
defined in the Apache-2.0 licence, shall be dual licensed as above, without
any additional terms or conditions.
