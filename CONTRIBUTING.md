# Contributing to Mycel

This guide is for anyone who wants to change Mycel's code or documentation.
It covers setting up, building and running, the checks to run before a pull
request, how a change is reviewed and merged, and the rules for commits,
dependencies and vendored code.

For anything larger than a small fix, open an issue first, so the approach
is agreed before you spend time on code. Security vulnerabilities are never
reported in an issue or a pull request: [SECURITY.md](SECURITY.md) says how
to report one privately. By taking part, you agree to the
[code of conduct](CODE_OF_CONDUCT.md).

## Set up

You need:

- Rust, through [rustup](https://rustup.rs). `rust-toolchain.toml` pins the
  toolchain version, rustfmt, clippy and the WebAssembly target. rustup
  installs them the first time you run `cargo` in the repository.
- Node.js 22.18 or later, with npm. The TypeScript tests use Node's built-in
  type stripping, which sets the minimum (`engines` in `package.json`).
- On Linux, the libraries for the web view, D-Bus and audio. On Debian or
  Ubuntu:

  ```sh
  sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
    librsvg2-dev libdbus-1-dev libasound2-dev libssl-dev pkg-config
  ```

- The Tauri CLI, to run the desktop app:

  ```sh
  cargo install tauri-cli --version '^2' --locked
  ```

- Xcode for the iPhone and iPad app, or the Android SDK, the NDK and a JDK
  for the Android app. The header of each `scripts/package-*.sh` lists what
  that script needs.

## Build and run

```sh
npm ci                             # web dependencies
cargo build --workspace            # every Rust crate
(cd apps/host && cargo tauri dev)  # the desktop app, with live reload
```

On Windows, add `--exclude mycel-sim --exclude mycel-bench` to the workspace
commands, as CI does: the simulator and the benchmarks are Unix development
tools.

The command-line device runs the same UI in a browser, on
<http://127.0.0.1:7777>:

```sh
npm run build                      # the web UI it serves
cargo run -p mycel-cli -- serve
```

To work on the UI without a device, start the Vite development server. In a
plain browser the UI talks to an in-memory mock of the runtime, which
[`packages/sdk/README.md`](packages/sdk/README.md) describes:

```sh
npm run dev                        # http://localhost:1420
```

The rules bundles are WebAssembly and are built separately. The built
bundles are checked in under `crates/mycel-rules/fixtures/`, and the runtime
embeds the chat rules from there. After a change under `rules/`, rebuild
them:

```sh
rules/build.sh
```

The packaged apps come from `scripts/package-mac.sh`,
`scripts/package-ios.sh` and `scripts/package-android.sh`. The `Apps`
workflow builds the Linux and Windows installers.
[PLATFORMS.md](docs/PLATFORMS.md) has the details for each system.

## Run the tests

```sh
cargo test --workspace             # Rust
npm run typecheck && npm test      # TypeScript
```

Three things to know before you trust a failure:

- On macOS, three LAN discovery tests (`lan_discovery_via_mdns`,
  `one_path_per_interface` and `sync_over_an_interface_with_ip_off`) fail
  with "No route to host" unless your terminal has Local Network permission.
  Allow it in System Settings > Privacy & Security > Local Network.
- Some tests time real work, such as sync throughput, calls and multipath,
  and can miss their deadline on a loaded machine. CI builds the tests with
  `CARGO_PROFILE_DEV_OPT_LEVEL=2` and retries a failed test twice. Locally,
  rerun a failed test on its own before you assume it is broken.
- Security regression tests are never retried. CI runs them in a job of
  their own, and a failure there is a real failure.

[TESTING.md](docs/TESTING.md) describes every suite, the tests that are
ignored by default, and what is not tested.

## Code style

- Formatting is whatever `rustfmt` produces with `rustfmt.toml`. Don't
  format by hand, and don't mix reformatting with other changes.
- Clippy must pass with `-D warnings`. The workspace lints are in the root
  `Cargo.toml`. If you must silence a lint, use `#[expect(...)]` on the
  smallest item, with a comment that says why.
- Use `unsafe` only where there is no safe way, with a `// SAFETY:` comment
  that explains why it is sound.
- Return errors. Don't panic on input from a peer, a file or the network:
  everything a peer sends is untrusted.
- Comments and docs say why, in plain, short sentences.

## Before you open a pull request

These are the local forms of the main CI jobs. Running them first saves a
round trip.

```sh
cargo fmt --all
cargo fmt --all --manifest-path rules/Cargo.toml
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run typecheck && npm test && npm run build
```

CI runs further checks that need extra tools. Run the ones that apply to
your change, if you have the tool installed:

- `typos` checks the spelling of code, comments and docs. `_typos.toml`
  holds the accepted words.
- `cargo deny check` checks dependencies, licences and advisories. Run it
  after any change to a `Cargo.toml` or to `Cargo.lock`.
- `actionlint` and `zizmor .github/workflows .github/dependabot.yml` check
  the workflows. Run them after a change under `.github/`.

[TESTING.md](docs/TESTING.md) lists every CI job with the command it runs,
including the documentation build and the rules workspace.

## How changes land

Every change reaches `main` through a pull request. A pull request can be
merged once it has one approving review from a code owner
(`.github/CODEOWNERS`) and the `CI result` check has passed. `CI result` is
the last job of the CI workflow, and it fails if any other job failed. Pull
requests are merged as a squash or as a merge commit.

A pull request should follow these rules:

- Keep a pull request to one change. Split refactors from behaviour changes.
- Add or update tests for every behaviour change, and docs for every
  user-visible one.
- Say so in the pull request if your change alters what goes over the
  network or what is stored on disk. Mycel doesn't yet promise compatibility
  between builds: every device has to run the same build.
- Write commit subjects in the imperative ("Fix…", "Add…"), under 72
  characters. Use the body to explain why.
- Don't commit secrets, signing keys, personal data or build output.
  `.gitignore` covers the usual files; check `git status` anyway.

## Sign your commits off (DCO)

Every commit needs a `Signed-off-by` line, which `git commit -s` adds:

```text
Signed-off-by: Your Name <you@example.com>
```

It certifies the [Developer Certificate of Origin](https://developercertificate.org):
that you wrote the change, or otherwise have the right to submit it under
the project's licence. Use your real name, or the name you are known by.
To sign off commits you already made: `git rebase --signoff main`.

The `Sign-off (DCO)` job in CI fails a pull request in which any commit,
merge commits aside, lacks the line.

## Dependencies

A new dependency needs a reason, given in the pull request. Prefer crates
that are widely used and maintained.

Every Rust dependency must pass `cargo deny check`. The policy is in
`deny.toml`:

- Vulnerabilities, unmaintained crates, unsound crates and yanked versions
  are errors.
- Licences must be on the allowed list, which holds permissive licences
  compatible with distributing Mycel under MIT or Apache-2.0. Any other
  licence fails until it is reviewed and listed as an exception for the one
  crate that needs it.
- Crates come from crates.io only. Git dependencies and wildcard version
  requirements are refused.

CI builds with `--locked` and installs with `npm ci`, so commit the change
to `Cargo.lock` or `package-lock.json` together with the manifest. For npm,
CI runs `npm audit --omit=dev`, and the `Dependency review` job fails a pull
request that adds a dependency with a known vulnerability.

### Accepted advisories

An advisory that Mycel is not exposed to can be accepted, with the reason
written down. The accepted advisories are listed in three files, one for
each tool that reads them:

| File | Read by |
|---|---|
| `deny.toml` | cargo-deny, in CI and in the daily `Audit` workflow |
| `.cargo/audit.toml` | a local `cargo audit` |
| `osv-scanner.toml` | OSV-Scanner and OpenSSF Scorecard |

`deny.toml` holds the full entry: the advisory, why Mycel isn't exposed, and
the date to look again. Keep all three files in step, and remove an entry
when its reason goes. cargo-deny only reads the platforms Mycel ships on,
so the other two files can list an advisory that `deny.toml` doesn't need.

### Dependency updates

Dependabot proposes updates every week. Two groups are updated by hand
instead:

- The crates under `vendor/`. Raising the version requirement of one of
  them would build against the unpatched upstream release, so they are
  updated by vendoring the new release again.
- New minor and major versions of the `tauri` crates and the `@tauri-apps`
  npm packages. The two must stay on the same minor version, so update them
  together.

## Vendored code

`vendor/` holds patched copies of a few upstream crates (Iroh, its QUIC
stack, and others). Before you touch anything there:

1. Read that crate's `MYCEL_PATCH.md`. The notes for `noq` are in
   `vendor/noq-proto/MYCEL_PATCH.md`.
2. Keep the change as small as possible, mark it `MYCEL PATCH`, describe it in
   `MYCEL_PATCH.md`, and add a test.
3. Never reformat vendored files or remove their licence files and notices.

[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) lists each vendored crate,
its upstream and its licence.

## Where to ask

Questions, bug reports and proposals all go to the
[issue tracker](https://github.com/atullal/mycel/issues/new/choose).

- For a bug, use the bug report form. Say which platform and build you ran,
  what you did, what you expected, and what happened. Attach `mycel.log`
  from the data folder if you can, after removing anything private. The
  [user guide](docs/USER_GUIDE.md) says where the data folder is.
- For an idea or a larger change, use the feature request form before you
  write the code.
- For a question about a change you are working on, ask in its issue, or
  open a draft pull request and ask there.
- For a security vulnerability, never use a public issue. Report it
  privately, as [SECURITY.md](SECURITY.md) describes.

## Licence

Mycel is licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT), at your option. Unless you explicitly state otherwise,
any contribution you intentionally submit for inclusion in the work, as
defined in the Apache-2.0 licence, shall be dual licensed as above, without
any additional terms or conditions.
