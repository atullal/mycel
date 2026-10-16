## What and why

<!-- What does this change, and why? Link the issue it fixes, if there is one. -->

## How it was tested

<!-- Tests added or changed, and anything you checked by hand (which platforms, how many devices). -->

## Checklist

- [ ] Tests cover the change, and `cargo test` / `npm test` pass.
- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` are clean.
- [ ] Docs are updated for anything a user or app developer would notice.
- [ ] No secrets, keys, personal data or build output in the diff.
- [ ] Every commit is signed off (`git commit -s`, see CONTRIBUTING.md).
- [ ] Wire format and stored data: unchanged, **or** the change is described below.
      (Every device has to run the same build; say what an older build would see.)
- [ ] New dependencies, if any, are explained and pass `cargo deny check`.
- [ ] Changes under `vendor/` follow that crate's `MYCEL_PATCH.md`.

<!-- Security fixes: don't describe a vulnerability here. Report it privately first (SECURITY.md). -->
