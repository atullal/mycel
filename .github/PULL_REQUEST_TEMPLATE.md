<!-- Security fixes: don't describe a vulnerability here. Report it privately first (SECURITY.md). -->

## What and why

<!-- What does this change, and why? Link the issue it fixes, if there is one. -->

## How it was tested

<!-- Tests added or changed, and anything you checked by hand (which platforms, how many devices). -->

## Wire format and stored data

<!-- "Unchanged", or what changed and what an older build would see. Every device has to run the same build. -->

## Checklist

- [ ] `cargo fmt`, `cargo clippy` and `cargo test` pass, and so do `npm run typecheck`, `npm test` and `npm run build` if TypeScript changed. CONTRIBUTING.md has the exact commands.
- [ ] Tests cover the change.
- [ ] Docs are updated for anything a user or app developer would notice.
- [ ] Every commit is signed off (`git commit -s`).
- [ ] No secrets, keys, personal data or build output in the diff.
- [ ] New dependencies, if any, are explained and pass `cargo deny check`.
- [ ] Changes under `vendor/`, if any, follow that crate's `MYCEL_PATCH.md`.
