# Security policy

Mycel is end-to-end encrypted, peer-to-peer software. We take reports about
its security seriously, and we are grateful for them.

## Status: not audited

Mycel is pre-release software. **Its cryptography and protocols have not been
reviewed by an external auditor.** The trust layer, the encrypted envelopes
and the sync protocol were designed and reviewed only by this project. Don't
rely on Mycel where a flaw could put someone at risk until an independent
review has happened.

## Supported versions

Only the latest commit on `main` and the newest pre-release (`dev-*` tags) get
security fixes. We don't backport fixes to older builds. Builds negotiate
the protocol version ([docs/PROTOCOL.md](docs/PROTOCOL.md)), so an updated
device keeps working with the others, but compatibility is not yet a
promise: after a fix, update every device.

## Reporting a vulnerability

**Please don't report vulnerabilities in public issues, pull requests or
discussions.**

Report them privately through GitHub:
<https://github.com/atullal/mycel/security/advisories/new>

Only the maintainers can see the report. Please include:

- what is affected: the component, and the commit or release;
- what an attacker can do, and what they need first (a contact, a member of a
  space, someone on the same network, a malicious peer or keeper, a malicious
  app or rules bundle);
- how to reproduce it: steps, a test, or a proof of concept;
- a fix or mitigation, if you have one;
- how you'd like to be credited, or that you'd rather not be.

If you can't use GitHub's form, open a public issue that asks for a private
contact, with no details of the problem.

## What happens next

These are targets for a small team, not guarantees:

| Step | Target |
|---|---|
| We acknowledge your report | 3 working days |
| We confirm it or explain why we don't think it's a vulnerability | 10 working days |
| A fix for a critical or high-severity issue is released | 30 days |
| A fix for any other confirmed issue is released | 90 days |

We keep you updated as we work on it. When the fix ships, we publish a GitHub
security advisory, request a CVE where one applies, and credit you unless you
ask us not to.

## Coordinated disclosure

We ask you to give us time to fix the problem before you make it public. Our
default is 90 days from your report, or the release of the fix if that comes
first. If a fix needs longer, we'll explain why and agree a date with you. If
the problem is being exploited, or is already public, we move faster and may
publish sooner.

If the vulnerability is in a dependency or a vendored crate, we report it
upstream as well, coordinating with you and with the upstream maintainers.

## Scope

In scope: any way to break Mycel's security guarantees through the code in
this repository. In particular:

- **Trust layer** (`crates/mycel-trust`): membership, roles, invites,
  removal and encryption epochs. For example, gaining or keeping access you
  shouldn't have, or making peers disagree about who is a member.
- **Cryptography and encrypted envelopes** (`crates/mycel-crypto`,
  `crates/mycel-sync`): signatures, key agreement, content encryption,
  attachments, and the keys kept on the device.
- **Sync** (`crates/mycel-sync`, `crates/mycel-net`): forged, replayed,
  reordered or malformed data accepted from a peer, and peers learning data
  they shouldn't.
- **Network and mesh** (`crates/mycel-net`, `crates/mycel-link-*`,
  `crates/mycel-call`, `crates/mycel-video`): discovery, invites, contact
  cards, relays and keepers, mesh routing, blobs, calls and video. Includes
  remote crashes and resource exhaustion that a peer can trigger.
- **Rules sandbox** (`crates/mycel-rules`): escaping the WebAssembly sandbox,
  breaking determinism, or getting around fuel and memory limits.
- **Host and IPC** (`apps/host`, `packages/sdk`, `crates/mycel-cli`): the
  Tauri commands and capabilities exposed to app code, the web UI, the CLI's
  local HTTP API, file access, notifications, and data stored on the device.
- **Vendored crates** (`vendor/`), as Mycel uses them.
- **Build and release**: the GitHub Actions workflows and the published
  installers.

Out of scope:

- Vulnerabilities in dependencies that Mycel's use doesn't expose. Report
  them upstream; tell us too if you're not sure.
- Attacks that need an already compromised operating system, or physical
  access to an unlocked device.
- The benchmark and simulation tools (`bench/`, `crates/mycel-sim`), unless
  the problem also affects the shipped code.
- Reports from automated scanners with no demonstrated impact.

## Safe harbour

We consider security research done in good faith and within this policy to
be authorized. We won't take legal action against you for it, and if someone
else does, we'll make clear that you acted with our permission.

Good faith means that you:

- test only on your own devices and accounts, or with the explicit consent of
  their owners;
- don't access, change or keep other people's data, and stop and tell us if
  you come across any;
- don't degrade other people's use of Mycel or of the networks it runs on
  (such as Iroh's public relays or the BitTorrent DHT);
- give us reasonable time to fix the problem before you disclose it.

If you're unsure whether something is in scope or allowed, ask us first
through the private reporting form.
