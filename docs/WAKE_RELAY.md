# Optional wake relay: design

> **Status: a design. Nothing in this document is built.** Mycel has no wake
> relay, no push server and no APNs or FCM integration. If one is built, it
> is **off by default**: a user turns it on, per device, after reading what
> it can see. Everything else in Mycel keeps working without it.

## Why this exists

A suspended iPhone or iPad can't be woken the moment a message is sent
without Apple's push service (APNs), and APNs takes requests only from a
server holding the app developer's key. Mycel's iOS app therefore runs in
**slow mode** ([PLATFORMS.md](PLATFORMS.md#background-delivery-without-a-server)):
it catches up when iOS lends it time, over Bluetooth when a Mycel device is
nearby, and when it's opened. Messages wait on the sender, keepers and
carriers until then.

Some users will want timely delivery more than they want zero
infrastructure. This design gives them that **without trusting anyone with
content or identity**: the relay is trusted for availability only. If it
lies, drops wakes or disappears, Mycel falls back to slow mode. It never
gets anything that would let it read, forge or attribute messages.

Research behind it (2026-10): SimpleX's notification server (sees APNs
tokens and per-queue wake counts, not queue addresses, senders or content),
Session's "fast mode" (push server reachable only through onion requests),
Delta Chat's chatmail notifier, and the platform limits in
[PLATFORMS.md](PLATFORMS.md#what-the-platforms-allow-researched-2026-10).
No iOS release up to 26 offers a server-free way to wake a suspended app on
time; Wi-Fi Aware (iOS 26) gives links to paired devices only while the app
is already running.

## Goals and non-goals

**Goals**
1. **Content-blind:** the relay never sees message content, sizes of
   messages, conversation IDs or Mycel identity keys.
2. **Identity-blind:** the relay can't tell who the device's owner is or who
   is waking it. It holds a push token, which Apple can map to an Apple ID;
   the relay can't.
3. **Unlinkable capabilities:** each contact (or conversation) gets its own
   wake capability. Contacts can't tell which other capabilities wake the
   same device; outsiders can't link a capability to a person.
4. **Revocable and rate-limited:** the device can revoke any capability, and
   the relay caps wakes per capability, so a leaked one can only cause a few
   harmless wakes.
5. **Replaceable:** a user picks the relay; any operator can run one for an
   app build they hold the APNs key for (see Limits). Losing the relay costs
   timeliness, nothing else.

**Non-goals**
- Delivering content through the relay. Content always travels over Mycel's
  own paths (direct, mesh, keepers, carriers).
- Hiding from Apple that the device received a push, or when.
- Android: it doesn't need a relay (see [Android](#android-no-relay-needed)).

## Parts

```text
 sender S (a contact of D)          wake relay R                 APNs           D's phone
 ─────────────────────────          ────────────                 ────           ─────────
 holds cap_S = (id_S, pk_D)
 send message over Mycel ──────────────────────────────────────────────────────▶ (asleep)
 wake = id_S ‖ HPKE(pk_D, hint) ─▶ look up id_S → token_D
   (through a one-hop proxy        rate-limit id_S
    or OHTTP, never directly)      jitter, coalesce
                                   push {mutable-content, blob} ─▶ ──────────────▶ Notification
                                                                                 Service Extension:
                                                                                 decrypt hint,
                                                                                 fetch over Mycel,
                                                                                 show a generic alert
```

- **D**: the device to wake. Holds a per-relay *registration key* and a
  per-relay *wake key pair* (X25519), both separate from its Mycel identity.
- **R**: the relay. Stores `registration → push token` and
  `capability id → registration`, nothing else.
- **S**: anyone D gave a capability to, over Mycel's end-to-end encrypted
  channels.
- **NSE**: an iOS Notification Service Extension in Mycel's app, which may
  run for about 30 s within a small memory limit (about 24 MB reported)
  for every push with `mutable-content`, even after the user swiped Mycel
  away.

## Protocol

All requests to R go over TLS 1.3 or QUIC. R authenticates nothing about
people, only possession of random secrets.

### 1. Register (D → R)

D generates, per relay:
- `reg_key`: an Ed25519 key pair, used only to manage this registration;
- `wake_key`: an X25519 key pair (the HPKE recipient key).

It sends `Register { reg_pk, push_token, platform, sig }` (signed with
`reg_key`) through an anonymising hop (below), so R doesn't learn D's IP
address. R returns `reg_id` (128 random bits). Re-registering with a new
token (APNs rotates them) uses the same `reg_key`.

### 2. Mint capabilities (D → R)

D asks R for capability IDs: `Mint { reg_id, n, sig }` → `[id_1 … id_n]`,
each 128 random bits, stored by R as `id_i → reg_id`. D keeps a pool and
hands one to each contact (or conversation), inside the trust layer, as
`cap = (relay URL, id_i, wake_pk, expiry)`. The capability travels only
end to end; R never learns who holds which `id`.

`Revoke { reg_id, [id…], sig }` deletes them. D revokes a contact's
capability when they are removed, blocked or after the expiry (30 days by
default; contacts get fresh ones over Mycel).

### 3. Wake (S → R)

After S sends D a message that D hasn't acknowledged within a short grace
period (so a device that is awake and connected is never pushed), S sends:

```text
Wake { id_S, blob }    blob = HPKE.Seal(wake_pk, info = "mycel/v0/wake", aad = id_S, pt = pad(hint, 96))
```

- HPKE is RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256
  and ChaCha20-Poly1305: standard, widely reviewed, no custom cryptography.
- `hint` is the smallest thing that lets the NSE fetch quickly: the
  sender's Mycel node ID and a send timestamp. It is padded to a fixed
  length, so every blob is the same size.
- S sends the wake **through a one-hop proxy** (a random Mycel peer, like
  Session's onion requests cut to one hop) or an Oblivious HTTP relay
  (RFC 9458) operated by someone other than R, so R doesn't learn S's IP
  address next to `id_S`.

R looks up `id_S`, applies the rate limits (below), waits a random 0–10 s,
coalesces wakes for the same registration in that window, and sends one
APNs push:

```json
{ "aps": { "mutable-content": 1, "alert": { "title": "Mycel", "body": "New activity" } },
  "m": "<blob, base64>" }
```

with `apns-push-type: alert`, `apns-priority: 10` and an
`apns-collapse-id` per registration (APNs keeps only the newest
notification for an offline device anyway). The visible fallback text is
generic; the NSE replaces it.

### 4. Fetch (NSE on D)

The NSE decrypts the blob with `wake_key` (from the Keychain, in an access
group shared with the extension; `AfterFirstUnlockThisDeviceOnly`), then
runs a cut-down Mycel fetch: connect to the sender (or its carriers and the
conversation's keepers) over Iroh, pull the pending envelopes into a
staging inbox in the app group container, decrypt only enough to pick the
alert kind, and show Mycel's usual generic alert ("New message", "Incoming
call", never names or text: [notify.rs](../apps/host/src-tauri/src/notify.rs)).
The app ingests the staging inbox the next time it runs; the NSE never
opens the main store (the app may hold its lock). If nothing is fetched in
time, it shows "You may have new messages".

Replays and forgeries (only R could try, and only if it learned `wake_pk`)
cost one fetch and one generic alert; the timestamp lets the NSE drop
replays it has seen.

## Rate limits and abuse

- Per capability: at most 1 push per 30 s, a burst of 5, 200 per day.
- Per registration: at most 1 push per 10 s after coalescing.
- A leaked or abused capability can't be pinned on anyone by R (it doesn't
  know who holds it). D can: each capability goes to one contact, the NSE
  counts wakes that fetched nothing per sender hint, and D revokes the
  capability and hands that contact a new one (or none).
- R needs no accounts: registrations expire after 60 days without a token
  refresh.

## What the relay learns, and who else sees what

| Party | Learns | Doesn't learn |
|---|---|---|
| Wake relay R | a push token and `reg_pk`; how many capabilities a registration has; when each capability fires (timing, counts); the proxy's address | D's or S's identity, IP addresses (with the proxy), message content, sizes or recipients beyond "this token" |
| Apple (APNs) | the token, which it ties to the device and Apple ID; push timing and counts; R's address | the blob's plaintext; anything about S |
| The one-hop proxy / OHTTP relay | S's address; that S talks to R | `id_S` and the blob (encrypted to R / opaque) |
| A contact S | its own `id_S` and D's `wake_pk` | D's other capabilities; D's token |
| An eavesdropper on S's or D's network | that S talks to the proxy; that D gets APNs pushes | anything inside TLS or the blob |

**Timing is the real leak.** R and Apple see when D is woken, which follows
when its contacts send. Mitigations, in order of cost: the random delay
and coalescing above; optional cover pushes (D asks R for a few at random
times a day); and choosing a relay operated by someone the user trusts
with timing. None of these hide the pattern from Apple, which sees every
push to a token.

## Trust

Trusted for **availability only**: R can drop, delay, replay or reorder
wakes, or stop running, and the result is slow mode. It is not trusted for
confidentiality (it never holds content or keys that decrypt it) or
integrity (it never relays content; envelopes are signed by their authors
and checked by the trust layer as always). This is the same trust tier as
a keeper or a store-and-forward carrier ([TRUST.md](TRUST.md#8e-optional-wake-relay-designed-not-built)),
with less to see.

## Android: no relay needed

Android keeps Mycel connected with a foreground service. For users who
don't want that, the same capability idea works with **UnifiedPush** and no
Mycel relay at all: D registers with a distributor *the user chose* (ntfy,
Sunup or NextPush, all self-hostable) and shares, as its capability, the
endpoint URL and its RFC 8291 Web Push keys. S posts the encrypted wake
straight to that endpoint (through the proxy). The distributor sees only
ciphertext and timing. This is a design too; it is not built.

## Limits

- **APNs keys.** Apple sends pushes for an app only when the request is
  signed with a key from the app's developer team. So only whoever ships a
  given iOS build can run a relay for it; others can run one for their own
  build, with their own bundle ID and key. "Self-hostable" therefore means
  "per build", which is why SimpleX, Session and Delta Chat each run theirs
  centrally. This is the one place where Mycel's design would admit a
  single operator, and why it stays optional and off by default.
- **Delivery isn't guaranteed.** SimpleX reports that Apple drops 15–20% of
  notifications to offline devices, and that the extension's memory limit
  loses about 10%. Slow mode keeps running underneath.
- **The NSE gets the wake key and a fetch path.** Keys shared with the
  extension through a Keychain access group widen where they live (still
  device-only). The extension must fit the Rust fetch path in its memory
  limit; that has not been measured.
- **Visible alerts.** Without Apple's notification-filtering entitlement,
  every push shows an alert, even when the fetch found nothing.

## If it's built

1. A separate crate (`mycel-wake`) for the capability and blob formats,
   with test vectors, fuzzed decoders and the trust-layer integration that
   hands capabilities to contacts.
2. A relay binary that keeps state in memory plus an append-only token file,
   with no request logging by default, documented in TRUST.md with the table
   above.
3. The NSE target and the staging inbox, with a memory benchmark on a real
   iPhone.
4. A Settings switch, off by default, that explains the table above before
   it registers anything.
5. A design review (with the v2 wire spec) before it ships.
