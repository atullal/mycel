# Routing: survey and design decisions

How a Mycel device reaches another one when they share no network: a
Bluetooth-only phone in the US messaging a Bluetooth-only phone in Europe,
a crowd of 300 at a conference with no Wi-Fi, a village with one satellite
uplink. This is the design record: what exists, what we took from it, what
we built, and why.

**Short answer.**
- **Three layers.** Routing is hierarchical: a *local mesh* (signed
  distance vector over radio hops, scoped to a few hops), a *global key
  lookup* (signed pkarr records in the Mainline DHT and the n0 DNS relay:
  "this device is reachable via gateways G1, G2"), and the *internet* for
  distance. A message climbs from Bluetooth to the nearest device with the
  internet, crosses the internet in milliseconds, and descends through the
  far side's gateway.
- **When there is no live path,** store-and-forward moves it toward
  connectivity: spare copies go to the likeliest neighbours first, then a
  single copy climbs by delivery predictability toward "the internet",
  with hop-by-hop custody, mailboxes at the far gateways, and signed
  receipts.
- **What we reuse and what is ours.** We reuse Iroh (QUIC, multipath,
  relays, hole punching, custom transports), the pkarr record format, and
  the Mainline DHT (via `n0-mainline`, the crate Iroh's own DHT lookup uses).
  We reuse *ideas* from Babel, B.A.T.M.A.N., OLSR, fisheye routing,
  PRoPHET, Spray-and-Wait and MaxProp. The routing core itself is ours
  (`crates/mycel-net/src/mesh/core.rs`, ~2k lines, sans-IO), because
  nothing existing routes *QUIC packets between Iroh endpoints over
  arbitrary links* with our identities. No new transport library is needed.

## 1. Requirements that decide the design

1. **End-to-end encryption is QUIC's.** Relays forward ciphertext of a
   connection between two other devices. The routing layer must carry
   opaque packets, never terminate sessions. That rules out designs that
   are their own encrypted transport (Reticulum, cjdns, Yggdrasil, libp2p),
   unless we abandoned Iroh.
2. **One identity.** The Ed25519 device key is the Iroh endpoint id, the
   Mycel signing key, and the routing identity. A second key system
   (Reticulum destinations, cjdns IPv6-from-key, libp2p PeerIds) would mean
   a second trust problem.
3. **Any medium, mixed.** BLE L2CAP (tens of kB/s), AWDL, LAN, Wi-Fi
   Direct, UWB / 802.15.4, the internet. Costs must be measured, not
   hard-coded, and comparable across media.
4. **Multipath.** Several routes to one destination become several QUIC
   paths, which noq aggregates and fails over between. That needs routes
   addressable separately: our mesh address is `(destination, waypoint)`.
5. **Churn.** People walk. Links appear and vanish every few seconds in a
   crowd. Convergence must be fast and loop-free *while* converging.
6. **Global reach without a Mycel-run server.** Lookups must work through
   infrastructure nobody here operates (the Mainline DHT), with the n0 DNS
   relay as a faster fallback Iroh already uses.
7. **Disconnection is normal.** When no end-to-end path exists, data must
   still move toward its destination and be delivered later, without
   giving carriers any plaintext.
8. **Simulable.** The routing core must run 100k nodes in one process with
   a virtual clock, so it can't own sockets, timers or threads.

## 2. Local routing (inside one radio mesh)

| Protocol | What it does | Strengths for us | Weaknesses for us | Decision |
|---|---|---|---|---|
| **B.A.T.M.A.N. IV** | Each node floods an *originator message* (OGM) with a sequence number; neighbours rebroadcast the best copy once; each node keeps only "best next hop per originator", ranked by TQ (packet-loss based). | No topology database. Self-healing, tiny state. Proven in Freifunk meshes. | Flooding cost O(N) per node per period. The TQ metric ignores throughput. Loops are possible transiently (bounded by seqno windows). Kernel C code. | **Idea reused** (our base design: signed OGMs, rebroadcast once per seqno, best-next-hop state). Code rejected. |
| **B.A.T.M.A.N. V** | Separates neighbour discovery (ELP) from OGMv2; metric = throughput. | Throughput-aware metric. | Same flooding scale. | **Idea reused**: our hop cost is measured RTT + a throughput term. |
| **Babel** (RFC 8966) | Distance vector with per-source seqnos and the *feasibility condition*. A route is usable only if `(seqno newer)` or `(same seqno, metric < feasibility distance)`. Triggered updates, retractions (metric ∞), seqno requests to recover from starvation. | **Loop-free at all times, even during convergence**, not only via TTL. Fast reaction to link loss (retraction). Designed for mixed wired/wireless. | Unauthenticated by default (RFC 8967 adds MAC). C reference implementation. | **Ideas reused**: feasibility condition, retractions, triggered updates, seqno requests (§6). Code rejected. |
| **OLSRv2** (RFC 7181) | Link-state. HELLOs give 2-hop neighbourhoods; *multipoint relays* (MPRs) are the minimal neighbour set covering all 2-hop neighbours, and only MPRs forward floods. Topology control messages give everyone the full graph. | MPRs cut flooding drastically in dense networks. | Full topology at every node: memory and CPU grow with N², and it's heavy for phones. HELLOs carry neighbour lists (privacy, size). | **Idea tried in reduced form**: flood reduction without 2-hop state, now off, since over unicast hops it leaves devices out (§6.9). Full link-state rejected. |
| **AODV** (RFC 3561) / **DSR** (RFC 4728) | Reactive: flood a route request when you need a route; the reply sets up state. | No overhead when idle. | First-packet latency of a full flood; a flood *per destination*; routes break silently under mobility. Chat presence wants routes ready. | **Rejected** as the primary scheme. The on-demand idea survives as seqno requests and global record lookups. |
| **Fisheye state routing** | Update frequency falls with distance: near nodes are accurate, far nodes coarse; packets get more precise routes as they approach. | Cuts overhead roughly from O(N) to O(near) per period. | Far routes are staler. | **Idea reused**: announcement *scope* (§6.4). |

## 3. Overlays and community meshes

| System | What it does | Strengths | Weaknesses for us | Decision |
|---|---|---|---|---|
| **Yggdrasil** | Spanning tree gives each node tree coordinates; a DHT maps keys to coordinates; greedy routing on the tree. Encrypted IPv6 overlay. | Scales to large networks without global flooding. Keys are addresses. | Path stretch. Root dependence and tree instability under mobile churn. Go and TUN-based: it is its own transport. | **Idea reused**: key-based lookup instead of global flooding. Code rejected (req. 1, 2). |
| **cjdns** | Kademlia-style DHT over key distance, source-routed labels, encrypted. | Pioneered key = address. | Complex, slow to converge, its own crypto, C, little activity. | **Rejected.** |
| **Reticulum** | Destinations are key hashes; *announces* propagate path information, rate-limited; *transport nodes* keep path tables and forward; works down to LoRa and serial at tiny bitrates. Rust ports exist (`reticulum-rs` 0.9.x in LXMF-rs, and Beechat's). | Best-in-class for very low-bandwidth links. Announce-based path discovery with strict rate limits. | Its own transport, crypto and identities; not QUIC; the Rust ports say they are not drop-in compatible with Python Reticulum yet. | **Ideas reused**: announce rate limiting, relays as "transport nodes". Code rejected (req. 1, 2). |
| **BitChat** | BLE mesh: every message flooded with TTL 7; store-and-forward cache for offline peers; Nostr relays bridge to the internet (geohash channels); Noise for E2E. | Zero setup, works in crowds. | Flooding every message doesn't scale past a crowd. The internet bridge is a public relay network: metadata goes to third parties. | **Ideas reused**: TTL scoping, store-and-forward, an internet bridge. We route instead of flooding data, and our bridge is any Mycel device with the internet. |
| **Meshtastic** | LoRa *managed flooding*: rebroadcast delayed by SNR (far nodes first), cancelled if a neighbour was heard rebroadcasting; hop limit 3–7; MQTT gateways to the internet. | Flood suppression that works on real radios. | A central MQTT broker for the internet. | **Ideas reused**: jittered rebroadcast (§6.1); suppression tried and turned off over unicast hops (§6.9). Central broker rejected; gateways publish to a DHT instead. |
| **Briar / Bramble** | Sync between contacts over Tor, Bluetooth and Wi-Fi; a *mailbox* (a spare device) holds messages for an offline user. | Sound security model; mailbox concept. | No multi-hop routing through strangers. | **Idea reused**: mailboxes at the destination's gateways (§7.4). |
| **libp2p** | Kademlia for peer routing, circuit relay v2 (reservations, limited relayed bandwidth), gossipsub, AutoNAT. Mature Rust implementation. | Proven components. | Duplicates Iroh (transport, identity, relays, NAT traversal); a second stack in the app. | **Ideas reused**: relay budgets and reservations (our gateway budgets). Code rejected. |

## 4. Iroh's own pieces

| Piece | Use |
|---|---|
| QUIC (noq) with **multipath**, custom transports | **Adopted.** Every link, mesh route and gateway route is a QUIC path, aggregated and failed over by the path selector. |
| **Relays** (n0 or self-hosted) and hole punching | **Adopted** for internet-connected devices. They reach each other, and gateways, as usual. |
| **pkarr** records (signed DNS packets), n0 DNS relay | **Adopted.** Gateway reachability records use the same format, so any pkarr resolver can read them. |
| **Mainline DHT** (`iroh-mainline-address-lookup` 0.6, built on `n0-mainline`) | **Adopted** (`n0-mainline` directly, behind the `dht` feature). The crate only publishes the endpoint's *own* record; a gateway publishes *someone else's* (already signed) record, which is a few lines on top of `n0-mainline`. |
| **iroh-gossip** (HyParView membership + PlumTree broadcast trees) | **Not for routing.** It broadcasts within a topic swarm; route tables need scoped, per-neighbour state, not global broadcast. |
| **iroh-blobs** | Evaluated earlier; not used (different hash ids, no multi-source ranges). |

## 5. Store-and-forward (DTN)

| Work | What it does | Decision |
|---|---|---|
| **Bundle Protocol v7** (RFC 9171); `bp7` 0.9 (CBOR encoding), `dtn7-rs` 0.18 (daemon with TCP/HTTP convergence layers) | Bundles with lifetime, source/destination endpoint ids, status reports. Custody transfer was split out of BPv7 into separate work. | **Ideas reused**: lifetime, hop-by-hop custody, status reports become our signed delivery receipts. **Code rejected.** `dtn7` is a daemon with its own convergence layers and routing, not an embeddable core. BPSec would duplicate our envelope signatures and encryption. Our payloads are already signed, encrypted and content-addressed Mycel envelopes. |
| **PRoPHET** (RFC 6693) | *Delivery predictability* P(a,b): raised on each encounter, aged over time, transitive through intermediaries. Forward to nodes with higher P. | **Adopted** (§7.2). The virtual destination "the internet" lets copies climb toward connectivity. |
| **Spray-and-Wait** (Spyropoulos et al., 2005) | L copies, binary spray, then wait for direct delivery. | **Adopted, steered**: the copies are sprayed first, each to the likeliest neighbour without one; then a single copy follows the gradient toward the internet (as in Spray-and-Focus, same authors, 2007). L depends on the bundle's size. |
| **MaxProp** (Burgess et al., 2006) | Priority by path likelihood; flooded acks clear buffers. | **Idea reused**: signed receipts flood among carriers and free their copies. |
| **RAPID** (Balasubramanian et al., 2007) | Replication as utility optimisation using a metadata channel. | **Rejected**: heavy metadata for marginal gains at our scale. |

## 6. Our local mesh: how route tables are distributed and kept fresh

Route tables are **distributed and partial**. Each device keeps, per
origin within its scope, the neighbours that announced it, with cost,
hops and sequence number, plus one *feasibility distance*. Nobody has a
global table. They are synced by signed announcements: periodic ones
every 16 s (Babel's update interval), plus *triggered* updates when
something changes.

1. **Announcements** (`Announce`, signed by the origin over origin, seqno,
   flags, scope, uplink cost and name). Relays add `hops` and `cost`
   (unsigned, as in B.A.T.M.A.N. and Babel). Each relay rebroadcasts the
   best copy of each seqno once, after a 10–50 ms jitter, never back where
   it came from. Announcements for one neighbour leave in one datagram
   (`T_OGMS`), saving a QUIC packet's ~40 bytes of headers, and on
   Bluetooth a connection event, per announcement.
2. **Cost** = Σ per hop (smoothed RTT in 0.1 ms units + 2 ms per hop). The
   driver feeds each hop connection's measured RTT, plus a throughput term
   (time to move 64 KiB at the hop's cwnd/RTT rate). So BLE, AWDL and
   cable hops rank themselves. For gateways, each announcement carries an
   **uplink cost** (the gateway's measured internet RTT and throughput
   term). A device without the internet picks the gateway with the lowest
   *total*: mesh cost + uplink cost. A fibre gateway four hops away beats a
   congested one next door.
3. **Sequence numbers** are the origin's wall clock in milliseconds,
   strictly increasing per origin (`max(now, last+1)`). Comparisons are
   only ever between seqnos of the *same* origin, so clock skew between
   devices doesn't matter. A restarted device needs no stored counter. An
   announcement more than ±10 min from the receiver's clock is rejected as a
   replay, which needs clocks within 10 minutes (phones are NTP/GPS
   synced). A per-origin counter would need persistence and a recovery
   path after reinstall; epoch-ms gives both for free.
4. **Feasibility condition** (Babel): per origin we remember the feasibility
   distance FD = (seqno, cost) of what we last advertised. A route through
   neighbour n, advertised as (s, c), is usable only if `s > FD.seq` or
   `(s = FD.seq and c < FD.cost)`. Any accepted route is strictly closer than
   anything we told others, so no loop can form *during* convergence, not
   just "TTL kills it eventually".
5. **Triggered updates and retractions.** When a hop goes down, every
   origin whose selected route used it, and which has no feasible
   alternative, is retracted at once. We send our neighbours the latest
   signed announcement with cost ∞. They drop that route and, if it was
   their last, retract in turn. A dead route stops being used in about one
   RTT per hop, instead of after a 3.5-period timeout.
6. **Seqno requests.** With routes left but none feasible (starvation), or
   right after a retraction, we ask for a fresh seqno. The request travels
   toward the origin. A device that already has a newer feasible
   announcement answers with it; the origin answers by announcing at once
   (rate-limited). Recovery takes about an RTT, not up to an announcement
   period.
7. **Fisheye scope.** Every period an origin announces with scope 2 hops.
   Every 8th period it uses the full scope (10 hops). Nearby routes refresh
   every 16 s; far ones every 128 s, with timeouts scaled to match. Each
   device originates the same number of announcements, but each one floods
   a 2-hop neighbourhood instead of the whole mesh 7 times out of 8. The
   scope is 10 hops, not 8, because routes follow the cheapest path, which
   can be a hop or two longer than the fewest hops: with 8, devices 8 radio
   hops away were missed (3% of pairs in `flood-scaling`).
8. **Babel's timing, not B.A.T.M.A.N.'s.** The period was 2 s, as in
   B.A.T.M.A.N., because routes used to expire to notice a loss. They
   don't need to: a hop connection notices a lost link within seconds
   (1.5 s keep-alives, 5 s idle) and triggers retractions and seqno
   requests (items 5–6). So the period only refreshes, and Babel's 16 s
   does. What changes goes out at once:
   - retractions and seqno requests, as before;
   - a device's first neighbour gets a full-scope announcement at once
     (what it announced alone reached nobody);
   - a new neighbour is **greeted** with our routes (Babel's full update
     to a new neighbour), each within its announcement's scope, so meeting
     a mesh doesn't wait for a period. In a crowd everyone meets 15
     devices at once and one table is enough, so a device greets at most
     one new neighbour per 4 s; the others get its own announcement.
9. **No broadcast-style flood reduction.** A device never rebroadcasts to
   a neighbour that already sent it that seqno, since that neighbour has
   it. The Trickle-style rule (in a dense neighbourhood, skip the
   rebroadcast after hearing 3 equal copies) is off by default: it
   assumes broadcast radios, where those 3 copies reached our neighbours
   too. Over unicast hop connections they reached *their* neighbours, and
   9% of pairs were left without a route after a flood
   (`routing-convergence`). OLSR's MPRs would need 2-hop state.
10. **At most 6 hop connections opened per device.** A device opens hop
    connections to at most 6 devices in range, each its own pseudo-random
    pick so they spread out; others open theirs to it (about 11 in all in a
    crowd). A Bluetooth radio holds ~10 connections, and each costs
    keep-alives and a share of every announcement. Direct traffic between
    two devices in range doesn't need one: it uses the link itself.
11. **Failover without waiting for routing.** Up to 3 routes per
    destination are open QUIC paths at once. When one breaks, traffic
    continues on the others within about a probe timeout, not the path's
    5 s idle timeout. That needs the vendored noq patch
    (`vendor/noq-proto/MYCEL_PATCH.md` §3):
    - a path that stopped both acknowledging and hearing gets no new data,
      and its in-flight packets are retransmitted on the others;
    - ACKs move off a path that went quiet, so the peer isn't left hearing
      nothing;
    - stale ACKs don't inflate its RTT;
    - path selection, and with it the path calls and the Network panel
      report, moves off the dead path at once.

    Before the patch, losing a relay mid-transfer stalled the rest for 5–20 s
    in about 1 run in 4. Routing convergence only decides which routes to
    *add*. Measured in `tests/mesh.rs`.
12. **Lying neighbours.** An announcement's hops and cost aren't signed:
    relays fill them in. A black hole can relay every origin "at no
    cost" to pull traffic toward itself and drop it. But each honest hop
    adds one hop and at least 2.1 ms of cost (`MIN_HOP_COST`: a measured
    cost of at least 0.1 ms plus `HOP_PENALTY`), and only the origin sends
    zero hops. A relayed announcement below that floor can't come from an
    honest relay, so its sender, a direct neighbour over its own
    authenticated hop connection, is **distrusted** for 10 minutes: the
    routes it gave go at once (retractions and seqno requests restore the
    others), the routes it relays are ignored, and it stays reachable
    itself (its own announcements are signed by it). In `adversarial` at
    full size (300 phones, 15 such black holes) delivery went from 82% to
    100% (`docs/SIMULATION.md` §4, fixed 20). A liar that claims plausible
    values (one hop from everyone, at the least cost) isn't caught by
    this; item 13 is what stops it.
13. **End-to-end feedback.** What a liar can't fake is the destination's
    acknowledgements. The transport tells the router (`Router::feedback`)
    when a whole retransmission timeout passes with nothing acknowledged
    for our packets to a destination, and when an acknowledgement comes
    back. Its timeout follows the measured round trip, so a slow path isn't
    a dead one. After two timeouts in a row through the same next hop, on
    a mesh route that still claims to reach the destination and over a hop
    that is still up, and a silence of at least 1.5 s plus twice the
    route's cost (slow or busy routes get longer), that hop is
    **suspected** for that destination for 2 minutes:
    - our packets, and those we relay to it, take the next feasible route
      (any feasible route is loop-free, not only the best); with every
      route suspected, still the best: dropping can't deliver, and
      suspicion can be wrong;
    - the store-and-forward carrier stops trusting that route with every
      copy of our bundle (§7.3).

    One acknowledgement clears the count. Routes through gateways or the
    internet aren't judged: the destination may just be offline. Custody
    hand-offs aren't steered by it: on a trace of brief contacts, where
    routes stop delivering for ordinary reasons, that cost more than it
    saved. At most 1,024 destinations and 4 suspects each are kept. Relays
    can't judge on their own: the acknowledgements are inside the
    end-to-end encryption, and the reverse path needn't pass them. In
    `adversarial` at full size, 15 such liars (dropping bundles too) took
    delivery to 76%; with this and §7.3's split, 94%
    (`docs/SIMULATION.md` §4, fixed 21).

    **In the node** (`mesh/watch.rs`) the evidence comes per QUIC path.
    Every end-to-end connection (pooled, dialled for another protocol, or
    accepted) is watched: a path `mesh(dst, via)` we keep sending on that
    has had no frame back for 3 s (both ends send keep-alives every 1.5 s),
    or that QUIC gives up while still silent (after 5 s), is reported to
    `Router::path_feedback`; frames arriving again clear it. Only frames
    QUIC counted after decrypting the packet carrying them count, so a
    relay can drop them but can't fake them; nothing at the mesh layer (a
    packet merely claiming to come from the destination) counts. The same
    rules apply: two silences scaled to the route's cost, mesh routes
    only. A suspected hop's route stops being offered as a QUIC path for
    that destination (`RouteDown`), the next one is (`RouteUp`), and if
    every other route is infeasible because we advertised the cheap one,
    a fresh seqno is asked for, not through the suspect, as after a loss.
    The node's carrier is told (`Carrier::doubt`). Measured with real
    nodes (`tests/mesh.rs`): a relay that keeps announcing a destination
    and drops everything to and from it is routed around in 6.6 s, and two
    hops at 20 kB/s with 30 ms of latency and queue drops suspect nothing.

    **Next protocol version: signed route attestations.** Feedback finds a
    liar only by losing traffic to it first, and only at sources. The
    planned fix is to sign what relays add: each hop signs (origin, seqno,
    the hops and cost it advertises, the neighbour it sends to), so a
    relay can't claim to be nearer than the signed chain it received
    (SEAD and Ariadne's idea, with our Ed25519 keys). It changes the
    announcement format and costs a signature per hop, so it waits for the
    next protocol version; `docs/TRUST.md` §8b.
14. **Short queues under the hops, so control traffic gets through.**
    Announcements, seqno requests, keep-alives and the end-to-end
    connections' acknowledgements share each hop with the bulk data, and
    below QUIC that hop is a first-in, first-out queue nobody can reorder:
    the radio's or the Bluetooth controller's send buffer. The hop
    connection's congestion control (Cubic) fills that buffer until it
    overflows. On the 400 kB/s test radios a saturated hop's queue held
    170 ms on average (250 ms, full, at worst) and dropped ~1.5% of what
    reached it, control included. End-to-end paths through two such hops
    ran at 300–600 ms RTT, and a path that lost packets grew its window
    back by about one packet per RTT, too slowly to recover within a
    transfer. That, not lost announcements (each relay's arrived at the
    full rate, at most 400 ms late), is why two routes sometimes carried
    only 1.2–1.4× one route.
    - So each relay runs CoDel (RFC 8289) on every hop to a device in
      range, with the hop's smoothed RTT above its lowest standing in for
      the queueing delay. When it stays more than a target above for an
      interval (100 ms, or the hop's RTT if longer: no sender can react
      sooner), a data frame is dropped, then more often while it stays
      above. The end-to-end connections slow down before the buffer
      fills.
    - The target is the time to send 3 full packets at the rate the hop
      delivers, at least 20 ms (radio jitter isn't a queue) and at most
      250 ms: 20 ms at 400 kB/s, ~180 ms at Bluetooth's 20 kB/s.
    - Never dropped: announcements, seqno requests, control frames, and
      packets of 400 bytes or less (acknowledgements, voice).
    - Not on internet hops (their queues are shared with the rest of the
      internet). And when a second of dropping doesn't drain a queue,
      someone else's traffic fills it or the link got slower: the delay
      becomes the new base instead of starving our traffic.
    - Measured (`control_traffic_crosses_a_saturated_hop`): at 400 kB/s,
      a small exchange across a saturated two-hop route takes 40–60 ms
      (median) instead of ~560 ms, and the radio queue holds 20–40 ms
      instead of 180 ms. At 20 kB/s it takes ~400 ms instead of 650–830 ms
      (once 6.6 s), for ~5% of the bulk throughput. Two routes carry
      1.84–1.97× one route (`two_routes_aggregate_and_fail_over`, 20 runs
      interleaved with the old build, which spread 1.79–2.19×).
    - No wire change: it only decides which frames a device puts on its
      own hops.

## 7. Beyond one mesh

### 7.1 Gateways and records

- **Gateways.** A device that reaches the internet and relays for others
  sets the gateway flag (signed) and its uplink cost in its announcements.
  Gateway budgets cap what crosses between the mesh and the internet. A
  gateway never relays internet → internet: it is not an open proxy.
- **Records.** A device *without* the internet picks up to 2 (configurable
  1–3) gateways by total cost, through distinct first hops where it can.
  It signs a pkarr record with its own key: `mycel-gw:<gateway>:<cost>,…|exp:<unix>`. It sends the record to those gateways as mesh control
  messages. Each gateway checks the signature and that it is named in the
  record, then publishes it: to the Mainline DHT (`dht` feature) and to the
  n0 pkarr relay, as Iroh does for normal records. A gateway accepts at
  most 1024 origins' records and one per origin per 10 s.
- **Freshness.**
  - Records carry a TTL of 30 minutes. The origin republishes every 10
    minutes, and at once (at most every 5 s) when its gateway set changes:
    it moved, or a gateway left.
  - pkarr resolution keeps the newest record by timestamp, so a move
    supersedes the old record as soon as the new one propagates. The n0
    relay is immediate; the DHT takes seconds to a minute.
  - Old gateways stop routing to a device they have no mesh route to, so a
    stale record fails fast; the sender re-resolves on path failure.
  - A looked-up record is trusted for a minute (`REACH_TTL`). After that,
    the next packet starts a new lookup and, meanwhile, goes on through a
    gateway of the old record that has a hop up (stale-while-revalidate,
    for another minute, `REACH_STALE`); an out-of-date record never starts
    a dial. A gateway relaying a flow used to park it for a lookup (the
    DHT can take seconds) every minute.
  - When the device gets the internet itself, Iroh's own publisher
    replaces the record with its relay address.
- **Using a record.** Anyone on the internet resolves a key.
  - **Behind gateways:** if the record names gateways, the device has no
    internet and lives behind them. The sender's Iroh gets one mesh address
    per gateway, `mesh(dst, via G)`, so each gateway is its own QUIC path.
    Packets go to G over an *internet hop* (a hop connection opened on
    demand, hung up after 60 s idle). G routes them into its mesh.
  - **Which gateway** (where the core chooses: at a gateway forwarding for
    its mesh, and for custody hand-offs; Iroh's own paths name theirs):
    the lowest record cost + internet hop cost. The gateways of one
    record sit in one mesh around the destination, so a hop not measured
    yet is costed as the cheapest measured hop to another of them (100 ms
    only when none is measured), and one that is up wins ties. A
    measured cost is the round trip *plus* the time to move 64 KiB, well
    above a flat 100 ms guess, so with the guess every untried gateway
    looked cheaper than the one carrying the traffic: each was dialled in
    turn while the traffic waited, and again whenever the unused hop
    idled out (`global-scale`, warm messages: optimality p95 5.14× →
    2.65×; `docs/SIMULATION.md` §4, fixed 19).
  - **Replies:** the reply's waypoint is G, so replies return through the
    same gateway.
  - **Sender without the internet:** it uses its own gateways as waypoints
    (the *default route*). Its gateway resolves the destination and dials the
    far gateway.
  - **US to Europe:** the US phone's packet climbs BLE hops to the US
    gateway, crosses the internet to the EU gateway, then descends BLE hops
    to the EU phone. It is one QUIC connection, encrypted end to end, and
    each US/EU gateway pair is a separate path.

### 7.2 When there is no live path: live → partial → store

Data that must arrive later (sync envelopes, message requests) travels as
**bundles**. The order of preference:

1. **Live route.** If the destination is reachable now, by any mix of
   mesh, gateways and internet, the live QUIC sync does it. No bundle is
   needed. A sync that isn't through within 10 s is also handed to
   carriers (it keeps trying live): a stale connection to a device that
   moved away only times out after 60 s, and the passer-by who could have
   carried the bundle may be gone by then.
2. **Partial route.** If part of the way is up, the bundle moves as far as
   it can *now*, hop by hop with **custody**. Each hop takes
   responsibility and the previous one deletes its copy on an
   acknowledgement. It moves along the mesh route, the default route to a
   gateway, the internet hop to the destination's gateways, and the far
   mesh route. The device at the break holds it until the next segment
   appears.
3. **Spray.** A bundle starts with several copies: 32 for 16 KiB or
   less (chat), falling geometrically to 4 at 256 KiB. While a device
   holds more than one, it hands half to the likeliest neighbour that has
   none, better than itself or not (binary Spray-and-Wait, steered by
   predictability). Devices with the internet don't spray: copies should
   end up there, unless the internet has proved not to reach the
   destination.
4. **Store and carry.** A single copy waits and moves, with custody, only
   to a neighbour with a clearly better **delivery predictability**
   (PRoPHET) for **the internet**. Each device keeps P(x) for destinations
   x and for the virtual destination *internet*. Devices with the internet
   have P(internet) = 1. Encounters raise P, time ages it, and it is
   transitive through neighbours. So a Bluetooth phone's message climbs
   toward the first device with the internet. Once a device with the
   internet has found the destination isn't on it, the copy follows
   predictability for the destination instead.

   How this was chosen (`docs/BENCHMARKS.md` §6.5, `docs/SIMULATION.md`
   §4): spray-first wins or ties on every trace; Spray-and-Focus (spray
   only to neighbours no worse than us) kept copies where they were on
   traces without social structure (Helsinki: 39.5% against 62.9%).
   Following P(destination), as plain PRoPHET does, cost 2–28 points of
   delivery. Following nothing ties on conference traces but loses 13
   points in the simulated disaster zone, where the internet is a few
   partitions away; it wins only where the gateways are fast-moving trams
   with tiny stores. 32 copies for chat take delivery within an hour on
   Helsinki from 61% to 94%. The policies are `DtnConfig` knobs
   (`spray`, `gradient`, `copies`, `copies_small`).

### 7.3 Carriers' limits

A bundle is an already-signed, already-encrypted batch of Mycel envelopes
addressed to a key. Its header (id, source, destination, creation time,
lifetime, copies) is signed by the source.
- **What carriers learn:** destination key, size and timing; never content.
- **Per-carrier limits:** a 64 MiB store for others' bundles (a device's
  own bundles don't count against it), a 256 KiB maximum bundle, a 4 MiB
  share per source, and lifetimes up to 7 days.
- **Lifetimes run from creation.** A carrier expires a bundle at its
  source's `created + lifetime` (converted through its own wall clock), not
  a fresh lifetime at each hop, and never later than one lifetime from
  when it arrived, whatever the source's clock says.
- **When the store is full:** a carried bundle expiring sooner makes room
  for a fresher one, soonest first (drop-oldest, the best queueing policy
  in Lindgren and Phanse, 2006); if the bundle's source is over its share,
  its own older bundles go first. A bundle that would expire before
  everything carried is refused. A device's own bundles are never dropped
  for others'.
- **Offer first.** A bundle is offered (its signed header and size) before
  any payload crosses the link; the receiver answers take, duplicate or
  refuse. A refusal costs a round trip, not the transfer. Summaries say how
  much room a carrier has left and what could make way (its soonest-expiring
  bundles), so neighbours don't offer what would be refused, and a refusal
  for lack of room stops offers to that carrier until its next summary.
  (Sending the whole payload and refusing at the end turned 95–99% of the
  link time on conference traces into refused transfers, retried every
  second: `docs/BENCHMARKS.md` §6.1.)
- **Summaries say what changed** (`Carrier::summaries`). A new hop
  connection gets everything: the bundles held, the latest receipts, room,
  and the most useful 64 predictabilities. After that a neighbour hears what
  changed, at most every 2 s: bundles taken since, receipts learnt since,
  room, and the predictabilities the gradient uses between full summaries.
  With the internet gradient that is P(internet), plus P(destination) for
  the destinations it holds bundles for that the internet doesn't lead to
  (its summary `wants` them). Every 60 s it gets everything held again, so
  it learns what we dropped, with the full predictability table, so
  PRoPHET's transitivity keeps carrying destination predictabilities hop
  by hop. Nothing changes, nothing is sent. A summary that may not have
  arrived (its stream failed) resets the neighbour to "tell it
  everything". Sending all 64 predictabilities to every neighbour every
  10 s cost 8 kB/s per device at 2,000 devices (`docs/SIMULATION.md` §4).
- **Resume.** A transfer cut short (the median Helsinki contact lasts
  2.4 s) leaves its bytes with the receiver for 5 minutes, bounded to a
  quarter of its store. The next offer of that bundle, from any carrier,
  resumes where it stopped: the id is the hash of the content, checked
  when the last byte arrives.
- **Copies in flight** aren't given again: a single copy on its way to
  one neighbour isn't also offered to another.
- **Rate limits:** per neighbour and per source.
- **A route that just failed gets one share.** When our live packets to
  the destination have just gone unacknowledged along a mesh route (§6,
  item 13: the router tells the carrier, `Carrier::doubt`), our own
  bundles for it send half their copies along the live route and the rest
  to other neighbours, the likeliest first, one share each, keeping the
  last copy for the next route. A black hole on the route can take custody
  of one share, not all of them. Without that evidence custody moves whole
  along a live route, as before.
- **Hand-off order:** deliveries first, then live routes, the gradient,
  and spraying last: contacts end, and a 1 MB spray queued ahead of a
  delivery can cost the delivery.
- **Forgetting:** what a neighbour last told us (its predictabilities and
  bundle ids) is dropped 10 minutes after we last heard from it.
- **Dials:** a failed internet dial backs off (2 s, doubling to 60 s). A
  device with the internet whose dial to a destination without a record
  fails learns that the internet doesn't reach it (`Toward::Unreachable`)
  and carries its bundles by predictability for the destination alone.

### 7.4 Mailboxes and receipts

- **Mailboxes.** A bundle reaching one of the destination's advertised
  gateways is kept there (the destination's *mailbox*) until the
  destination appears on that mesh, then delivered. Conversation keepers
  get their copy through normal sync, since they are members.
- **Receipts.** The destination signs a receipt (bundle id). Receipts
  spread among carriers like MaxProp's acks, and every carrier holding a
  copy deletes it.

## 8. Why not route globally over Bluetooth alone

Flat proactive routing costs every device O(N) state and O(N) messages per
period: O(N²) traffic network-wide. Multi-hop wireless capacity per node
also falls as Θ(1/√(n log n)) (Gupta & Kumar, 2000). Purely radio routing is
therefore limited to neighbourhoods. A message from Boston to Berlin over
50 m Bluetooth hops would need ~100,000 hops. The design keeps each layer
where it works:

| Layer | Scope | Mechanism | State per device |
|---|---|---|---|
| Local mesh | ≤ 10 hops (≤ 2 most of the time) | signed distance vector | origins in scope |
| Global lookup | the planet | pkarr records: DHT, n0 relay | none (looked up on demand, cached 60 s, then refreshed while in use) |
| Distance | the planet | the internet via gateways | open internet hops (≤ 256) |
| Time | days | custody bundles, PRoPHET, mailboxes | bounded store |

## 9. Library decisions

| Need | Decision |
|---|---|
| Transport, encryption, multipath, NAT traversal, relays | **Iroh 1.3** (vendored with our multipath patch) |
| Mesh as a transport | **Iroh custom transport** (ours: `mesh/mod.rs`) |
| Local routing | **Our sans-IO core** (`mesh/core.rs`). Ideas from Babel, B.A.T.M.A.N., OLSR and fisheye. No Rust library routes opaque QUIC packets by Ed25519 key over arbitrary links. |
| Global lookup | **pkarr records** (`iroh-dns`), the n0 relay via Iroh's `PkarrRelayClient`, and the **Mainline DHT** via `n0-mainline` |
| Store-and-forward | **Our sans-IO carrier** (`mesh/dtn.rs`): steered spraying + a PRoPHET gradient toward the internet + custody + offers, resume and receipts. |

## 10. What the tests measure

- **Convergence** (`core.rs` virtual-time harness):
  - time for every node to learn a route after a link appears;
  - time for a dead route to stop being used;
  - loops observed during convergence (must be 0);
  - announcements per node per second against mesh size, with and without
    fisheye and flood reduction.
- **QUIC-level** (`tests/mesh.rs`, `tests/global.rs`):
  - failover between open paths;
  - BLE → gateway → internet → gateway → BLE sync and calls;
  - two gateways aggregated, with failover;
  - gateway choice by total cost;
  - forged records;
  - gateway budgets.
- **Store-and-forward** (`dtn.rs` harness and `tests/global.rs`):
  - partial route with custody;
  - gradient against spray on delivery time;
  - mailboxes;
  - receipts;
  - a data mule across partitions.

### Measured

- **Learning and losing routes** (virtual-time simulator, 500 ms period, 5 ms per hop):
  - routes across a new link: 0.4 s at 2 hops, 1.4 s up to 8 hops;
  - a dead route is unused 25 ms after the link drops (retraction);
  - a cut ring heals in 0.6 s (seqno request).
- **Loops:** zero frame loops and zero route loops, checked at every step through 60 link flaps in a 30-device mesh with traffic.
- **Overhead per device** (`mycel-sim flood-scaling`, Bluetooth-only phones with ~12 neighbours, steady state): 3.4 kB/s at 2,000 devices, 8.4% of a BLE radio, with every pair within 8 hops routed. With the old timing (2 s, full scope of 8 hops every 4th, flood reduction): 26.8 kB/s (67%), 85% routed. Fisheye alone cuts traffic 4–5× (`docs/SIMULATION.md` §5). In `global-scale` (2,002 devices in neighbourhoods of 80) routing costs 467 B/s per device, down from 3,768.
- **Gateways** (QUIC, in-process): a Bluetooth-only device three BLE hops from its gateway syncs with one behind another gateway; the first sync took 0.58 s. A test-tone call along that route had 84 ms RTT and 0 % loss.
- **Two gateways:** 2.0× one path's throughput. When one is lost, the longest pause on the other is 0.8–2.6 s: data in flight leaves a hole in the stream until the dead path's loss detection gives up.
- **Store-and-forward:** spraying 4 copies, then a single copy following the gradient toward the internet, gets the first copy to the internet in 28 min (mean of 40 traces, 4 clusters in a chain). The same 4 copies with no gradient (Spray-and-Wait) don't get there within 12 h. A real data mule delivered 1 s after meeting the destination. Against The ONE's routers on real contact traces, see `docs/BENCHMARKS.md`.
