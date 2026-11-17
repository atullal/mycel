# Routing design

This document explains how a Mycel device reaches another one when the two
share no network, and why the routing is built the way it is. It states the
constraints, describes the design (a signed distance-vector mesh, gateways
and reachability records, relays among devices, store-and-forward), reports
what was measured, and surveys the routing and delay-tolerant-networking
protocols the design draws on.

It is for people who work on `crates/mycel-net/src/mesh/` or who want to
judge the design. [ARCHITECTURE.md](ARCHITECTURE.md) gives a shorter tour of
the same machinery, and [TRUST.md](TRUST.md) says what relays, gateways and
carriers can and cannot do to the traffic they carry.

## Contents

- [Problem and constraints](#problem-and-constraints)
- [Design in brief](#design-in-brief)
- [Local mesh](#local-mesh)
- [Beyond one mesh](#beyond-one-mesh)
- [Store-and-forward](#store-and-forward)
- [Defaults](#defaults)
- [Measurements](#measurements)
- [Survey of prior work](#survey-of-prior-work)
- [Limitations and open questions](#limitations-and-open-questions)

## Problem and constraints

Three cases set the problem:

- a Bluetooth-only phone in the US messaging a Bluetooth-only phone in
  Europe;
- a crowd of 300 at a conference with no Wi-Fi;
- a village with one satellite uplink.

In each, the two ends share no network. Eight constraints decide the design.

1. QUIC provides the end-to-end encryption. A relay forwards the ciphertext
   of a connection between two other devices, so the routing layer carries
   opaque packets and never terminates a session. That rules out designs
   that are their own encrypted transport (Reticulum, cjdns, Yggdrasil,
   libp2p), unless Iroh is abandoned.
2. There is one identity. The Ed25519 device key is the Iroh endpoint id,
   the Mycel signing key and the routing identity. A second key system
   (Reticulum destinations, cjdns IPv6-from-key, libp2p PeerIds) would mean
   a second trust problem.
3. Any medium carries traffic, and media mix: BLE L2CAP (tens of kB/s),
   AWDL, LAN, Wi-Fi Direct, UWB / 802.15.4, the internet. Costs are
   measured, not hard-coded, and comparable across media.
4. Routing feeds multipath. Several routes to one destination become
   several QUIC paths, which noq aggregates and fails over between. Routes
   must therefore be addressable separately: a mesh address is
   `(destination, waypoint)`.
5. Links churn. People walk, and in a crowd links appear and vanish every
   few seconds. Convergence must be fast, and loop-free while it converges.
6. Global reach needs no server that Mycel runs. Lookups work through
   infrastructure nobody here operates (the Mainline DHT). n0's DNS server,
   which Iroh uses by default, is a faster addition, and n0's relay servers
   are the default way in to a device behind a router. Each can be switched
   off, and then only other devices and the DHT are involved.
7. Disconnection is normal. When no end-to-end path exists, data still
   moves toward its destination and is delivered later, without giving
   carriers any plaintext.
8. The router can be simulated. The routing core must run 100k nodes in one
   process on a virtual clock, so it owns no sockets, timers or threads.

## Design in brief

Routing is hierarchical. Each layer does what it scales to:

| Layer | Scope | Mechanism | State per device |
|---|---|---|---|
| Local mesh | ≤ 10 hops (≤ 2 most of the time) | signed distance vector | origins in scope |
| Global lookup | the planet | pkarr records in the Mainline DHT and on n0's DNS server | none (looked up on demand, cached 60 s, then refreshed while in use) |
| Distance | the planet | the internet, through gateways and relays | open internet hops (≤ 256) |
| Time | days | custody bundles, PRoPHET, mailboxes | bounded store |

Devices in range of each other form a **mesh**. Two neighbours keep a **hop
connection** between them: a QUIC connection over whatever links they share,
on which mesh frames travel as datagrams. A device that forwards the packets
of a connection between two other devices is a **relay**. It forwards
ciphertext and needs to be a member of nothing the two ends share.

Each device announces itself in a signed **announcement** that its
neighbours pass on. From the announcements it hears, a device keeps the
neighbours that lead to every device within a few hops, and at what cost.
Up to 3 routes per destination are offered to QUIC as separate paths.

A device that has the internet and relays for its mesh is a **gateway**. A
device without the internet signs a **reachability record** naming its best
gateways, and the gateways publish it under the device's key. Anyone on the
internet resolves the key and reaches the device through those gateways,
over **internet hops**: hop connections opened on demand across the
internet. A message climbs from Bluetooth to the nearest device with the
internet, crosses the internet in milliseconds, and descends through the far
side's gateway.

A device that has the internet but sits behind a router that lets nothing in
is reached the same way. It asks devices the internet can dial in to,
**internet relays**, to carry traffic for it, and names them in the record
it publishes itself. That needs no **relay server** (an `iroh-relay`; n0's
are the default and can be switched off).

When there is no live path, **store-and-forward** moves data toward
connectivity as **bundles**. Spare copies go to the likeliest neighbours
first. Then a single copy climbs by delivery predictability toward the
internet, with hop-by-hop custody, mailboxes at the far gateways, and signed
receipts.

### Why the layers

Flat proactive routing costs every device O(N) state and O(N) messages per
period, which is O(N²) traffic across the network. The capacity of
multi-hop wireless per node also falls as Θ(1/√(n log n)) (Gupta & Kumar,
2000). Routing by radio alone is therefore limited to neighbourhoods: a
message from Boston to Berlin over 50 m Bluetooth hops would need about
100,000 hops. The design keeps each layer where it works.

### What is reused and what is Mycel's own

| Need | Decision |
|---|---|
| Transport, encryption, multipath, NAT traversal, relay servers | Iroh 1.3, vendored with Mycel's multipath patch |
| Mesh as a transport | an Iroh custom transport (`mesh/mod.rs`) |
| Local routing | Mycel's own core (`mesh/core.rs`) |
| Global lookup | pkarr records (`iroh-dns`) in the Mainline DHT (`n0-mainline`) and on n0's DNS server (Iroh's `PkarrRelayClient`) |
| Relays among devices | the same core and records (`mesh/relay.rs`) |
| Store-and-forward | Mycel's own core (`mesh/dtn.rs`): steered spraying, a PRoPHET gradient toward the internet, custody, offers, resume and receipts |

`n0-mainline` is the crate Iroh's own DHT lookup uses. The ideas come from
Babel, B.A.T.M.A.N., OLSR, fisheye routing, PRoPHET, Spray-and-Wait and
MaxProp; the [survey](#survey-of-prior-work) says which.

The routing core is Mycel's own because no existing Rust library routes
opaque QUIC packets between Iroh endpoints, by Ed25519 key, over arbitrary
links. Store-and-forward is Mycel's own because the Rust implementation of
the [Bundle Protocol](#bundle-protocol-v7-rfc-9171) is a daemon, not a core
that can be embedded. No new transport library is needed.

### Where the code is

All of it is in `crates/mycel-net/src/mesh/`.

| File | What it holds |
|---|---|
| `core.rs` | the router, as a pure state machine |
| `mod.rs` | the driver: hop connections, datagrams, clocks, queue management |
| `wire.rs` | frames on the wire, mesh addresses, announcement signatures |
| `watch.rs` | end-to-end evidence from QUIC paths, for the router |
| `directory.rs` | the record format and the directory backends |
| `records.rs` | a device's own record, and lookups of others' |
| `relay.rs` | relays among devices: choosing, asking, answering |
| `dtn.rs` | store-and-forward, as a pure state machine |

The two state machines do no I/O, read no clock and check no signature
themselves. Every input carries the time, and every effect comes back as a
value for the caller to carry out. The driver wraps them around QUIC; the
simulator runs many of them on a virtual clock.

## Local mesh

Route tables are distributed and partial. Each device keeps, for every
origin within its scope, the neighbours that announced it, each with a
cost, a hop count and a sequence number (seqno), plus one feasibility
distance. Nobody has a global table. The tables are kept in step by signed
announcements: periodic ones every 16 s (Babel's update interval), and
triggered ones when something changes.

### Announcements

An announcement (`Announce`) is signed by its origin over the origin's key,
seqno, flags, scope, uplink cost and name. Relays fill in `hops` and
`cost`, which are not signed, as in B.A.T.M.A.N. and Babel.

Each relay rebroadcasts the best copy of each seqno once, after a jitter of
10–50 ms. It never sends it to a neighbour that already sent it that seqno,
since that neighbour has it. Announcements for one neighbour leave in one
datagram (`T_OGMS`), which saves a QUIC packet's ~40 bytes of headers and,
on Bluetooth, a connection event per announcement.

### Cost

A route's cost is the sum over its hops of the hop's smoothed RTT, in units
of 0.1 ms, plus 2 ms per hop. The driver feeds in each hop connection's
measured RTT plus a throughput term: the time to move 64 KiB at the rate
the hop's congestion window allows (cwnd per RTT). So BLE, AWDL and cable
hops rank themselves.

A gateway's announcement also carries its **uplink cost**: its measured
internet RTT and throughput term. A device without the internet picks the
gateway with the lowest total of mesh cost and uplink cost. A fibre gateway
four hops away beats a congested one next door.

### Sequence numbers

A seqno is the origin's wall clock in milliseconds, made strictly
increasing per origin (`max(now, last + 1)`). Seqnos are only ever
compared for the same origin, so clock skew between devices doesn't affect
the comparison, and a restarted device needs no stored counter. A
per-origin counter would need persistence and a recovery path after a
reinstall; wall-clock milliseconds give both for free.

An announcement more than 10 minutes from the receiver's clock is rejected
as a replay. That needs clocks within 10 minutes of each other, which
phones synced by NTP or GPS have.

### Feasibility condition

For each origin a device remembers its feasibility distance, FD: the seqno
it last advertised for that origin and the lowest cost it advertised with
it. A route through neighbour n, advertised as (s, c), is usable only if
`s > FD.seq`, or `s = FD.seq` and `c < FD.cost`.

Any accepted route is therefore strictly closer to the origin than anything
the device told others, so no loop can form while the mesh converges. This
is Babel's condition. A TTL alone would only end a loop after it formed.

### Retractions and seqno requests

When a hop goes down, every origin that is left without a feasible route is
retracted at once: the device sends its neighbours the origin's latest
signed announcement with cost ∞. They drop that route and, if it was their
last, retract in turn. A dead route stops being used in about one RTT per
hop, instead of after a timeout of 3.5 periods.

With routes left but none feasible (starvation), or right after a
retraction, the device asks for a fresh seqno. The request travels toward
the origin. A device that already has a newer feasible announcement answers
with it; the origin answers by announcing at once, rate-limited. Recovery
takes about an RTT, not up to an announcement period.

### Fisheye scope

Every period an origin announces with a scope of 2 hops. Every 8th period
it uses the full scope of 10 hops. Nearby routes refresh every 16 s and far
ones every 128 s, with timeouts scaled to match. Each device originates the
same number of announcements, but 7 times out of 8 an announcement floods a
2-hop neighbourhood instead of the whole mesh.

The full scope is 10 hops, not 8, because routes follow the cheapest path,
which can be a hop or two longer than the path with the fewest hops. With
8, devices 8 radio hops apart were missed (3% of pairs in `flood-scaling`).

### Timing

The period only refreshes routes, so Babel's 16 s is enough. A short
period, as in B.A.T.M.A.N., is needed when routes must expire for a loss to
be noticed. Here a hop connection notices a lost link within seconds
(keep-alives every 1.5 s, a 5 s idle timeout) and triggers retractions and
seqno requests. What changes goes out at once:

- retractions and seqno requests;
- a full-scope announcement to a device's first neighbour, because what the
  device announced alone reached nobody;
- a greeting to a new neighbour with the device's routes (Babel's full
  update to a new neighbour), each within its announcement's scope, so
  meeting a mesh doesn't wait for a period.

In a crowd everyone meets 15 devices at once and one table is enough to
join. So a device greets at most one new neighbour per 4 s. The others get
its own announcement at once, and are greeted in turn with what they
haven't heard meanwhile.

### Flooding over unicast hops

Mycel does no broadcast-style flood reduction. The Trickle-style rule (in a
dense neighbourhood, skip the rebroadcast after hearing 3 copies at least
as good as one's own) exists as `Config::flood_reduction` and is off by
default.

The rule assumes broadcast radios, where those 3 copies reached the
device's neighbours too. Over unicast hop connections they reached the
senders' own neighbours, and 9% of pairs were left without a route after a
flood (`routing-convergence`). OLSR's multipoint relays would need 2-hop
state.

### Hop connections

A device opens hop connections to at most 6 devices in range. Each device
makes its own pseudo-random pick, so the connections spread out, and others
open theirs to it: about 11 in all in a crowd. A Bluetooth radio holds
about 10 connections, and each costs keep-alives and a share of every
announcement.

Direct traffic between two devices in range doesn't need a hop connection.
It uses the link itself.

### Multipath and failover

A mesh address names a destination and a waypoint, `mesh(dst, via)`: the
neighbour or gateway the packets leave through, which also routes the
replies. Each route to a destination is a distinct address, so Iroh opens
one QUIC path per route. Up to 3 routes per destination, through distinct
neighbours, are open paths at once. A route costing more than 4 times the
best plus 30 ms isn't offered, and a route already in use counts as 20%
cheaper, so routes don't flap.

A direct path always beats the mesh. A device with a direct link to a
destination gets no mesh addresses for it, and the mesh refuses to carry
data to a neighbour. That also keeps hop connections from running over the
mesh themselves.

When one path breaks, traffic continues on the others within about a probe
timeout, not the path's 5 s idle timeout. Routing convergence only decides
which routes to add. This depends on Mycel's patch to noq (section 3 of
`vendor/noq-proto/MYCEL_PATCH.md`):

- a path that stopped both acknowledging and hearing gets no new data, and
  its in-flight packets are retransmitted on the others;
- ACKs move off a path that went quiet, so the peer isn't left hearing
  nothing;
- stale ACKs don't inflate its RTT;
- path selection, and with it the path that calls and the Network panel
  report, moves off the dead path at once.

Without the patch, losing a relay mid-transfer stalls the rest for 5–20 s
in about 1 run in 4 (`two_routes_aggregate_and_fail_over` in
`tests/mesh.rs`).

### Budgets

A relay spends a bounded rate on other devices' traffic: one budget per
neighbour the traffic arrives from, and one in total. Traffic crossing
between the mesh and the internet draws on a gateway budget as well, and
traffic between two internet hops on an internet relay's budget. Each
neighbour may send a bounded rate of announcements, and a relay floods one
origin's new seqnos at most every 250 ms, so a device that storms reaches
its neighbours, not the mesh. The values are under [Defaults](#defaults).

### Lying neighbours

An announcement's hops and cost aren't signed: relays fill them in. A black
hole can relay every origin "at no cost" to pull traffic toward itself and
drop it.

Each honest hop, though, adds one hop and at least 2.1 ms of cost
(`MIN_HOP_COST`: a measured cost of at least 0.1 ms plus `HOP_PENALTY`),
and only the origin sends zero hops. A relayed announcement below that
floor can't come from an honest relay. Its sender, a direct neighbour over
its own authenticated hop connection, is **distrusted** for 10 minutes:

- the routes it gave go at once (retractions and seqno requests restore the
  others);
- the routes it relays are ignored;
- it stays reachable itself, since its own announcements are signed by it.

A liar that claims plausible values (one hop from everyone, at the least
cost) isn't caught by this. [End-to-end feedback](#end-to-end-feedback) is
what stops that one. The effect of both is under
[Measurements](#black-holes).

### End-to-end feedback

What a liar can't fake is the destination's acknowledgements. The transport
tells the router (`Router::feedback`) when a whole retransmission timeout
passes with nothing acknowledged for the device's packets to a destination,
and when an acknowledgement comes back. Its timeout follows the measured
round trip, so a slow path isn't taken for a dead one.

A next hop is **suspected** for a destination, for 2 minutes, after two
timeouts in a row through it, provided that:

- the mesh route through it still claims to reach the destination;
- the hop is still up;
- the silence has lasted at least 1.5 s plus twice the route's cost, so
  slow or busy routes get longer.

While a hop is suspected, the device's packets to that destination, and
those it relays to it, take the next feasible route. Any feasible route is
loop-free, not only the best. With every route suspected they still take
the best: dropping can't deliver, and suspicion can be wrong.
Store-and-forward also stops trusting that route with every copy of the
device's own bundles ([Hand-offs](#hand-offs)). One acknowledgement clears
the count.

Its reach is limited in three ways:

- Routes through gateways or the internet aren't judged. The destination
  may only be offline.
- Custody hand-offs aren't steered by suspicion. On a trace of brief
  contacts, where routes stop delivering for ordinary reasons, that cost
  more than it saved.
- Relays can't judge on their own. The acknowledgements are inside the
  end-to-end encryption, and the reverse path needn't pass them.

In the node the evidence comes per QUIC path (`mesh/watch.rs`). Every
end-to-end connection (pooled, dialled for another protocol, or accepted)
is watched. A path `mesh(dst, via)` that the device keeps sending on and
that has had no frame back for 3 s (both ends send keep-alives every 1.5 s),
or that QUIC gives up while still silent (after 5 s), is reported to
`Router::path_feedback`. Frames arriving again clear it.

Only frames that QUIC counted after decrypting the packet that carried them
count, so a relay can drop them but can't fake them. Nothing at the mesh
layer counts, such as a packet merely claiming to come from the
destination. The same rules apply: two silences scaled to the route's cost,
mesh routes only.

A suspected hop's route stops being offered as a QUIC path for that
destination (`RouteDown`) and the next one is offered (`RouteUp`). If every
other route is infeasible because the device advertised the cheap one, it
asks for a fresh seqno, not through the suspect, as after a loss.
Store-and-forward is told (`Carrier::doubt`).

Feedback finds a liar only by losing traffic to it first, and only at
sources. Signing what relays add would stop the lie itself; that is the
first of the [open questions](#limitations-and-open-questions).

### Queue management on hops

Announcements, seqno requests, keep-alives and the acknowledgements of the
end-to-end connections share each hop with the bulk data. Below QUIC that
hop is a first-in, first-out queue nobody can reorder: the radio's or the
Bluetooth controller's send buffer. The hop connection's congestion control
(Cubic) fills that buffer until it overflows.

Left alone, a saturated hop's queue on the 400 kB/s test radios holds
170 ms on average (250 ms, full, at worst) and drops ~1.5% of what reaches
it, control included. End-to-end paths through two such hops run at
300–600 ms RTT, and a path that loses packets grows its window back by
about one packet per RTT, too slowly to recover within a transfer. That,
not lost announcements (each relay's arrive at the full rate, at most
400 ms late), is why two routes sometimes carried only 1.2–1.4× one route.

So each device runs CoDel (RFC 8289) on every hop to a device in range. The
hop's smoothed RTT above its lowest stands in for the queueing delay.

- When the RTT stays more than a target above its lowest for an interval, a
  data frame is dropped, then more often while it stays above. The
  end-to-end connections slow down before the buffer fills.
- The interval is 100 ms, longer on slow hops, and never shorter than the
  hop's RTT: no sender can react sooner.
- The target is the time to send 3 full packets at the rate the hop
  delivers, at least 20 ms (radio jitter isn't a queue) and at most 250 ms:
  20 ms at 400 kB/s, ~180 ms at Bluetooth's 20 kB/s.
- Announcements, seqno requests, control frames and packets of 400 bytes or
  less (acknowledgements, voice) are never dropped.
- Internet hops are left alone. Their queues are shared with the rest of
  the internet.
- When a second of dropping doesn't drain a queue, someone else's traffic
  fills it or the link got slower. The delay becomes the new base instead
  of starving Mycel's traffic.

Nothing changes on the wire: queue management only decides which frames a
device puts on its own hops. The results are under
[Measurements](#saturated-hops).

## Beyond one mesh

### Gateways

A device that reaches the internet and relays for others sets the gateway
flag and its uplink cost in its announcements, both signed. A device
without the internet keeps a **default route** to the gateway with the
lowest total cost and sends there whatever it has no mesh route for.

A gateway budget caps what crosses between the mesh and the internet. A
device whose uplink is metered (mobile data) is not a gateway: nothing of
anyone else's goes over an uplink paid for by the byte. It still relays
between devices near it, which costs no data.

A gateway is not an open proxy. It never looks a device up or dials one for
traffic that came from the internet, and it passes traffic between two
internet hops only as the [internet relay](#relays-among-devices) of one of
them.

### Reachability records

A reachability record says how to reach a device from the internet. It is a
pkarr signed packet, the format Iroh's own address lookup uses, signed by
the device's own key and resolved by that key, so any pkarr resolver can
read it. Besides addresses to dial, it carries these items, separated by
`|`:

| Item | Meaning |
|---|---|
| `mycel-gw:<key>:<cost>,…` | up to 3 devices that carry traffic to this one (gateways or internet relays), with its cost to each |
| `mycel-relay` | the internet can reach this device, and it relays for devices that ask |
| `exp:<unix seconds>` | nobody should use the record after this time |

A record without `mycel-gw` reads as "dial the device directly".

Records are published in two ways.

A device without the internet picks up to 2 gateways (configurable, 1–3) by
total cost, through distinct first hops where it can. It signs a record
naming them, which needs no network, and sends it to those gateways as a
mesh control message. Each gateway checks the signature and that the record
names it, then publishes it. A gateway publishes for at most 1,024 origins,
and one record per origin per 10 s.

A device with the internet publishes its own record (`mesh/records.rs`), in
place of Iroh's publisher, so that one record says everything wherever it
is published. The record always lists the relay servers the device is
connected to, which don't say where the device is. It lists IP addresses
only while the device is public: it is an internet relay, or the internet
can dial in to it and it uses no relay server. A device behind a router
publishes no IP address and names its internet relays.

Records live in two directories (`mesh/directory.rs`): the Mainline DHT,
which nobody operates, and n0's DNS server, a pkarr relay that Iroh
resolves through by default. `MYCEL_DHT=0` and `MYCEL_N0_DNS=0` switch each
off. A lookup asks every directory that is on and keeps the newest record
by pkarr timestamp. A device remembers DHT nodes from its last run, so
joining the DHT again doesn't depend on the DHT's well-known bootstrap
hosts.

Records are kept fresh as follows:

- A record is valid for 30 minutes. A device without the internet
  republishes every 10 minutes, and at once (at most every 5 s) when its
  gateway set changes: it moved, or a gateway left. A device with the
  internet republishes its own when its addresses or its role change, and
  every 5 minutes.
- Resolution keeps the newest record, so a move supersedes the old record
  as soon as the new one propagates. On n0's server that is at once; the
  DHT takes longer.
- Old gateways stop routing to a device they have no mesh route to, so a
  stale record fails fast, and the sender resolves again on path failure.
- A looked-up record is trusted for a minute (`REACH_TTL`). After that the
  next packet starts a new lookup and meanwhile goes on through a gateway
  of the old record that has a hop up (stale-while-revalidate, for another
  minute, `REACH_STALE`). An out-of-date record never starts a dial.
  Without this, a gateway relaying a flow would park it for a lookup once a
  minute, and a DHT lookup can take seconds.
- When a device gets the internet itself, the record it then publishes for
  itself is newer and replaces the one its gateways published.

### Relays among devices

Two devices behind home routers can't dial each other: each router lets in
only answers to what went out. Something both can reach has to pass packets
between them. By default that is a relay server. Internet relays let
devices do it for each other, so reaching a device over the internet needs
no relay server (`mesh/relay.rs`; the routing is in `mesh/core.rs`).

A device is an internet relay while the internet can dial in to it (a
public address, a forwarded port), it has the internet, and its uplink
isn't metered. It learns whether it can be dialled from its DHT node, which
sees whether unsolicited packets get through; `MYCEL_REACHABLE` says so
instead, and `MYCEL_INTERNET_RELAY=0` turns the role off. Its record says
`mycel-relay` and gives its address.

A device is a **client** when it has the internet, the internet can't dial
in to it, and no relay server is connected. A device whose relay server is
switched off, blocked or down therefore falls back to internet relays by
itself. A client:

1. Collects candidates: the devices it was told about (its contacts, then
   the members of its conversations, keepers included) and the relays those
   devices name in their own records. That is two steps from someone it
   knows, and no further. One contact behind a relay is enough to find one.
2. Reads each candidate's record, and asks only those whose own signed
   record says they relay.
3. Keeps a hop connection up to each relay it chose, 2 by default. The hop
   is dialled again when it drops and is never hung up as idle: it is how
   traffic for the client gets in.
4. Asks each to be its relay, and again every minute.
5. Names the relays that agreed in its own record, as `mycel-gw` entries,
   the way a device without the internet names its gateways.

Whoever looks the client up gets one mesh address per relay, each its own
QUIC path, exactly as for a device behind gateways. Losing one relay costs
a path, not the connection.

An internet relay carries traffic between two internet hops only if one end
is its client. A request counts only when it arrives straight from the
asking device, on that device's own authenticated hop connection. Like a
gateway, it never looks up or dials anyone for traffic that came from the
internet. So nobody can bounce traffic through a device that didn't agree
to it, or enrol someone else as a client.

What relaying costs a device is bounded:

- Traffic between two internet hops has a budget of its own, on top of the
  per-neighbour and total relay budgets.
- The number of clients is bounded. A client is forgotten when its hop
  drops, or when it hasn't asked for 3 minutes.
- When every place is taken, a device the relay knows takes the place of
  the stranger that asked longest ago. Strangers can fill the places but
  can't keep out the devices the relay knows.
- Nothing is relayed over a metered uplink. On mobile data a device drops
  its clients and stops being an internet relay and a gateway, so nobody
  else's traffic is paid for by it.

An internet relay also leads to a direct path. The hop to it is an ordinary
QUIC connection, so the relay sees the client's address as the internet
does, and says so when it agrees. The client gives that address to Iroh,
which offers it to the devices the client talks to. A connection that
started through a relay can then move to a direct path, and the relay
carries only what can't.

A client gives up on a relay that refuses, doesn't answer within 10 s or
can't be connected to within 30 s. It takes the next candidate and doesn't
try that relay again for 10 minutes. It also drops a relay whose record no
longer says it relays.

### Reaching a device through its record

Anyone on the internet resolves a key. If the record names gateways or
internet relays, the device sits behind them. The sender's Iroh gets one
mesh address per device named, `mesh(dst, via G)`, so each is its own QUIC
path. Packets go to G over an internet hop, which is opened on demand and
hung up after 60 s idle. G routes them into its mesh, or passes them to its
client.

Iroh's own paths each name their gateway. The core chooses one itself in
two places: at a gateway forwarding for its mesh, and for custody hand-offs.
It takes the lowest sum of the record's cost and the internet hop's cost,
and on equal cost a hop that is up.

The gateways of one record sit in one mesh around the destination. So a hop
not measured yet is costed as the cheapest measured hop to another of them,
and as 100 ms only when none is measured. A measured cost is the round trip
plus the time to move 64 KiB, well above a flat 100 ms. With a flat guess,
every untried gateway looks cheaper than the one carrying the traffic: each
is dialled in turn while the traffic waits, and again whenever the unused
hop idles out.

Replies carry the same waypoint, so they return through the same gateway. A
sender without the internet uses its own gateways as waypoints (its default
route); its gateway resolves the destination and dials the far gateway.

From a Bluetooth-only phone in the US to one in Europe, a packet climbs BLE
hops to the US gateway, crosses the internet to the EU gateway, then
descends BLE hops to the EU phone. It is one QUIC connection, encrypted end
to end, and each pair of US and EU gateways is a separate path.

## Store-and-forward

Data that must arrive later (sync envelopes, message requests) travels as
**bundles**. A bundle is an already-signed, already-encrypted batch of Mycel
envelopes addressed to a key. Its id is the hash of its source, destination
and payload, and the source signs the id, the creation time and the
lifetime. A device that holds a bundle for someone else is a **carrier**.
Carriers learn the source and destination keys, the size and the timing,
never the content.

### From live route to stored bundle

A device tries four things, in this order:

1. If the destination is reachable now, by any mix of mesh, gateways and
   internet, the live QUIC sync does it and no bundle is needed. A sync
   that isn't through within 10 s is also handed to carriers while it keeps
   trying live. A stale connection to a device that moved away only times
   out after 60 s, and the passer-by who could have carried the bundle may
   be gone by then.
2. If part of the way is up, the bundle moves as far as it can now, hop by
   hop with **custody**: each hop takes responsibility, and the previous
   one deletes its copy on an acknowledgement. The bundle moves along the
   mesh route, the default route to a gateway, the internet hop to the
   destination's gateways, and the far mesh route. The device at the break
   holds it until the next segment appears.
3. With no next hop, spare copies are sprayed. A bundle starts with several
   copies: 32 for 16 KiB or less (chat), falling geometrically to 4 at
   256 KiB. While a device holds more than one, it hands half to the
   likeliest neighbour that has none, whether that neighbour is better than
   itself or not (binary Spray-and-Wait, steered by predictability).
   Devices with the internet don't spray, because copies should end up
   there, unless the internet has proved not to reach the destination.
4. A single copy is stored and carried. It waits, and moves with custody
   only to a neighbour with a clearly better **delivery predictability**
   (PRoPHET) for the internet.

Each device keeps a predictability P(x) for destinations x and for the
virtual destination *internet*. Devices with the internet have
P(internet) = 1. Encounters raise P, time ages it, and it is transitive
through neighbours. So a Bluetooth phone's message climbs toward the first
device with the internet. Once a device with the internet has found that
the destination isn't on it, the copy follows predictability for the
destination instead.

### Why spray first, then climb toward the internet

The policy was chosen on contact traces and in simulation
([BENCHMARKS.md](BENCHMARKS.md), section 6, and
[SIMULATION.md](SIMULATION.md), section 4):

- Spraying first wins or ties on every trace. Spray-and-Focus (spray only
  to neighbours no worse than the holder) kept copies where they were on
  traces without social structure (Helsinki: 39.5% against 62.9%).
- Following P(destination), as plain PRoPHET does, cost 2–28 points of
  delivery.
- Following nothing ties on conference traces but loses 13 points in the
  simulated disaster zone, where the internet is a few partitions away. It
  wins only where the gateways are fast-moving trams with tiny stores.
- 32 copies for chat take delivery within an hour on Helsinki from 61% to
  94%.

The policies are `DtnConfig` knobs (`spray`, `gradient`, `copies`,
`copies_small`).

### What carriers hold

A carrier's store for other devices' bundles is 64 MiB; a device's own
bundles don't count against it. A bundle is at most 256 KiB, one source
gets a share of 4 MiB, and lifetimes run up to 7 days.

Lifetimes run from creation. A carrier expires a bundle at its source's
`created + lifetime`, converted through its own wall clock, not after a
fresh lifetime at each hop, and never later than one lifetime from when it
arrived, whatever the source's clock says.

When the store is full, a carried bundle that expires sooner makes room for
one that expires later, soonest first (drop-oldest, the best queueing
policy in Lindgren and Phanse, 2006). If the new bundle's source is over
its share, that source's own older bundles go first. A bundle that would
expire before everything carried is refused. A device's own bundles are
never dropped for others'.

What a neighbour last told a carrier (its predictabilities and bundle ids)
is dropped 10 minutes after the carrier last heard from it.

### Offers and resume

A bundle is offered, as its signed header and size, before any payload
crosses the link. The receiver answers take, duplicate or refuse, so a
refusal costs a round trip, not the transfer. Sending the whole payload and
refusing at the end turned 95–99% of the link time on conference traces
into refused transfers, retried every second ([BENCHMARKS.md](BENCHMARKS.md),
section 6).

A transfer cut short (the median Helsinki contact lasts 2.4 s) leaves its
bytes with the receiver for 5 minutes, bounded to a quarter of its store.
The next offer of that bundle, from any carrier, resumes where it stopped:
the id is the hash of the content, checked when the last byte arrives.

### Summaries

Summaries (`Carrier::summaries`) tell each neighbour what it needs to plan
its offers. They say how much room a carrier has left and what could make
way (its soonest-expiring bundles), so neighbours don't offer what would be
refused. A refusal for lack of room stops offers to that carrier until its
next summary.

A summary says what changed:

- A new hop connection gets everything: the bundles held, the latest
  receipts, room, and the most useful 64 predictabilities.
- After that a neighbour hears what changed, at most every 2 s: bundles
  taken since, receipts learnt since, room, and the predictabilities the
  gradient uses. With the internet gradient that is P(internet), plus
  P(destination) for the destinations the neighbour holds bundles for that
  the internet doesn't lead to (its summary `wants` them).
- Every 60 s it gets everything held again, so it learns what was dropped,
  with the full predictability table, so PRoPHET's transitivity keeps
  carrying destination predictabilities hop by hop.
- When nothing changes, nothing is sent. A summary that may not have
  arrived, because its stream failed, resets the neighbour to "tell it
  everything".

Sending all 64 predictabilities to every neighbour every 10 s cost 8 kB/s
per device at 2,000 devices ([SIMULATION.md](SIMULATION.md), section 4).

### Hand-offs

Hand-offs to a neighbour go in this order: deliveries first, then live
routes, the gradient, and spraying last. Contacts end, and a 1 MB spray
queued ahead of a delivery can cost the delivery. At most 8 bundles are
handed to one neighbour at a time.

Copies in flight aren't given again: a single copy on its way to one
neighbour isn't also offered to another.

A route that failed a moment ago gets one share. When a device's live
packets to a destination have gone unacknowledged along a mesh route
([end-to-end feedback](#end-to-end-feedback) tells the carrier through
`Carrier::doubt`), its own bundles for that destination send half their
copies along the live route and the rest to other neighbours, the likeliest
first, one share each, keeping the last copy for the next route. A black
hole on the route can take custody of one share, not all of them. Without
that evidence custody moves whole along a live route.

A failed internet dial backs off: 2 s, doubling to 60 s. A device with the
internet whose dial to a destination without a record fails learns that the
internet doesn't reach it (`Toward::Unreachable`), and carries its bundles
by predictability for the destination alone.

### Mailboxes and receipts

A bundle that reaches one of the destination's advertised gateways is kept
there, in the destination's **mailbox**, until the destination appears on
that mesh, and is then delivered. Conversation keepers get their copy
through normal sync, since they are members.

The destination signs a **receipt** for the bundle id. Receipts spread
among carriers like MaxProp's acknowledgements, and every carrier holding a
copy deletes it.

## Defaults

These are the router's defaults: fields of `Config` and constants in
`mesh/core.rs`, with the driver's in `MeshOptions` (`mesh/mod.rs`) and the
record publisher's in `mesh/records.rs`. The carrier's limits are under
[What carriers hold](#what-carriers-hold).

| Setting | Default | In code |
|---|---|---|
| Hop limit of a route or an announcement | 10 | `max_hops` |
| Routes per destination | 3 | `routes` |
| Announcement period | 16 s | `announce_every` |
| Near scope, full scope | 2 hops, 10 hops every 8th period | `NEAR_SCOPE`, `FAR_EVERY` |
| Route timeout | 3.5 periods, 8 times that beyond the near scope | `Router::expires` |
| Clock window for announcements | ±10 min | `MAX_CLOCK_SKEW_MS` |
| Announcements accepted per neighbour | 100/s, burst 400 | `OGM_RATE` |
| One origin's floods through a relay | at most every 250 ms | `ORIGIN_GAP` |
| Seqno requests | one per origin per second, 8 hops | `SEQREQ_GAP`, `SEQREQ_HOPS` |
| An origin's answers to seqno requests | at most every 500 ms | `FORCED_GAP` |
| Hop connections a device opens | 6 | `MeshOptions::max_neighbours` |
| Relay budget per neighbour, in total | 1 MiB/s, 4 MiB/s | `relay_rate_per_neighbour`, `relay_rate_total` |
| Gateway budget (mesh ↔ internet) | 2 MiB/s | `gateway_rate` |
| Internet relay budget (internet ↔ internet) | 2 MiB/s | `internet_relay_rate` |
| Clients of an internet relay | 256, forgotten 3 min after last asking | `max_relay_clients`, `RELAY_CLIENT_TTL` |
| Relays a client asks | 2 (at most 3), again every 60 s | `MeshOptions::relays`, `RELAY_REFRESH` |
| Gateways named in a record | 2 (1–3) | `gateways` |
| Records a gateway publishes | 1,024 origins, one per origin per 10 s | `max_records`, `RECORD_MIN_GAP` |
| Record lifetime | 30 min | `REACH_LIFETIME` |
| Record republished | every 10 min through gateways, every 5 min by its owner | `REACH_REFRESH`, `records::REPUBLISH` |
| Looked-up record trusted, then used while looked up again | 60 s, 60 s | `REACH_TTL`, `REACH_STALE` |
| Internet hops open at once | 256 | `max_internet_hops` |
| Idle internet hop hung up | after 60 s | `INTERNET_IDLE` |
| Back-off after a failed internet dial | 2 s, doubling to 60 s | `DIAL_BACKOFF_MIN`, `DIAL_BACKOFF_MAX` |
| Frames parked for a lookup or a dial | 32 per destination, 256 destinations, 8 s | `PENDING_FRAMES`, `PENDING_KEYS`, `PENDING_TIMEOUT` |
| Distrust of a lying neighbour | 10 min, 256 remembered | `DISTRUST`, `DISTRUST_MAX` |
| Suspicion of a next hop | 2 min, 1,024 destinations, 4 suspects each | `SUSPECT_FOR`, `FEEDBACK_MAX`, `SUSPECTS_PER_DST` |

## Measurements

[TESTING.md](TESTING.md), [SIMULATION.md](SIMULATION.md) and
[BENCHMARKS.md](BENCHMARKS.md) have the methods and the full results. The
figures here are the ones the design decisions rest on.

### What the tests cover

- The router on a virtual clock (`mesh/core/tests.rs`):
  - time for every node to learn a route after a link appears;
  - time for a dead route to stop being used;
  - loops observed during convergence, which must be 0;
  - announcements per node per second against mesh size, with and without
    fisheye and flood reduction;
  - gateway choice by total cost, and no open proxy;
  - internet relays: clients only, a bounded number of them, a budget of
    their own, none on a metered uplink;
  - lying neighbours and end-to-end feedback.
- Records (unit tests in `mesh/directory.rs` and `mesh/records.rs`): forged
  records are refused, the newest wins, and a device's own record carries
  what its role says.
- Real nodes over QUIC (`tests/mesh.rs`, `tests/global.rs`,
  `tests/relay.rs` in `crates/mycel-net`):
  - failover between open paths;
  - BLE → gateway → internet → gateway → BLE sync, and a call along the
    same route (`crates/mycel-call/tests/calls.rs`);
  - two gateways aggregated, with failover;
  - relay budgets;
  - two devices behind routers syncing through an internet relay, a relay
    learnt from a contact's record, and two relays as two paths;
  - a data mule across partitions.
- Store-and-forward on a virtual clock (`mesh/dtn/tests.rs`):
  - a partial route with custody;
  - the gradient against spray on delivery time;
  - mailboxes;
  - receipts.

### Convergence and loops

In the virtual-time simulator, with a 500 ms period and 5 ms per hop:

- routes across a new link are learnt in 0.4 s at 2 hops and 1.4 s up to
  8 hops;
- a dead route is unused 25 ms after the link drops (retraction);
- a cut ring heals in 0.6 s (seqno request).

There are zero frame loops and zero route loops, checked at every step
through 60 link flaps in a 30-device mesh with traffic.

### Announcement overhead

In `mycel-sim flood-scaling` (Bluetooth-only phones with ~12 neighbours,
steady state), routing costs each device 3.4 kB/s at 2,000 devices, 8.4% of
a BLE radio, with every pair within 8 hops routed. With the earlier
settings (a 2 s period, the full scope of 8 hops every 4th period, flood
reduction) it costs 26.8 kB/s (67%) with 85% routed. Fisheye alone cuts
traffic 4–5× ([SIMULATION.md](SIMULATION.md)).

In `global-scale` (2,002 devices in neighbourhoods of 80), routing costs
467 B/s per device, down from 3,768 with the earlier settings.

### Saturated hops

In `control_traffic_crosses_a_saturated_hop`, at 400 kB/s, a small exchange
across a saturated two-hop route takes 40–60 ms (median) instead of
~560 ms, and the radio queue holds 20–40 ms instead of 180 ms. At 20 kB/s
it takes ~400 ms instead of 650–830 ms (once 6.6 s), for ~5% of the bulk
throughput.

Two routes carry 1.84–1.97× one route
(`two_routes_aggregate_and_fail_over`, 20 runs interleaved with the build
without queue management, which spread 1.79–2.19×).

### Black holes

In `adversarial` at full size (300 phones):

- 15 black holes that relay every origin at no cost took delivery to 82%.
  With distrust it is 100%.
- 15 liars that claim plausible values, and drop bundles too, took delivery
  to 76%. With end-to-end feedback and the split of bundles on a doubted
  route it is 94%.

Both are in [SIMULATION.md](SIMULATION.md), section 4, which also records
that the second result varies with the seed.

With real nodes (`tests/mesh.rs`), a relay that keeps announcing a
destination and drops everything to and from it is routed around in 6.6 s.
Two hops at 20 kB/s with 30 ms of latency and queue drops suspect nothing.

### Gateway routes

Over QUIC, in process:

- A Bluetooth-only device three BLE hops from its gateway syncs with one
  behind another gateway. The first sync took 0.58 s. A test-tone call
  along that route had 84 ms RTT and 0% loss.
- Two gateways give 2.0× one path's throughput. When one is lost, the
  longest pause on the other is 0.8–2.6 s: data in flight leaves a hole in
  the stream until the dead path's loss detection gives up.

Costing an unmeasured gateway hop like its measured neighbours, not at a
flat 100 ms, took the optimality p95 of warm messages in `global-scale`
from 5.14× to 2.65× ([SIMULATION.md](SIMULATION.md), section 4).

### Carried bundles

Spraying 4 copies, then a single copy following the gradient toward the
internet, gets the first copy to the internet in 28 min (mean of 40 traces,
4 clusters in a chain). The same 4 copies with no gradient (Spray-and-Wait)
don't get there within 12 h. A real data mule delivered 1 s after meeting
the destination.

[BENCHMARKS.md](BENCHMARKS.md) compares Mycel's store-and-forward with The
ONE's routers on real contact traces.

## Survey of prior work

The design was chosen against the protocols below. The tables give the
verdict on each; the subsections give the reasons.

### Local routing protocols

These route inside one radio mesh.

| Protocol | Kind | Verdict | Where it shows in Mycel |
|---|---|---|---|
| B.A.T.M.A.N. IV | proactive distance vector | idea reused | [Announcements](#announcements) |
| B.A.T.M.A.N. V | the same, with a throughput metric | idea reused | [Cost](#cost) |
| Babel (RFC 8966) | loop-free distance vector | ideas reused | [Feasibility condition](#feasibility-condition), [Retractions and seqno requests](#retractions-and-seqno-requests) |
| OLSRv2 (RFC 7181) | link state | tried in reduced form, now off | [Flooding over unicast hops](#flooding-over-unicast-hops) |
| AODV (RFC 3561), DSR (RFC 4728) | reactive | rejected as the primary scheme | seqno requests, record lookups |
| Fisheye state routing | scoped updates | idea reused | [Fisheye scope](#fisheye-scope) |

#### B.A.T.M.A.N. IV

Each node floods an originator message (OGM) with a sequence number.
Neighbours rebroadcast the best copy once, and each node keeps only the
best next hop per originator, ranked by TQ, a metric based on packet loss.

There is no topology database, the state is tiny, the mesh heals itself,
and it is proven in Freifunk meshes. Against it: flooding costs O(N) per
node per period, TQ ignores throughput, loops are possible transiently
(bounded by seqno windows), and the implementation is kernel C code.

Mycel reuses the idea as its base design: signed OGMs, one rebroadcast per
seqno, best-next-hop state. The code is rejected.

#### B.A.T.M.A.N. V

Version V separates neighbour discovery (ELP) from OGMv2 and uses
throughput as its metric. The flooding scales as in version IV. Mycel
reuses the throughput-aware metric: a hop's cost is its measured RTT plus a
throughput term.

#### Babel (RFC 8966)

Babel is a distance vector with per-source seqnos and the feasibility
condition: a route is usable only if its seqno is newer, or its seqno is
the same and its metric is below the feasibility distance. It has triggered
updates, retractions (metric ∞), and seqno requests to recover from
starvation.

It is loop-free at all times, even during convergence, and not only by TTL.
It reacts fast to link loss through retractions, and it was designed for
mixed wired and wireless networks. It is unauthenticated by default
(RFC 8967 adds a MAC), and the reference implementation is in C.

Mycel reuses the feasibility condition, retractions, triggered updates and
seqno requests. The code is rejected.

#### OLSRv2 (RFC 7181)

OLSRv2 is link-state. HELLOs give each node its 2-hop neighbourhood.
Multipoint relays (MPRs) are the minimal set of neighbours covering all
2-hop neighbours, and only MPRs forward floods. Topology control messages
give every node the full graph.

MPRs cut flooding drastically in dense networks. But every node holds the
full topology, so memory and CPU grow with N², which is heavy for phones,
and HELLOs carry neighbour lists, a cost in privacy and size.

Mycel tried the idea in reduced form, flood reduction without 2-hop state.
It is now off, since over unicast hops it leaves devices out. Full
link-state is rejected.

#### AODV (RFC 3561) and DSR (RFC 4728)

Both are reactive: a node floods a route request when it needs a route, and
the reply sets up state. There is no overhead when idle. But the first
packet waits for a full flood, there is a flood per destination, and routes
break silently under mobility. Chat presence wants routes ready.

Both are rejected as the primary scheme. The on-demand idea survives as
seqno requests and global record lookups.

#### Fisheye state routing

Update frequency falls with distance: near nodes are known accurately and
far nodes coarsely, and packets get more precise routes as they approach.
That cuts overhead roughly from O(N) to O(near) per period, at the price of
staler far routes. Mycel reuses the idea as the announcement scope.

### Overlays and community meshes

| System | Kind | Verdict | Where it shows in Mycel |
|---|---|---|---|
| Yggdrasil | spanning-tree overlay | idea reused, code rejected | [Reachability records](#reachability-records) |
| cjdns | DHT overlay | rejected | |
| Reticulum | announce-based transport | ideas reused, code rejected | [Budgets](#budgets) |
| BitChat | BLE flooding | ideas reused | [Store-and-forward](#store-and-forward), [Gateways](#gateways) |
| Meshtastic | LoRa managed flooding | ideas reused, broker rejected | [Announcements](#announcements) |
| Briar / Bramble | sync between contacts | idea reused | [Mailboxes and receipts](#mailboxes-and-receipts) |
| libp2p | peer-to-peer stack | ideas reused, code rejected | [Budgets](#budgets) |

#### Yggdrasil

A spanning tree gives each node tree coordinates, a DHT maps keys to
coordinates, and routing is greedy on the tree. It is an encrypted IPv6
overlay. It scales to large networks without global flooding, and keys are
addresses.

Against it: path stretch, dependence on the root, and tree instability
under mobile churn. It is written in Go and based on TUN: it is its own
transport. Mycel reuses key-based lookup in place of global flooding. The
code is rejected, by constraints 1 and 2.

#### cjdns

cjdns is a Kademlia-style DHT over key distance with source-routed labels,
encrypted. It pioneered key = address. It is complex, slow to converge, has
its own cryptography, is written in C, and sees little activity. It is
rejected.

#### Reticulum

Destinations are key hashes. Announces propagate path information and are
rate-limited; transport nodes keep path tables and forward. It works down
to LoRa and serial links at tiny bitrates, and is best-in-class for very
low-bandwidth links. Rust ports exist (`reticulum-rs` 0.9.x in LXMF-rs, and
Beechat's).

It has its own transport, cryptography and identities, and is not QUIC. The
Rust ports say they are not drop-in compatible with Python Reticulum yet.
Mycel reuses announce rate limiting and relays as "transport nodes". The
code is rejected, by constraints 1 and 2.

#### BitChat

BitChat is a BLE mesh. Every message is flooded with TTL 7, a
store-and-forward cache serves offline peers, Nostr relays bridge to the
internet (geohash channels), and Noise gives end-to-end encryption. It
needs zero setup and works in crowds.

Flooding every message doesn't scale past a crowd, and the internet bridge
is a public relay network, so metadata goes to third parties. Mycel reuses
TTL scoping, store-and-forward and an internet bridge. It routes data
instead of flooding it, and its bridge is any Mycel device with the
internet.

#### Meshtastic

Meshtastic does managed flooding over LoRa: a rebroadcast is delayed by SNR
(far nodes first) and cancelled if a neighbour was heard rebroadcasting.
The hop limit is 3–7, and MQTT gateways reach the internet. Its flood
suppression works on real radios. The internet side depends on a central
MQTT broker.

Mycel reuses the jittered rebroadcast. Suppression was tried and is turned
off over unicast hops. The central broker is rejected: gateways publish to
a DHT instead.

#### Briar / Bramble

Briar syncs between contacts over Tor, Bluetooth and Wi-Fi. A mailbox, a
spare device, holds messages for a user who is offline. The security model
is sound, and the mailbox concept is useful. It has no multi-hop routing
through strangers. Mycel reuses the mailbox, placed at the destination's
gateways.

#### libp2p

libp2p has Kademlia for peer routing, circuit relay v2 (reservations,
limited relayed bandwidth), gossipsub and AutoNAT, with a mature Rust
implementation. The components are proven. But it duplicates Iroh
(transport, identity, relays, NAT traversal) and would be a second stack in
the app.

Mycel reuses relay budgets and reservations, as its gateway budgets; an
internet relay's clients and its budget follow the same pattern. The code
is rejected.

### Iroh components

| Component | Verdict | Use in Mycel |
|---|---|---|
| QUIC (noq) with multipath and custom transports | adopted | every link, mesh route and gateway route is a QUIC path, aggregated and failed over by the path selector |
| Relay servers (n0's or self-hosted) and hole punching | adopted, optional | devices with the internet reach each other, and gateways, as usual |
| pkarr records (signed DNS packets) and n0's DNS server | adopted; the server is optional | reachability records use the same format, so any pkarr resolver can read them |
| Mainline DHT (`iroh-mainline-address-lookup` 0.6, built on `n0-mainline`) | adopted, through `n0-mainline` | records are published and resolved there |
| iroh-gossip (HyParView membership, PlumTree broadcast trees) | not used for routing | it broadcasts within a topic swarm; route tables need scoped, per-neighbour state |
| iroh-blobs | evaluated, not used | different hash ids, no multi-source ranges |

Iroh's DHT lookup crate only publishes the endpoint's own record. A gateway
publishes someone else's record, already signed, which is a few lines on
top of `n0-mainline`. So Mycel uses `n0-mainline` directly, behind the
`dht` feature of `mycel-net`.

### Delay-tolerant networking

| Work | Verdict | Where it shows in Mycel |
|---|---|---|
| Bundle Protocol v7 (RFC 9171) | ideas reused, code rejected | [Store-and-forward](#store-and-forward) |
| PRoPHET (RFC 6693) | adopted | [From live route to stored bundle](#from-live-route-to-stored-bundle) |
| Spray-and-Wait (Spyropoulos et al., 2005) | adopted, steered | [From live route to stored bundle](#from-live-route-to-stored-bundle) |
| MaxProp (Burgess et al., 2006) | idea reused | [Mailboxes and receipts](#mailboxes-and-receipts) |
| RAPID (Balasubramanian et al., 2007) | rejected | |

#### Bundle Protocol v7 (RFC 9171)

BPv7 defines bundles with a lifetime, source and destination endpoint ids,
and status reports. Custody transfer was split out of BPv7 into separate
work. The Rust crates are `bp7` 0.9 (CBOR encoding) and `dtn7-rs` 0.18 (a
daemon with TCP and HTTP convergence layers).

Mycel reuses the lifetime and hop-by-hop custody, and status reports become
its signed delivery receipts. The code is rejected. `dtn7` is a daemon with
its own convergence layers and routing, not an embeddable core. BPSec would
duplicate Mycel's envelope signatures and encryption: the payloads are
already signed, encrypted and content-addressed Mycel envelopes.

#### PRoPHET (RFC 6693)

PRoPHET keeps a delivery predictability P(a, b) that is raised on each
encounter, aged over time, and transitive through intermediaries. Bundles
are forwarded to nodes with a higher P. Mycel adopts it. The virtual
destination "the internet" lets copies climb toward connectivity.

#### Spray-and-Wait (Spyropoulos et al., 2005)

L copies are sprayed in binary fashion, then each holder waits for direct
delivery. Mycel adopts it, steered. The copies are sprayed first, each to
the likeliest neighbour without one. Then a single copy follows the
gradient toward the internet, as in Spray-and-Focus (the same authors,
2007). L depends on the bundle's size.

#### MaxProp (Burgess et al., 2006)

MaxProp ranks bundles by path likelihood, and floods acknowledgements that
clear buffers. Mycel reuses the second idea: signed receipts flood among
carriers and free their copies.

#### RAPID (Balasubramanian et al., 2007)

RAPID treats replication as utility optimisation over a metadata channel.
It is rejected: heavy metadata for marginal gains at Mycel's scale.

## Limitations and open questions

Mycel is experimental and has had no external audit. These limits apply to
routing in particular.

- The figures in this document come from simulation and from tests over
  emulated links, not from devices in the field. Relays among devices, and
  running without n0's servers, are tested between processes on one
  computer with a local test DHT, not across real routers or on the public
  DHT.
- Devices need clocks within 10 minutes of each other
  ([Sequence numbers](#sequence-numbers)).
- Hops and cost in an announcement are unsigned. A plausible lie about them
  is found only by [end-to-end feedback](#end-to-end-feedback), after
  traffic was lost to it.
- A device finds internet relays only among the devices it knows and the
  relays those name. If none of them can be dialled from the internet, and
  no relay server is connected, the device can't be reached from the
  internet.
- A metered uplink is recognised by the name of the network interface. A
  phone's hotspot or a tethered phone looks like any Wi-Fi or Ethernet and
  isn't recognised; `MYCEL_METERED` says so instead.
- Relays, gateways and carriers see keys, sizes and timing, and can drop
  traffic. [TRUST.md](TRUST.md), sections 8b and 8c, says what each can and
  cannot do.

These questions are open.

- Signed route attestations would stop a plausible lie itself. Each hop
  would sign the origin, the seqno, the hops and cost it advertises, and
  the neighbour it sends to, so a relay couldn't claim to be nearer than
  the signed chain it received (the idea of SEAD and Ariadne, with Mycel's
  Ed25519 keys). That changes the announcement format and costs a signature
  per hop, so it waits for the next protocol version ([TRUST.md](TRUST.md),
  section 8b).
- End-to-end feedback may not be enough against plausible liars. The 94%
  under [Black holes](#black-holes) is one seed. With other seeds the same
  defence delivers less: where most of a destination's neighbourhood sits
  next to a liar, every alternative route leads to one too.
- A slow mesh route never gives way to gateways. The core keeps traffic on
  a mesh route by design, even when the internet through the destination's
  gateways would be faster. Whether to trade that for traffic on the
  gateways' budgets is undecided.
- Replicas can exceed the number of copies a bundle started with. A
  hand-off whose acknowledgement is lost when a contact ends leaves copies
  on both sides.

The last three are open findings in [SIMULATION.md](SIMULATION.md),
section 4, with the evidence and how to reproduce it.
