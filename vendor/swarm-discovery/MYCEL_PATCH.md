# Mycel's patch to swarm-discovery 0.6.3

iroh's mDNS address lookup uses swarm-discovery. Upstream speaks a private
subset of mDNS that standard DNS-SD (Apple's Bonjour / mDNSResponder,
Android's NSD, Avahi) can't interoperate with:

- responses carry no PTR record, so DNS-SD browsers list no instances;
- every record has TTL 0, which DNS-SD responders treat as a "goodbye" and
  delete at once;
- the receiver reads SRV/TXT only from the answer section, but a DNS-SD
  responder answering a PTR query puts them in the additional records;
- without hickory's `mdns` feature, records with the cache-flush bit (which
  DNS-SD sets on SRV/TXT/A/AAAA) parse with class 0x8001 and are dropped.

That matters for iPhones and iPads: without Apple's multicast entitlement an
app can't send its own mDNS packets, so Mycel on iOS discovers and advertises
through the system's mDNSResponder (`crates/mycel-net/src/native_mdns.rs`),
and the other platforms have to understand it.

Changes (marked `MYCEL PATCH`):

1. `Cargo.toml`: hickory-proto with the `mdns` feature.
2. `src/sender.rs`: a PTR answer for our instance, TTL 120 s on every record,
   and the cache-flush bit on the unique ones (SRV, TXT, A, AAAA).
3. `src/receiver.rs`: SRV/TXT and A/AAAA read from answers and additional
   records; an instance whose PTR has TTL 0 (a goodbye) isn't refreshed by
   the rest of that packet.

The wire format is otherwise unchanged (instance label = peer id, SRV target
`<peer id>-<port>.local.`, TXT attributes), so unpatched builds still see
patched ones and vice versa.
