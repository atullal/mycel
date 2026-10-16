//! Live calls between two real nodes (real QUIC), with test audio in place of
//! microphones and speakers: over loopback IP, over in-memory links with a
//! Bluetooth-like bandwidth limit, and with the peer-to-peer Wi-Fi link cut
//! mid-call so the call continues over Bluetooth.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use mycel_call::audio::{AudioDiag, AudioHandle, AudioIo, AudioPorts, TestAudio, TestSource};
use mycel_call::proto::{self, CallRef, Ctrl, call_id};
use mycel_call::{ALPN_CALL, CallEvent, CallPhase, EndReason};
use mycel_crypto::Hash32;
use mycel_net::MeshOptions;
use mycel_net::link::{MemNet, PathKind};

/// Alice calls Bob and Bob answers; returns the call id once both are talking.
pub async fn connect_call(alice: &Device, bob: &Device, space: Hash32) -> String {
    let out = alice.calls.start(space).await.unwrap();
    assert_eq!(out.state, CallPhase::Connecting, "{out:?}");
    let ring = eventually("bob's device rings", 15, || bob.incoming().filter(|r| r.id == out.id)).await;
    assert_eq!(ring.conversation, space.to_string());
    assert_eq!(ring.peer, alice.hex());
    eventually("alice hears it ringing", 5, || (alice.call(&out.id)?.state == CallPhase::Ringing).then_some(())).await;
    bob.calls.accept(&ring.id).await.unwrap();
    eventually("both active", 10, || {
        let a = alice.call(&out.id)?;
        let b = bob.call(&out.id)?;
        (a.state == CallPhase::Active && b.state == CallPhase::Active).then_some(())
    })
    .await;
    out.id
}

/// Mean delay from each tone burst Alice "says" to its onset in what Bob hears.
fn burst_latency(alice: &Device, bob: &Device, period: f64) -> Option<f64> {
    let src = alice.audio.source_start()?;
    let rec = bob.audio.recording();
    let rec = rec.lock();
    let start = rec.start?;
    let offset = start.saturating_duration_since(src).as_secs_f64();
    let delays: Vec<f64> = TestAudio::onsets(&rec.samples)
        .into_iter()
        .map(|t| {
            let t = t + offset;
            t - (t / period).floor() * period
        })
        .collect();
    if delays.len() < 3 {
        return None;
    }
    let tail = &delays[1..];
    Some(tail.iter().sum::<f64>() / tail.len() as f64)
}

#[tokio::test(flavor = "multi_thread")]
async fn call_carries_audio_both_ways_and_hangs_up() {
    let alice = device("alice", TestSource::Bursts { hz: 1000.0, on_ms: 100, period_ms: 500 }, true, &[]).await;
    let bob = device("bob", sine(440.0), true, &[]).await;
    alice.node.add_peer_addr(bob.node.addr());
    bob.node.add_peer_addr(alice.node.addr());
    let space = shared_space(&alice, &bob).await;

    let t = Instant::now();
    let id = connect_call(&alice, &bob, space).await;
    eprintln!("ring → answer → active in {:?}", t.elapsed());
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Alice hears Bob's 440 Hz; Bob hears Alice's 1 kHz bursts.
    let f = alice.heard(1.0).expect("alice hears something");
    assert!((f - 440.0).abs() < 8.0, "alice heard {f} Hz");
    assert!(bob.heard_power(2.0, 1000.0) > 50.0 * bob.heard_power(2.0, 440.0), "bob hears 1 kHz, not his own tone");
    let latency = burst_latency(&alice, &bob, 0.5).expect("bursts detected");
    let a = alice.call(&id).unwrap();
    let b = bob.call(&id).unwrap();
    eprintln!(
        "mouth-to-ear latency {:.0} ms (estimate {} ms); bitrate {} bps; path {:?}; rtt {} ms; jitter buffer {} ms; sent {} received {} lost {}",
        latency * 1000.0,
        b.stats.latency_ms,
        a.bitrate,
        a.path,
        a.stats.rtt_ms,
        b.stats.buffer_ms,
        a.stats.frames_sent,
        b.stats.frames_received,
        b.stats.frames_lost,
    );
    assert!(latency < 0.200, "latency {latency:.3} s");
    assert_eq!(a.path, Some(PathKind::Network));
    assert_eq!(a.bitrate, 32_000, "fast path: full bitrate");
    assert_eq!(a.stats.transport, "datagram");
    assert!(a.stats.frames_sent > 150 && b.stats.frames_received > 150);
    assert!(b.stats.frames_lost < 10, "lost {}", b.stats.frames_lost);
    assert!(a.duration_ms >= 3_000);
    assert!(b.level > 0.0, "bob's mic meter moves");
    // alice's tone comes in 100 ms bursts: her meter moves during one
    eventually("alice's mic meter moves", 3, || (alice.call(&id)?.level > 0.0).then_some(())).await;
    assert!(a.remote_level > 0.0, "alice hears bob's steady tone on her meter");

    // mute: Bob goes silent for Alice, and Alice sees it
    bob.calls.set_muted(&id, true).unwrap();
    eventually("alice sees bob muted", 5, || alice.call(&id)?.remote_muted.then_some(())).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(alice.heard(0.3).is_none(), "muted mic sends silence");
    bob.calls.set_muted(&id, false).unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(alice.heard(0.3).is_some());

    // Bob hangs up
    bob.calls.end(&id).unwrap();
    let a = eventually("alice sees the hang-up", 5, || alice.call(&id).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(a.end_reason, Some(EndReason::RemoteHungUp));
    assert_eq!(bob.call(&id).unwrap().end_reason, Some(EndReason::HungUp));
    assert!(alice.live().is_empty() && bob.live().is_empty());

    // and a second call, hung up by the caller this time
    let id2 = connect_call(&alice, &bob, space).await;
    assert_ne!(id, id2, "every call gets a fresh id");
    alice.calls.end(&id2).unwrap();
    let b = eventually("bob sees the hang-up", 5, || bob.call(&id2).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(b.end_reason, Some(EndReason::RemoteHungUp));
}

#[tokio::test(flavor = "multi_thread")]
async fn decline_timeout_busy_and_strangers() {
    let alice = device("alice", sine(440.0), true, &[]).await;
    let bob = device("bob", sine(660.0), true, &[]).await;
    let carol = device("carol", sine(550.0), true, &[]).await;
    for a in [&alice, &bob, &carol] {
        for b in [&alice, &bob, &carol] {
            if a.node.id() != b.node.id() {
                a.node.add_peer_addr(b.node.addr());
            }
        }
    }
    let space = shared_space(&alice, &bob).await;

    // Bob declines
    let out = alice.calls.start(space).await.unwrap();
    let ring = eventually("bob rings", 10, || bob.incoming()).await;
    bob.calls.decline(&ring.id).unwrap();
    let a = eventually("declined", 5, || alice.call(&out.id).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(a.end_reason, Some(EndReason::RemoteDeclined));
    assert_eq!(bob.call(&ring.id).unwrap().end_reason, Some(EndReason::Declined));

    // nobody answers
    alice.calls.set_ring_timeout(Duration::from_secs(2));
    bob.calls.set_ring_timeout(Duration::from_secs(2));
    let out = alice.calls.start(space).await.unwrap();
    let a = eventually("no answer", 10, || alice.call(&out.id).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(a.end_reason, Some(EndReason::NoAnswer));
    let b = eventually("missed", 10, || bob.call(&out.id).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(b.end_reason, Some(EndReason::Missed));
    alice.calls.set_ring_timeout(Duration::from_secs(45));
    bob.calls.set_ring_timeout(Duration::from_secs(45));

    // Carol isn't in Alice and Bob's conversation: she can't place a call
    // there, and if she rings Alice about it directly, Alice's device refuses.
    assert!(carol.calls.start(space).await.is_err());
    for bound_to in [carol.node.id(), bob.node.id()] {
        let conn = carol.node.connect(alice.node.id(), ALPN_CALL).await.unwrap();
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        let nonce = [7u8; 16];
        // a valid id for Carol, or Bob's id replayed by Carol: both refused
        let call = CallRef { space, initiator: bound_to, nonce, call: call_id(&space, &bound_to, &nonce) };
        let ring = Ctrl::Ring { version: proto::VERSION, call, group: false };
        proto::send(&mut tx, &ring).await.unwrap();
        assert_eq!(proto::recv(&mut rx).await.unwrap(), Some(Ctrl::Denied));
        conn.close(0u32.into(), b"");
    }
    assert!(
        alice.live().is_empty() && alice.incoming().is_none_or(|c| c.peer != carol.hex()),
        "nothing rang for carol"
    );

    // Busy: Alice is talking to Bob; Carol (in her own conversation with Alice) calls
    let space2 = shared_space(&carol, &alice).await;
    let id = connect_call(&alice, &bob, space).await;
    let busy = carol.calls.start(space2).await.unwrap();
    let c = eventually("busy", 10, || carol.call(&busy.id).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(c.end_reason, Some(EndReason::Busy));
    assert_eq!(alice.call(&id).unwrap().state, CallPhase::Active, "the first call goes on");
    alice.calls.end(&id).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn both_call_at_once_become_one_call() {
    let alice = device("alice", sine(440.0), true, &[]).await;
    let bob = device("bob", sine(660.0), true, &[]).await;
    alice.node.add_peer_addr(bob.node.addr());
    bob.node.add_peer_addr(alice.node.addr());
    let space = shared_space(&alice, &bob).await;

    let (a, b) = tokio::join!(alice.calls.start(space), bob.calls.start(space));
    let (a, b) = (a.unwrap(), b.unwrap());
    let winner = eventually("one active call on both sides", 15, || {
        let al = alice.live();
        let bl = bob.live();
        match (al.as_slice(), bl.as_slice()) {
            ([x], [y]) if x.id == y.id && x.state == CallPhase::Active && y.state == CallPhase::Active => {
                Some(x.id.clone())
            }
            _ => None,
        }
    })
    .await;
    assert!(winner == a.id || winner == b.id);
    // Two calls were placed: the losing one ended as replaced, without
    // ringing anyone. (Or one's ring got there before the other placed a
    // call, and pressing call answered it: one call all along.)
    if a.id != b.id {
        let loser = if winner == a.id { &b.id } else { &a.id };
        let lost = alice.call(loser).or_else(|| bob.call(loser)).unwrap();
        assert_eq!(lost.end_reason, Some(EndReason::Replaced));
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!((alice.heard(1.0).unwrap() - 660.0).abs() < 8.0);
    assert!((bob.heard(1.0).unwrap() - 440.0).abs() < 8.0);
    alice.calls.end(&winner).unwrap();
    eventually("both hung up", 5, || (alice.live().is_empty() && bob.live().is_empty()).then_some(())).await;

    // Nothing left over from the glare answers the next call by itself (a
    // lost glare has the higher key expect the lower key's call): the
    // lower key calls again, and the other device rings.
    let (lo, hi) = if alice.node.id() < bob.node.id() { (&alice, &bob) } else { (&bob, &alice) };
    let again = lo.calls.start(space).await.unwrap();
    let ring = eventually("it rings", 10, || hi.incoming().filter(|r| r.id == again.id)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(hi.call(&ring.id).unwrap().state, CallPhase::Ringing, "rings, isn't answered by itself");
    lo.calls.end(&again.id).unwrap();
}

/// Audio whose microphone check (`prepare`, which runs before a call is
/// placed) takes a while: a permission prompt, or a loaded machine slow to
/// run the check's thread. It lasts until `until()` (at most 5 s).
struct SlowPrepare {
    inner: Arc<TestAudio>,
    until: Box<dyn Fn() -> bool + Send + Sync>,
}

impl AudioIo for SlowPrepare {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn prepare(&self) -> anyhow::Result<()> {
        let end = Instant::now() + Duration::from_secs(5);
        while !(self.until)() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.inner.prepare()
    }
    fn open(&self, ports: AudioPorts) -> anyhow::Result<AudioHandle> {
        self.inner.open(ports)
    }
    fn diagnostics(&self) -> AudioDiag {
        self.inner.diagnostics()
    }
}

/// Both press call at once, but one of them is slow to place the call: the
/// other's ring gets there while it is still checking the microphone (on a
/// loaded machine a few milliseconds' lag does it). `lower_first`: the
/// faster one has the lower key (its call is the one that wins a glare),
/// else the higher.
async fn glare_one_side_slow(lower_first: bool) {
    let alice = device("alice", sine(440.0), true, &[]).await;
    let bob = device("bob", sine(660.0), true, &[]).await;
    alice.node.add_peer_addr(bob.node.addr());
    bob.node.add_peer_addr(alice.node.addr());
    let space = shared_space(&alice, &bob).await;
    let (fast, slow) = if (alice.node.id() < bob.node.id()) == lower_first { (&alice, &bob) } else { (&bob, &alice) };
    let events = slow.events.clone();
    let rung = move || events.lock().iter().any(|e| matches!(e, CallEvent::Incoming(_)));
    slow.calls.set_audio(Arc::new(SlowPrepare { inner: slow.audio.clone(), until: Box::new(rung) }));

    let (f, s) = tokio::join!(fast.calls.start(space), slow.calls.start(space));
    let (f, s) = (f.unwrap(), s.unwrap());
    let winner =
        eventually("one active call on both sides", 15, || match (fast.live().as_slice(), slow.live().as_slice()) {
            ([x], [y]) if x.id == y.id && x.state == CallPhase::Active && y.state == CallPhase::Active => {
                Some(x.id.clone())
            }
            _ => None,
        })
        .await;
    for d in [fast, slow] {
        let other: Vec<_> = d.status().into_iter().filter(|c| c.id != winner).map(|c| (c.id, c.end_reason)).collect();
        assert!(other.is_empty(), "no second call, missed or replaced: {other:?}");
    }
    // pressing call answered the call that was already ringing
    assert_eq!((winner.as_str(), s.id.as_str()), (f.id.as_str(), f.id.as_str()));
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!((alice.heard(1.0).unwrap() - 660.0).abs() < 8.0);
    assert!((bob.heard(1.0).unwrap() - 440.0).abs() < 8.0);
    fast.calls.end(&winner).unwrap();
}

/// The lower key's ring comes while the higher key is still placing its
/// call. This used to hang: the higher key's call went out anyway and lost
/// the glare, while the winning call just rang on its device, unanswered
/// (the call glare flake on Windows CI).
#[tokio::test(flavor = "multi_thread")]
async fn both_call_at_once_higher_key_slow_to_place_it() {
    glare_one_side_slow(true).await;
}

/// The higher key's ring comes while the lower key is still placing its
/// call. This used to place a second call anyway: one call in the end, but
/// the first one rang and was then shown as missed.
#[tokio::test(flavor = "multi_thread")]
async fn both_call_at_once_lower_key_slow_to_place_it() {
    glare_one_side_slow(false).await;
}

/// No IP at all: the call starts on peer-to-peer Wi-Fi, then that link is
/// cut and the same call continues over a slow Bluetooth-like link, at a
/// lower bitrate.
#[tokio::test(flavor = "multi_thread")]
async fn call_moves_from_peer_wifi_to_bluetooth() {
    let wifi = MemNet::new(3, PathKind::PeerWifi);
    let bt = MemNet::new(3, PathKind::Bluetooth);
    // Bluetooth LE: ~20 KB/s, 20 ms each way
    bt.set_rate_limit(Some(20_000));
    bt.set_latency(Duration::from_millis(20));
    let alice = device("alice", sine(440.0), false, &[&wifi, &bt]).await;
    let bob = device("bob", sine(660.0), false, &[&wifi, &bt]).await;
    eventually("links up", 15, || {
        alice.node.peers().get(&bob.node.id()).is_some_and(|p| p.links.len() == 2).then_some(())
    })
    .await;
    let space = shared_space(&alice, &bob).await;

    let id = connect_call(&alice, &bob, space).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let a = alice.call(&id).unwrap();
    assert_eq!(a.path, Some(PathKind::PeerWifi), "starts on the fast link");
    assert_eq!(a.bitrate, 32_000);
    assert!((bob.heard(1.0).unwrap() - 440.0).abs() < 8.0);

    let cut = Instant::now();
    wifi.cut();
    let (a, gap) = eventually("call moves to bluetooth", 30, || {
        let a = alice.call(&id)?;
        (a.path == Some(PathKind::Bluetooth) && a.bitrate <= 12_000).then(|| (a, cut.elapsed()))
    })
    .await;
    eprintln!("alice's side moved to Bluetooth after {gap:?}, bitrate {} bps", a.bitrate);
    let b = eventually("bob's side moves to bluetooth too", 30, || {
        let b = bob.call(&id)?;
        (b.path == Some(PathKind::Bluetooth)).then_some(b)
    })
    .await;
    eprintln!("bob's side moved after {:?}, bitrate {} bps", cut.elapsed(), b.bitrate);
    let received = bob.call(&id).unwrap().stats.frames_received;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let b = bob.call(&id).unwrap();
    let a = alice.call(&id).unwrap();
    assert_eq!(a.state, CallPhase::Active, "same call, still going");
    assert_eq!(b.path, Some(PathKind::Bluetooth));
    let per_sec = (b.stats.frames_received - received) as f64 / 4.0;
    eprintln!(
        "over Bluetooth: {per_sec:.0} frames/s, rtt {} ms, buffer {} ms, latency ≈{} ms, loss {:.1}%",
        b.stats.rtt_ms, b.stats.buffer_ms, b.stats.latency_ms, a.stats.loss_pct
    );
    assert!(per_sec > 40.0, "audio keeps flowing over Bluetooth ({per_sec}/s)");
    assert!((bob.heard(1.0).unwrap() - 440.0).abs() < 8.0, "bob still hears alice");
    assert!((alice.heard(1.0).unwrap() - 660.0).abs() < 8.0, "alice still hears bob");
    alice.calls.end(&id).unwrap();
}

/// When the Wi-Fi path dies mid-call, each leg reports Bluetooth within about
/// a second (the call checks its path every second while talking), and keeps
/// reporting it: QUIC declares the silent path dead after two probe timeouts
/// and path selection drops it at once (vendor/noq-proto/MYCEL_PATCH.md §3).
/// The leg's path picks the call's bitrate: before, it reported the dead
/// Wi-Fi path for 3-5 s while the audio already went over Bluetooth.
#[tokio::test(flavor = "multi_thread")]
async fn call_leg_reports_bluetooth_promptly_after_wifi_dies() {
    let wifi = MemNet::new(4, PathKind::PeerWifi);
    let bt = MemNet::new(4, PathKind::Bluetooth);
    bt.set_rate_limit(Some(20_000));
    bt.set_latency(Duration::from_millis(20));
    let alice = device("alice", sine(440.0), false, &[&wifi, &bt]).await;
    let bob = device("bob", sine(660.0), false, &[&wifi, &bt]).await;
    eventually("links up", 15, || {
        alice.node.peers().get(&bob.node.id()).is_some_and(|p| p.links.len() == 2).then_some(())
    })
    .await;
    let space = shared_space(&alice, &bob).await;
    let id = connect_call(&alice, &bob, space).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(alice.call(&id).unwrap().path, Some(PathKind::PeerWifi), "starts on the fast link");
    assert_eq!(bob.call(&id).unwrap().path, Some(PathKind::PeerWifi));

    let cut = Instant::now();
    wifi.cut();
    let mut moved = [None, None];
    while cut.elapsed() < Duration::from_secs(5) && moved.iter().any(Option::is_none) {
        for (i, d) in [&alice, &bob].into_iter().enumerate() {
            if moved[i].is_none() && d.call(&id).and_then(|c| c.path) == Some(PathKind::Bluetooth) {
                moved[i] = Some(cut.elapsed());
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    eprintln!("legs report Bluetooth after: alice {:?}, bob {:?}", moved[0], moved[1]);
    for (who, at) in ["alice", "bob"].into_iter().zip(moved) {
        let at = at.unwrap_or_else(|| panic!("{who}'s leg never reported Bluetooth"));
        assert!(at < Duration::from_millis(1500), "{who}'s leg reported Bluetooth {at:?} after the cut");
    }
    // ... and stays there
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(alice.call(&id).unwrap().path, Some(PathKind::Bluetooth));
        assert_eq!(bob.call(&id).unwrap().path, Some(PathKind::Bluetooth));
    }
    assert_eq!(alice.call(&id).unwrap().state, CallPhase::Active);
    alice.calls.end(&id).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn audio_falls_back_to_a_stream() {
    let alice = device("alice", sine(440.0), true, &[]).await;
    let bob = device("bob", sine(660.0), true, &[]).await;
    alice.node.add_peer_addr(bob.node.addr());
    bob.node.add_peer_addr(alice.node.addr());
    alice.calls.force_stream(true);
    bob.calls.force_stream(true);
    let space = shared_space(&alice, &bob).await;
    let id = connect_call(&alice, &bob, space).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let a = alice.call(&id).unwrap();
    assert_eq!(a.stats.transport, "stream");
    assert!((bob.heard(1.0).unwrap() - 440.0).abs() < 8.0);
    assert!((alice.heard(1.0).unwrap() - 660.0).abs() < 8.0);
    alice.calls.end(&id).unwrap();
}

/// No direct link at all: Alice and Carol are each in range of Bob only.
/// Their call runs through Bob, who isn't in the conversation and only
/// forwards ciphertext.
#[tokio::test(flavor = "multi_thread")]
async fn call_through_a_mesh_relay() {
    let ab = MemNet::new(5, PathKind::PeerWifi);
    let bc = MemNet::new(6, PathKind::PeerWifi);
    let mesh = || Some(MeshOptions { announce_every: Duration::from_millis(500), ..MeshOptions::default() });
    let alice = device_with("alice", sine(440.0), false, &[&ab], mesh()).await;
    let bob = device_with("bob", sine(550.0), false, &[&ab, &bc], mesh()).await;
    let carol = device_with("carol", sine(660.0), false, &[&bc], mesh()).await;
    for (from, to) in [(&alice, &carol), (&carol, &alice)] {
        let id = to.node.id();
        eventually("a mesh route", 20, || {
            from.node.peers().get(&id).is_some_and(|p| p.links.contains(&PathKind::Mesh)).then_some(())
        })
        .await;
    }
    let space = shared_space(&alice, &carol).await;
    let id = connect_call(&alice, &carol, space).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (a, c) = (alice.call(&id).unwrap(), carol.call(&id).unwrap());
    assert_eq!(a.path, Some(PathKind::Mesh));
    assert_eq!(c.path, Some(PathKind::Mesh));
    assert!((carol.heard(1.0).unwrap() - 440.0).abs() < 8.0, "carol hears alice");
    assert!((alice.heard(1.0).unwrap() - 660.0).abs() < 8.0, "alice hears carol");
    eprintln!(
        "through one relay: rtt {} ms, latency ≈{} ms, loss {:.1}%, bitrate {} bps",
        c.stats.rtt_ms, c.stats.latency_ms, a.stats.loss_pct, a.bitrate
    );
    let relayed = bob.node.mesh().unwrap().stats();
    assert!(relayed.frames_relayed > 100, "{relayed:?}");
    assert!(bob.node.space_ids().is_empty(), "the relay isn't in the conversation");
    assert!(bob.calls.status().is_empty(), "nor in the call");
    alice.calls.end(&id).unwrap();
}

/// Bluetooth-only in the US (two hops from its gateway), Bluetooth-only in
/// Europe: a live call across both gateways and the internet, end to end.
#[tokio::test(flavor = "multi_thread")]
async fn call_across_two_gateways_and_the_internet() {
    use mycel_net::mesh::directory::{self, Directory, MemDirectory};
    let dir = MemDirectory::new();
    let radio = |n: u64| {
        let m = MemNet::radio(n, PathKind::Bluetooth);
        m.set_rate_limit(Some(100_000));
        m.set_latency(Duration::from_millis(10));
        m
    };
    let (e1, e2, e3) = (radio(9), radio(10), radio(11));
    let mesh = |internet: bool| {
        Some(MeshOptions {
            announce_every: Duration::from_millis(500),
            internet: Some(internet),
            directory: Some(std::sync::Arc::new(dir.clone())),
            ..MeshOptions::default()
        })
    };
    let us = device_with("us", sine(440.0), false, &[&e1], mesh(false)).await;
    let _relay = device_with("relay", sine(330.0), false, &[&e1, &e2], mesh(false)).await;
    let g_us = device_with("us-gateway", sine(330.0), true, &[&e2], mesh(true)).await;
    let g_eu = device_with("eu-gateway", sine(330.0), true, &[&e3], mesh(true)).await;
    let eu = device_with("eu", sine(660.0), false, &[&e3], mesh(false)).await;
    g_us.node.add_peer_addr(g_eu.node.addr());
    g_eu.node.add_peer_addr(g_us.node.addr());
    for who in [&us, &eu] {
        let id = who.node.id();
        let mut ok = false;
        for _ in 0..200 {
            if dir.get(id).await.and_then(|b| directory::open(&b, Some(&id))).is_some() {
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ok, "a record for {id:?}");
    }
    let space = shared_space(&us, &eu).await;
    let id = connect_call(&us, &eu, space).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (a, b) = (us.call(&id).unwrap(), eu.call(&id).unwrap());
    assert_eq!(a.path, Some(PathKind::Mesh));
    assert_eq!(b.path, Some(PathKind::Mesh));
    assert!((eu.heard(1.0).unwrap() - 440.0).abs() < 8.0, "Europe hears the US");
    assert!((us.heard(1.0).unwrap() - 660.0).abs() < 8.0, "the US hears Europe");
    eprintln!(
        "US<->EU call: rtt {} ms, latency ~{} ms, loss {:.1}%, bitrate {} bps (3 BLE hops at 10 ms + 2 gateways)",
        b.stats.rtt_ms, b.stats.latency_ms, a.stats.loss_pct, a.bitrate
    );
    us.calls.end(&id).unwrap();
}
