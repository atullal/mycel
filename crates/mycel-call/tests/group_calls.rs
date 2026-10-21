//! Group calls between real nodes (real QUIC), each with its own test tone,
//! so every device can check it hears exactly the others in its mix:
//! ringing everyone, joining late, leaving without ending the call, the
//! last person ending it, outsiders refused, and a call with no IP at all.

mod common;

use std::time::{Duration, Instant};

use common::*;
use mycel_call::audio::TestSource;
use mycel_call::level::goertzel;
use mycel_call::proto::{self, CallRef, Ctrl};
use mycel_call::{ALPN_CALL, CallInfo, CallPhase, EndReason, ParticipantState};
use mycel_crypto::Hash32;
use mycel_net::link::{MemNet, PathKind};
use mycel_trust::Role;

/// A tone nobody plays: the noise floor to compare against.
const NOBODY: f32 = 1_500.0;
/// Carol's tone where only she may be heard: clear of the harmonics and
/// intermodulation products of 440 and 660 Hz up to the third order.
const CAROL: f32 = 990.0;

fn connect_all(devs: &[&Device]) {
    for a in devs {
        for b in devs {
            if a.node.id() != b.node.id() {
                a.node.add_peer_addr(b.node.addr());
            }
        }
    }
}

/// A group conversation with all of `devs` in it (the first creates it).
async fn group_space(devs: &[&Device]) -> Hash32 {
    let owner = devs[0];
    let (space, genesis) = owner.node.create_space().unwrap();
    for d in &devs[1..] {
        owner.node.with_space(&space, |r| r.add_member(d.node.keys().public(), Role::Writer)).unwrap().unwrap();
    }
    for d in &devs[1..] {
        d.node.join_space(genesis.clone()).unwrap();
        d.node.sync_with(owner.node.id(), space, true).await.unwrap();
    }
    space
}

/// Power of `hz` in what `d` heard over the last `secs`, relative to the
/// noise floor.
fn snr(d: &Device, secs: f32, hz: f32) -> f32 {
    let p = d.heard_power(secs, hz);
    let floor = d.heard_power(secs, NOBODY).max(1e-9);
    p / floor
}

fn hears(d: &Device, hz: f32) -> bool {
    snr(d, 1.5, hz) > 30.0
}

/// `d` hears each of `present` clearly, and none of `absent`. An absent tone
/// (say, their own voice) must be far weaker than the faintest present one:
/// codec artifacts of a busy mix are, a real leak isn't.
fn assert_hears(d: &Device, name: &str, present: &[f32], absent: &[f32]) {
    let faintest = present.iter().map(|hz| d.heard_power(1.5, *hz)).fold(f32::MAX, f32::min);
    let leak = |hz: f32| d.heard_power(1.5, hz) / faintest.max(1e-12);
    let ok = present.iter().all(|hz| hears(d, *hz)) && absent.iter().all(|hz| leak(*hz) < 0.05);
    if !ok {
        for c in d.live() {
            for p in &c.participants {
                eprintln!(
                    "  {name} → {} {:?} level {:.2} bitrate {} path {:?}",
                    p.name, p.state, p.level, p.bitrate, p.path
                );
            }
            eprintln!("  {name}: frames lost {} late {}", c.stats.frames_lost, c.stats.frames_late);
        }
    }
    for hz in present {
        assert!(hears(d, *hz), "{name} should hear {hz} Hz (snr {:.1})", snr(d, 1.5, *hz));
    }
    for hz in absent {
        assert!(leak(*hz) < 0.05, "{name} shouldn't hear {hz} Hz ({:.3} of the faintest voice)", leak(*hz));
    }
}

fn joined(c: &CallInfo) -> usize {
    c.participants.iter().filter(|p| p.state == ParticipantState::Joined).count()
}

/// Talking with `n` others, all of them joined.
fn talking_to(d: &Device, id: &str, n: usize) -> Option<CallInfo> {
    d.call(id).filter(|c| c.state == CallPhase::Active && joined(c) == n && c.joined_count as usize == n + 1)
}

/// Onsets (seconds from the recording's start) of a `hz` tone in a mix,
/// from its power in 10 ms windows.
fn tone_onsets(samples: &[f32], hz: f32) -> Vec<f64> {
    let win = 480;
    let power: Vec<f32> = samples.chunks(win).map(|w| goertzel(w, hz, 48_000)).collect();
    let peak = power.iter().cloned().fold(0f32, f32::max);
    let mut out = Vec::new();
    let mut on = false;
    for (k, p) in power.iter().enumerate() {
        if !on && *p > peak * 0.2 {
            on = true;
            out.push((k * win) as f64 / 48_000.0);
        } else if on && *p < peak * 0.02 {
            on = false;
        }
    }
    out
}

/// Mean delay from each of `from`'s tone bursts (every `period` s) to its
/// onset in what `to` hears, mixed with everyone else.
fn mixed_burst_latency(from: &Device, to: &Device, hz: f32, period: f64) -> Option<f64> {
    let src = from.audio.source_start()?;
    let rec = to.audio.recording();
    let rec = rec.lock();
    let offset = rec.start?.saturating_duration_since(src).as_secs_f64();
    let delays: Vec<f64> = tone_onsets(&rec.samples, hz)
        .into_iter()
        .map(|t| {
            let t = t + offset;
            t - (t / period).floor() * period
        })
        .collect();
    (delays.len() >= 3).then(|| delays[1..].iter().sum::<f64>() / (delays.len() - 1) as f64)
}

#[tokio::test(flavor = "multi_thread")]
async fn group_call_rings_everyone_late_join_and_leaves() {
    let _cpu = cpu_alone().await;
    let alice = device("alice", TestSource::Bursts { hz: 1000.0, on_ms: 100, period_ms: 500 }, true, &[]).await;
    let bob = device("bob", sine(440.0), true, &[]).await;
    let carol = device("carol", sine(660.0), true, &[]).await;
    let dave = device("dave", sine(880.0), true, &[]).await;
    connect_all(&[&alice, &bob, &carol, &dave]);
    let space = group_space(&[&alice, &bob, &carol, &dave]).await;

    // Alice calls the group: everyone else's device rings
    let t = Instant::now();
    let out = alice.calls.start(space).await.unwrap();
    assert!(out.group);
    let id = out.id.clone();
    for (d, name) in [(&bob, "bob"), (&carol, "carol"), (&dave, "dave")] {
        let ring = eventually(&format!("{name}'s device rings"), 15, || d.incoming().filter(|r| r.id == id)).await;
        assert!(ring.group);
        assert_eq!(ring.peer, alice.hex(), "{name} sees who's calling");
        assert_eq!(ring.conversation, space.to_string());
    }
    eventually("alice sees three phones ringing", 5, || {
        let c = alice.call(&id)?;
        (c.state == CallPhase::Ringing
            && c.participants.iter().filter(|p| p.state == ParticipantState::Ringing).count() == 3)
            .then_some(())
    })
    .await;

    // Bob and Carol answer, Dave declines
    bob.calls.accept(&id).await.unwrap();
    carol.calls.accept(&id).await.unwrap();
    dave.calls.decline(&id).unwrap();
    for (d, name) in [(&alice, "alice"), (&bob, "bob"), (&carol, "carol")] {
        eventually(&format!("{name} talks to both others"), 15, || talking_to(d, &id, 2)).await;
    }
    eprintln!("3-way call up {:?} after alice pressed call", t.elapsed());
    let d = eventually("dave can still join", 10, || {
        dave.call(&id).filter(|c| c.state == CallPhase::Joinable && c.joined_count == 3)
    })
    .await;
    assert_eq!(dave.live().iter().filter(|c| c.state != CallPhase::Joinable).count(), 0);
    assert!(d.participants.iter().all(|p| p.state == ParticipantState::Joined), "{:?}", d.participants);
    let a = alice.call(&id).unwrap();
    let dave_row = a.participants.iter().find(|p| p.id == dave.hex()).unwrap();
    assert_eq!(dave_row.state, ParticipantState::Declined);

    // everyone hears both others, mixed, and not themselves
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_hears(&alice, "alice", &[440.0, 660.0], &[880.0, 1000.0]);
    assert_hears(&bob, "bob", &[1000.0, 660.0], &[880.0, 440.0]);
    assert_hears(&carol, "carol", &[1000.0, 440.0], &[880.0, 660.0]);
    let b = bob.call(&id).unwrap();
    let to_bob = mixed_burst_latency(&alice, &bob, 1000.0, 0.5).expect("bursts heard by bob");
    let to_carol = mixed_burst_latency(&alice, &carol, 1000.0, 0.5).expect("bursts heard by carol");
    eprintln!(
        "3-way: alice's voice reaches bob in {:.0} ms and carol in {:.0} ms (mixed with the third person); \
         bob's paths {:?}, bitrates {:?}, lost {}",
        to_bob * 1000.0,
        to_carol * 1000.0,
        b.participants.iter().map(|p| p.path).collect::<Vec<_>>(),
        b.participants.iter().map(|p| p.bitrate).collect::<Vec<_>>(),
        b.stats.frames_lost,
    );
    assert!(to_bob < 0.2 && to_carol < 0.2, "latency {to_bob:.3} / {to_carol:.3} s");
    assert!(
        b.participants.iter().all(|p| p.path == Some(PathKind::Network) && p.bitrate == 32_000),
        "{:#?}",
        b.participants
    );
    let speaking = eventually("carol's steady tone shows as speaking", 3, || {
        let b = bob.call(&id)?;
        b.participants.iter().any(|p| p.id == carol.hex() && p.speaking).then_some(b)
    })
    .await;
    assert!(speaking.active_speaker.is_some());

    // Dave joins late, with the call button
    let t = Instant::now();
    dave.calls.start(space).await.unwrap();
    for (d, name) in [(&alice, "alice"), (&bob, "bob"), (&carol, "carol"), (&dave, "dave")] {
        eventually(&format!("{name} talks to all three others"), 15, || talking_to(d, &id, 3)).await;
    }
    eprintln!("late joiner meshed with everyone in {:?}", t.elapsed());
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_hears(&dave, "dave", &[1000.0, 440.0, 660.0], &[880.0]);
    assert_hears(&alice, "alice", &[440.0, 660.0, 880.0], &[1000.0]);

    // Bob leaves: the call goes on for the others
    bob.calls.end(&id).unwrap();
    let b = eventually("bob's side ends", 5, || bob.call(&id).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(b.end_reason, Some(EndReason::HungUp));
    for (d, name) in [(&alice, "alice"), (&carol, "carol"), (&dave, "dave")] {
        eventually(&format!("{name} sees bob leave"), 10, || {
            let c = talking_to(d, &id, 2)?;
            c.participants.iter().any(|p| p.id == bob.hex() && p.state == ParticipantState::Left).then_some(())
        })
        .await;
    }

    // Alice, who started it, leaves too: still going for Carol and Dave
    alice.calls.end(&id).unwrap();
    for (d, name) in [(&carol, "carol"), (&dave, "dave")] {
        eventually(&format!("{name} still talking after alice left"), 10, || talking_to(d, &id, 1)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_hears(&carol, "carol", &[880.0], &[1000.0, 440.0]);
    assert_hears(&dave, "dave", &[660.0], &[1000.0, 440.0]);

    // Carol leaves: Dave is the last one, so the call is over
    carol.calls.end(&id).unwrap();
    let d =
        eventually("the last person's call ends", 10, || dave.call(&id).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(d.end_reason, Some(EndReason::RemoteHungUp));
    for dev in [&alice, &bob, &carol, &dave] {
        assert!(dev.live().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn outsiders_and_removed_members_are_refused() {
    let _cpu = cpu_shared().await;
    let alice = device("alice", sine(440.0), true, &[]).await;
    let bob = device("bob", sine(660.0), true, &[]).await;
    // Not 880 Hz: that's both 440's second harmonic and 2×660 − 440, and
    // the codec's concealment of a late frame puts a little of both there.
    let carol = device("carol", sine(CAROL), true, &[]).await;
    let eve = device("eve", sine(550.0), true, &[]).await;
    connect_all(&[&alice, &bob, &carol, &eve]);
    let space = group_space(&[&alice, &bob, &carol]).await;

    let out = alice.calls.start(space).await.unwrap();
    let id = out.id.clone();
    eventually("bob rings", 15, || bob.incoming().filter(|r| r.id == id)).await;
    eventually("carol rings", 15, || carol.incoming().filter(|r| r.id == id)).await;
    bob.calls.accept(&id).await.unwrap();
    carol.calls.decline(&id).unwrap();
    eventually("alice and bob talking", 15, || talking_to(&alice, &id, 1)).await;

    // Eve isn't in the group: even knowing the call exactly, she can't
    // join it, watch it, or ring about it; the devices in it refuse.
    assert!(eve.calls.start(space).await.is_err(), "no call from outside the group");
    let cref = alice.calls.call_ref(&id).unwrap();
    let own = CallRef::new(space, eve.node.id(), [3; 16]);
    for (to, msg) in [
        (&alice, Ctrl::Join { version: proto::VERSION, call: cref }),
        (&bob, Ctrl::Join { version: proto::VERSION, call: cref }),
        (&alice, Ctrl::Watch { version: proto::VERSION, call: cref }),
        (&alice, Ctrl::Ring { version: proto::VERSION, call: own, group: true }),
    ] {
        let conn = eve.node.connect(to.node.id(), ALPN_CALL).await.unwrap();
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        proto::send(&mut tx, &msg).await.unwrap();
        assert_eq!(proto::recv(&mut rx).await.unwrap(), Some(Ctrl::Denied), "{msg:?}");
        conn.close(0u32.into(), b"");
    }
    let a = alice.call(&id).unwrap();
    assert!(a.participants.iter().all(|p| p.id != eve.hex()), "eve never shows up");
    assert_eq!(a.joined_count, 2);

    // Carol is removed from the group while the call goes on: she can't
    // join it any more.
    alice.node.with_space(&space, |r| r.remove_member(carol.node.id())).unwrap().unwrap();
    bob.node.sync_with(alice.node.id(), space, false).await.unwrap();
    let _ = carol.calls.accept(&id).await;
    let c = eventually("carol's join is refused", 15, || carol.call(&id).filter(|c| c.state == CallPhase::Ended)).await;
    eprintln!("removed member's join ended as {:?}", c.end_reason);
    // For the next 2 s neither device in the call has Carol joined or hears
    // anything from her, checked every 100 ms rather than once at the end.
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        for (d, name) in [(&alice, "alice"), (&bob, "bob")] {
            let info = d.call(&id).expect("call still there");
            for p in info.participants.iter().filter(|p| p.id == carol.hex()) {
                assert_ne!(p.state, ParticipantState::Joined, "{name} has carol joined");
                assert_eq!(p.level, 0.0, "{name} has a level for carol");
            }
        }
    }
    let a = talking_to(&alice, &id, 1).expect("alice still talking to bob only");
    assert!(a.participants.iter().all(|p| p.id != carol.hex() || p.state != ParticipantState::Joined));
    // Both bounds: no louder than the noise floor allows (`hears`), and far
    // below the other voice.
    assert_hears(&alice, "alice", &[660.0], &[CAROL]);
    assert_hears(&bob, "bob", &[440.0], &[CAROL]);
    for (d, name) in [(&alice, "alice"), (&bob, "bob")] {
        assert!(!hears(d, CAROL), "{name} hears carol (snr {:.1})", snr(d, 1.5, CAROL));
    }
    alice.calls.end(&id).unwrap();
}

/// No IP at all: three devices on peer-to-peer Wi-Fi only.
#[tokio::test(flavor = "multi_thread")]
async fn group_call_over_links_only() {
    let _cpu = cpu_shared().await;
    let wifi = MemNet::new(5, PathKind::PeerWifi);
    let alice = device("alice", sine(440.0), false, &[&wifi]).await;
    let bob = device("bob", sine(660.0), false, &[&wifi]).await;
    let carol = device("carol", sine(880.0), false, &[&wifi]).await;
    let devs = [&alice, &bob, &carol];
    eventually("everyone sees everyone on the link", 15, || {
        devs.iter()
            .all(|a| {
                devs.iter()
                    .filter(|b| b.node.id() != a.node.id())
                    .all(|b| a.node.peers().get(&b.node.id()).is_some_and(|p| !p.links.is_empty()))
            })
            .then_some(())
    })
    .await;
    let space = group_space(&devs).await;
    let id = alice.calls.start(space).await.unwrap().id;
    for d in [&bob, &carol] {
        eventually("ring", 15, || d.incoming().filter(|r| r.id == id)).await;
        d.calls.accept(&id).await.unwrap();
    }
    for d in devs {
        eventually("3-way over the link", 20, || talking_to(d, &id, 2)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_hears(&alice, "alice", &[660.0, 880.0], &[440.0]);
    assert_hears(&bob, "bob", &[440.0, 880.0], &[660.0]);
    assert_hears(&carol, "carol", &[440.0, 660.0], &[880.0]);
    let c = carol.call(&id).unwrap();
    assert!(c.participants.iter().all(|p| p.path == Some(PathKind::PeerWifi)), "{:?}", c.participants);
    alice.calls.end(&id).unwrap();
    bob.calls.end(&id).unwrap();
    let c = eventually("last one out", 10, || carol.call(&id).filter(|c| c.state == CallPhase::Ended)).await;
    assert_eq!(c.end_reason, Some(EndReason::RemoteHungUp));
}
