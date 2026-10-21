//! Video calls between two real nodes (real QUIC), with test audio and the
//! test pattern in place of microphones and cameras: video both ways on a
//! fast path, video and audio sharing a slow link (audio must not suffer),
//! and video pausing when the call moves to Bluetooth.
//!
//! Apple only: encoding and decoding need VideoToolbox (elsewhere video is
//! still a stub that refuses to start).
#![cfg(any(target_os = "macos", target_os = "ios"))]

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_call::audio::{AudioIo, TestAudio, TestSource};
use mycel_call::level::estimate_frequency;
use mycel_call::{BoxFuture, CallEvent, CallHost, CallInfo, CallManager, CallPhase};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_net::iroh::endpoint::Connection;
use mycel_net::link::{Link, MemNet, PathKind};
use mycel_net::{NetMode, Node, NodeOptions};
use mycel_trust::Role;
use mycel_video::pattern::read_counter;
use mycel_video::platform::H264Decoder;
use mycel_video::{CameraState, TestPattern, UiFrame, UiSource, VideoSource};
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc};

/// Tests that measure speed (fps, throughput, rates) run one at a time:
/// side by side they starve each other of CPU and the numbers mean nothing.
static MEASURING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Host {
    node: Arc<Node>,
    events: Arc<Mutex<Vec<CallEvent>>>,
}

impl CallHost for Host {
    fn me(&self) -> SignPk {
        self.node.id()
    }

    fn members(&self, space: &Hash32) -> anyhow::Result<Vec<SignPk>> {
        let me = self.node.id();
        let others: Vec<SignPk> = self.node.with_space(space, |r| {
            r.members()
                .into_iter()
                .filter(|(k, role)| k.sign_pk != me && *role != Role::Relay)
                .map(|(k, _)| k.sign_pk)
                .collect()
        })?;
        if others.is_empty() {
            anyhow::bail!("nobody else here");
        }
        Ok(others)
    }

    fn may_call(&self, space: &Hash32, peer: &SignPk) -> bool {
        self.node.with_space(space, |r| r.is_member(peer) && r.my_role().is_some()).unwrap_or(false)
    }

    fn name_of(&self, peer: &SignPk) -> String {
        peer.short()
    }

    fn connect(&self, peer: SignPk) -> BoxFuture<anyhow::Result<Connection>> {
        let node = self.node.clone();
        Box::pin(async move { mycel_call::proto::connect(&node, peer).await })
    }

    fn note_connection(&self, peer: &SignPk, conn: &Connection) {
        self.node.note_connection(*peer, conn);
    }

    fn emit(&self, event: CallEvent) {
        self.events.lock().push(event);
    }
}

struct Device {
    node: Arc<Node>,
    calls: CallManager,
    audio: Arc<TestAudio>,
    events: Arc<Mutex<Vec<CallEvent>>>,
}

impl Device {
    fn hex(&self) -> String {
        self.node.id().0.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn call(&self, id: &str) -> Option<CallInfo> {
        self.calls.status().into_iter().find(|c| c.id == id)
    }

    fn incoming(&self) -> Option<CallInfo> {
        self.events.lock().iter().rev().find_map(|e| match e {
            CallEvent::Incoming(c) => Some(c.clone()),
            _ => None,
        })
    }

    fn heard(&self, secs: f32) -> Option<f32> {
        let rec = self.audio.recording();
        let rec = rec.lock();
        let n = (48_000.0 * secs) as usize;
        estimate_frequency(&rec.samples[rec.samples.len().saturating_sub(n)..], 48_000)
    }
}

async fn device(name: &str, source: TestSource, ip: bool, nets: &[&MemNet]) -> Device {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = ip;
    opts.links = nets.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    let (tx, rx) = mpsc::unbounded_channel();
    opts.extra_protocols.extend(mycel_call::proto::extra_protocols(tx));
    let node = Arc::new(Node::spawn(keys, opts).await.unwrap());
    let events: Arc<Mutex<Vec<CallEvent>>> = Arc::default();
    let calls = CallManager::new(Arc::new(Host { node: node.clone(), events: events.clone() }));
    let audio = Arc::new(TestAudio::new(source));
    calls.set_audio(audio.clone() as Arc<dyn AudioIo>);
    calls.set_video_source(Arc::new(TestPattern::default()) as Arc<dyn VideoSource>);
    calls.serve(rx);
    Device { node, calls, audio, events }
}

async fn shared_space(a: &Device, b: &Device) -> Hash32 {
    let (space, genesis) = a.node.create_space().unwrap();
    a.node.with_space(&space, |r| r.add_member(b.node.keys().public(), Role::Writer)).unwrap().unwrap();
    b.node.join_space(genesis).unwrap();
    b.node.sync_with(a.node.id(), space, true).await.unwrap();
    space
}

async fn eventually<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        if Instant::now() > end {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Alice calls Bob (with her camera on if `video`) and Bob answers.
async fn connect_call(alice: &Device, bob: &Device, space: Hash32, video: bool) -> String {
    let out = alice.calls.start(space).await.unwrap();
    if video {
        let i = alice.calls.set_camera(&out.id, true).await.unwrap();
        // (or ringing already: the call runs on its own task)
        assert!(matches!(i.state, CallPhase::Connecting | CallPhase::Ringing), "{i:?}");
    }
    let ring = eventually("bob's device rings", 15, || bob.incoming().filter(|r| r.id == out.id)).await;
    bob.calls.accept(&ring.id).await.unwrap();
    eventually("both active", 10, || {
        let a = alice.call(&out.id)?;
        let b = bob.call(&out.id)?;
        (a.state == CallPhase::Active && b.state == CallPhase::Active).then_some(())
    })
    .await;
    out.id
}

/// Decodes the remote video a device's app would show, reading the test
/// pattern's counters back: (counter, arrival).
fn watch(rx: broadcast::Receiver<UiFrame>) -> Arc<Mutex<Vec<(u32, Instant)>>> {
    let seen: Arc<Mutex<Vec<(u32, Instant)>>> = Arc::default();
    let out = seen.clone();
    let mut rx = rx;
    std::thread::spawn(move || {
        let mut dec = H264Decoder::default();
        loop {
            let f = match rx.blocking_recv() {
                Ok(f) => f,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            if f.source != UiSource::Remote {
                continue;
            }
            if let Ok(pic) = dec.decode(&f.frame)
                && let Ok((w, h, luma)) = pic.luma()
                && let Some(n) = read_counter(&luma, w, h, w)
            {
                out.lock().push((n, Instant::now()));
            }
        }
    });
    seen
}

fn fps(seen: &Mutex<Vec<(u32, Instant)>>, secs: f64) -> f64 {
    let cut = Instant::now() - Duration::from_secs_f64(secs);
    seen.lock().iter().filter(|f| f.1 >= cut).count() as f64 / secs
}

/// Mean delay from each of Alice's tone bursts to its onset in what Bob
/// heard, over bursts heard in the last `window` seconds.
fn burst_latency(alice: &Device, bob: &Device, period: f64, window: f64) -> Option<f64> {
    let src = alice.audio.source_start()?;
    let rec = bob.audio.recording();
    let rec = rec.lock();
    let start = rec.start?;
    let offset = start.saturating_duration_since(src).as_secs_f64();
    let len = rec.samples.len() as f64 / 48_000.0;
    let delays: Vec<f64> = TestAudio::onsets(&rec.samples)
        .into_iter()
        .filter(|t| *t > len - window)
        .map(|t| {
            let t = t + offset;
            t - (t / period).floor() * period
        })
        .collect();
    if delays.len() < 3 {
        return None;
    }
    Some(delays.iter().sum::<f64>() / delays.len() as f64)
}

/// Audio frames Bob received per second, and lost, over `secs`.
async fn audio_rate(bob: &Device, id: &str, secs: u64) -> (f64, u64) {
    let b0 = bob.call(id).unwrap().stats;
    tokio::time::sleep(Duration::from_secs(secs)).await;
    let b1 = bob.call(id).unwrap().stats;
    ((b1.frames_received - b0.frames_received) as f64 / secs as f64, b1.frames_lost - b0.frames_lost)
}

fn bursts() -> TestSource {
    TestSource::Bursts { hz: 1000.0, on_ms: 100, period_ms: 500 }
}

#[tokio::test(flavor = "multi_thread")]
async fn video_call_both_ways_over_ip() {
    let _measuring = MEASURING.lock().await;
    let alice = device("alice", TestSource::Sine { hz: 660.0, amp: 0.5 }, true, &[]).await;
    let bob = device("bob", TestSource::Sine { hz: 440.0, amp: 0.5 }, true, &[]).await;
    alice.node.add_peer_addr(bob.node.addr());
    bob.node.add_peer_addr(alice.node.addr());
    let space = shared_space(&alice, &bob).await;
    let bob_sees = watch(bob.calls.video_frames());
    let alice_sees = watch(alice.calls.video_frames());

    // Alice starts a video call; Bob answers with voice only
    let id = connect_call(&alice, &bob, space, true).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let a = alice.call(&id).unwrap();
    let b = bob.call(&id).unwrap();
    assert_eq!(a.video.camera, CameraState::On);
    assert!(a.video.sending);
    assert!(b.video.remote_camera && b.video.receiving, "bob gets alice's video");
    assert_eq!(b.video.camera, CameraState::Off);
    assert!(!a.video.remote_camera && !a.video.receiving, "bob's camera is off");
    assert!(fps(&bob_sees, 1.0) > 25.0, "bob sees {:.1} fps", fps(&bob_sees, 1.0));
    assert!(fps(&alice_sees, 1.0) < 1.0);

    // Bob turns his camera on mid-call
    bob.calls.set_camera(&id, true).await.unwrap();
    // his video starts low and steps up (each step a keyframe burst that
    // skips a frame or two); under load that takes a few seconds longer
    eventually("alice sees bob's video at full rate", 15, || {
        let a = alice.call(&id)?;
        (a.video.recv_width == 1280 && fps(&alice_sees, 1.0) > 25.0).then_some(())
    })
    .await;
    let (a, b) = (alice.call(&id).unwrap(), bob.call(&id).unwrap());
    eprintln!(
        "video call over IP: alice→bob {}x{} {:.1} fps {} kbit/s, latency {} ms; bob→alice {}x{} {:.1} fps; audio rtt {} ms, lost {}",
        b.video.recv_width,
        b.video.recv_height,
        b.video.recv_fps,
        a.video.sent_bitrate / 1000,
        b.video.latency_ms,
        a.video.recv_width,
        a.video.recv_height,
        a.video.recv_fps,
        a.stats.rtt_ms,
        b.stats.frames_lost,
    );
    assert!(a.video.receiving && fps(&alice_sees, 1.0) > 25.0, "alice sees bob");
    assert!(fps(&bob_sees, 1.0) > 25.0);
    assert!(b.video.latency_ms < 100);
    for seen in [&bob_sees, &alice_sees] {
        let s = seen.lock();
        assert!(s.windows(2).all(|w| w[1].0 > w[0].0), "in order");
    }
    // audio unaffected
    assert!((bob.heard(1.0).unwrap() - 660.0).abs() < 8.0);
    assert!((alice.heard(1.0).unwrap() - 440.0).abs() < 8.0);
    assert!(b.stats.frames_lost < 10, "audio lost {}", b.stats.frames_lost);

    // hang up: video stops with the call
    alice.calls.end(&id).unwrap();
    eventually("ended", 5, || (bob.call(&id)?.state == CallPhase::Ended).then_some(())).await;
    let n = bob_sees.lock().len();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(bob_sees.lock().len(), n, "no video after hang-up");
    let b = bob.call(&id).unwrap();
    assert_eq!(b.video.camera, CameraState::Off);
}

/// One call over a slow link, cameras on or off; audio measured over the
/// same window either way: (mouth-to-ear s, audio frames/s, audio lost,
/// the call at the end).
async fn slow_link_call(n: u64, video: bool) -> (f64, f64, u64, CallInfo, CallInfo, f64) {
    let wifi = MemNet::new(n, PathKind::PeerWifi);
    // ~600 kbit/s, shared by both directions (like a half-duplex radio), 10 ms
    wifi.set_rate_limit(Some(75_000));
    wifi.set_latency(Duration::from_millis(10));
    let alice = device("alice", bursts(), false, &[&wifi]).await;
    let bob = device("bob", TestSource::Sine { hz: 440.0, amp: 0.5 }, false, &[&wifi]).await;
    eventually("link up", 15, || alice.node.peers().get(&bob.node.id()).is_some_and(|p| p.online()).then_some(()))
        .await;
    let space = shared_space(&alice, &bob).await;
    let bob_sees = watch(bob.calls.video_frames());
    let id = connect_call(&alice, &bob, space, false).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    if video {
        alice.calls.set_camera(&id, true).await.unwrap();
        bob.calls.set_camera(&id, true).await.unwrap();
    }
    tokio::time::sleep(Duration::from_secs(4)).await; // settle
    let (rate, lost) = audio_rate(&bob, &id, 10).await;
    let lat = burst_latency(&alice, &bob, 0.5, 10.0).expect("bursts");
    let (a, b) = (alice.call(&id).unwrap(), bob.call(&id).unwrap());
    let fps = fps(&bob_sees, 5.0);
    alice.calls.end(&id).unwrap();
    (lat, rate, lost, a, b, fps)
}

/// Audio and video share a link that can't carry everything: video backs
/// off; audio loses nothing, its jitter stays put, and its delay rises by
/// less than 100 ms over the same link without video.
#[tokio::test(flavor = "multi_thread")]
async fn video_on_a_slow_link_leaves_audio_alone() {
    let _measuring = MEASURING.lock().await;
    let (lat_off, rate_off, lost_off, _, b_off, _) = slow_link_call(11, false).await;
    let (lat_on, rate_on, lost_on, a, b, fps) = slow_link_call(12, true).await;
    eprintln!(
        "600 kbit/s link: audio {rate_off:.0}→{rate_on:.0} frames/s, lost {lost_off}→{lost_on}, mouth-to-ear {:.0}→{:.0} ms \
         (jitter {:.1}→{:.1} ms, buffer {}→{} ms); video {}x{} {fps:.1} fps decoded, sent {} kbit/s (target {}), queue {} ms, \
         video latency {} ms, skipped {}",
        lat_off * 1000.0,
        lat_on * 1000.0,
        b_off.stats.jitter_ms,
        b.stats.jitter_ms,
        b_off.stats.buffer_ms,
        b.stats.buffer_ms,
        a.video.send_width,
        a.video.send_height,
        a.video.sent_bitrate / 1000,
        a.video.bitrate / 1000,
        a.video.queue_ms,
        b.video.latency_ms,
        a.video.frames_skipped,
    );
    assert!(rate_on > 45.0, "audio keeps flowing ({rate_on:.0}/s)");
    assert!(lost_on <= lost_off + 10, "audio loss {lost_off} → {lost_on}");
    // Measured: +40–80 ms on this half-duplex 600 kbit/s link (and none at
    // all on an unconstrained one); audio jitter and loss don't change.
    assert!(lat_on - lat_off < 0.100, "audio delay {:.0} → {:.0} ms", lat_off * 1000.0, lat_on * 1000.0);
    assert!(
        b.stats.jitter_ms < b_off.stats.jitter_ms + 5.0,
        "audio jitter {} → {} ms",
        b_off.stats.jitter_ms,
        b.stats.jitter_ms
    );
    assert!(fps > 4.0, "video still moving ({fps:.1} fps)");
    assert!(a.video.sent_bitrate < 600_000);
}

/// The call moves to Bluetooth: video pauses ("slow connection") on both
/// sides and the audio carries on.
#[tokio::test(flavor = "multi_thread")]
async fn video_pauses_on_bluetooth() {
    let _measuring = MEASURING.lock().await;
    let wifi = MemNet::new(12, PathKind::PeerWifi);
    let bt = MemNet::new(12, PathKind::Bluetooth);
    bt.set_rate_limit(Some(20_000));
    bt.set_latency(Duration::from_millis(20));
    let alice = device("alice", TestSource::Sine { hz: 660.0, amp: 0.5 }, false, &[&wifi, &bt]).await;
    let bob = device("bob", TestSource::Sine { hz: 440.0, amp: 0.5 }, false, &[&wifi, &bt]).await;
    eventually("links up", 15, || {
        alice.node.peers().get(&bob.node.id()).is_some_and(|p| p.links.len() == 2).then_some(())
    })
    .await;
    let space = shared_space(&alice, &bob).await;
    let bob_sees = watch(bob.calls.video_frames());
    let id = connect_call(&alice, &bob, space, true).await;
    // (video starts at 320×180 and ramps up)
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert!(fps(&bob_sees, 1.0) > 25.0, "video over peer-to-peer Wi-Fi ({:.1} fps)", fps(&bob_sees, 1.0));
    // the 480p rung (848×480) with the 16:9 camera fitted in, unstretched
    let video = alice.call(&id).unwrap().video;
    assert_eq!((video.send_width, video.send_height), (848, 476), "480p on peer-to-peer Wi-Fi");

    wifi.cut();
    // (the call's path shows within a second of the video noticing)
    let a = eventually("alice's video pauses on Bluetooth", 30, || {
        alice.call(&id).filter(|a| a.video.paused && a.path == Some(PathKind::Bluetooth))
    })
    .await;
    assert!(!a.video.sending);
    eventually("bob sees it paused", 10, || bob.call(&id)?.video.remote_paused.then_some(())).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let n = bob_sees.lock().len();
    let (rate, _) = audio_rate(&bob, &id, 4).await;
    assert_eq!(bob_sees.lock().len(), n, "no video over Bluetooth");
    assert!(rate > 40.0, "audio carries on ({rate:.0}/s)");
    assert!((bob.heard(1.0).unwrap() - 660.0).abs() < 8.0);
    assert_eq!(alice.call(&id).unwrap().video.camera, CameraState::On, "camera stays on for when the path recovers");
    alice.calls.end(&id).unwrap();
}

/// Measurement (run by hand): would a tiny 160×90 5 fps stream fit over a
/// Bluetooth-like 20 KB/s link without hurting audio?
///
/// `cargo test -p mycel-call --test video tiny_video -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn tiny_video_over_bluetooth_measurement() {
    let _measuring = MEASURING.lock().await;
    // SAFETY: this test runs on its own (ignored by default), before any
    // other thread reads the environment.
    unsafe { std::env::set_var("MYCEL_VIDEO_BLUETOOTH_KBPS", "40") };
    let bt = MemNet::new(13, PathKind::Bluetooth);
    bt.set_rate_limit(Some(20_000));
    bt.set_latency(Duration::from_millis(20));
    let alice = device("alice", bursts(), false, &[&bt]).await;
    let bob = device("bob", TestSource::Sine { hz: 440.0, amp: 0.5 }, false, &[&bt]).await;
    eventually("link up", 15, || alice.node.peers().get(&bob.node.id()).is_some_and(|p| p.online()).then_some(()))
        .await;
    let space = shared_space(&alice, &bob).await;
    let bob_sees = watch(bob.calls.video_frames());
    let id = connect_call(&alice, &bob, space, false).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (rate_off, lost_off) = audio_rate(&bob, &id, 6).await;
    let lat_off = burst_latency(&alice, &bob, 0.5, 6.0).unwrap_or(f64::NAN);
    alice.calls.set_camera(&id, true).await.unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (rate_on, lost_on) = audio_rate(&bob, &id, 10).await;
    let lat_on = burst_latency(&alice, &bob, 0.5, 10.0).unwrap_or(f64::NAN);
    let (a, b) = (alice.call(&id).unwrap(), bob.call(&id).unwrap());
    eprintln!(
        "Bluetooth 20 KB/s with tiny video: audio {rate_off:.0}→{rate_on:.0} frames/s, lost {lost_off}→{lost_on}, \
         mouth-to-ear {:.0}→{:.0} ms; video {}x{} {:.1} fps decoded {:.1}, sent {} kbit/s, video latency {} ms, queue {} ms",
        lat_off * 1000.0,
        lat_on * 1000.0,
        a.video.send_width,
        a.video.send_height,
        b.video.recv_fps,
        fps(&bob_sees, 5.0),
        a.video.sent_bitrate / 1000,
        b.video.latency_ms,
        a.video.queue_ms,
    );
    alice.calls.end(&id).unwrap();
}

/// Decodes every remote video stream a device's app would show, one decoder
/// per person: frames seen per person.
/// Frames decoded per person: (test-pattern counter, when).
type PerPerson = Arc<Mutex<std::collections::HashMap<[u8; 32], Vec<(u32, Instant)>>>>;

fn watch_people(rx: broadcast::Receiver<UiFrame>) -> PerPerson {
    let seen: PerPerson = Arc::default();
    let out = seen.clone();
    let mut rx = rx;
    std::thread::spawn(move || {
        let mut decs: std::collections::HashMap<[u8; 32], H264Decoder> = Default::default();
        loop {
            let f = match rx.blocking_recv() {
                Ok(f) => f,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            if f.source != UiSource::Remote {
                continue;
            }
            let dec = decs.entry(f.peer).or_default();
            if let Ok(pic) = dec.decode(&f.frame)
                && let Ok((w, h, luma)) = pic.luma()
                && let Some(n) = read_counter(&luma, w, h, w)
            {
                out.lock().entry(f.peer).or_default().push((n, Instant::now()));
            }
        }
    });
    seen
}

/// A group video call of three: everyone sees both others, each as its own
/// stream (a tile), each in order, and every participant's video shows.
#[tokio::test(flavor = "multi_thread")]
async fn group_video_call_of_three() {
    let _measuring = MEASURING.lock().await;
    let alice = device("alice", TestSource::Sine { hz: 440.0, amp: 0.5 }, true, &[]).await;
    let bob = device("bob", TestSource::Sine { hz: 550.0, amp: 0.5 }, true, &[]).await;
    let carol = device("carol", TestSource::Sine { hz: 660.0, amp: 0.5 }, true, &[]).await;
    let all = [&alice, &bob, &carol];
    for a in all {
        for b in all {
            if a.node.id() != b.node.id() {
                a.node.add_peer_addr(b.node.addr());
            }
        }
    }
    let (space, genesis) = alice.node.create_space().unwrap();
    for d in [&bob, &carol] {
        alice.node.with_space(&space, |r| r.add_member(d.node.keys().public(), Role::Writer)).unwrap().unwrap();
    }
    for d in [&bob, &carol] {
        d.node.join_space(genesis.clone()).unwrap();
        d.node.sync_with(alice.node.id(), space, true).await.unwrap();
    }
    let seen: Vec<_> = all.iter().map(|d| watch_people(d.calls.video_frames())).collect();

    let out = alice.calls.start(space).await.unwrap();
    alice.calls.set_camera(&out.id, true).await.unwrap();
    for d in [&bob, &carol] {
        let ring = eventually("rings", 15, || d.incoming().filter(|r| r.id == out.id)).await;
        d.calls.set_camera(&ring.id, true).await.unwrap();
        d.calls.accept(&ring.id).await.unwrap();
    }
    eventually("all three in", 20, || {
        all.iter()
            .all(|d| d.call(&out.id).is_some_and(|c| c.state == CallPhase::Active && c.joined_count == 3))
            .then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_secs(8)).await;

    for (d, seen) in all.iter().zip(&seen) {
        let info = d.call(&out.id).unwrap();
        let cut = Instant::now() - Duration::from_secs(2);
        for other in all.iter().filter(|o| o.node.id() != d.node.id()) {
            let s = seen.lock();
            let frames = s.get(&other.node.id().0).map(|v| v.as_slice()).unwrap_or(&[]);
            let fps = frames.iter().filter(|f| f.1 >= cut).count() as f64 / 2.0;
            assert!(frames.windows(2).all(|w| w[1].0 > w[0].0), "in order");
            let p = info.participants.iter().find(|p| p.id == other.hex()).expect("participant");
            eprintln!(
                "{} sees {}: {fps:.1} fps decoded, {}x{} at {:.1} fps, sending them {}x{} {} kbit/s",
                d.node.id().short(),
                other.node.id().short(),
                p.video.recv_width,
                p.video.recv_height,
                p.video.recv_fps,
                p.video.send_width,
                p.video.send_height,
                p.video.sent_bitrate / 1000,
            );
            assert!(fps > 12.0, "{fps:.1} fps");
            assert!(p.video.remote_camera && p.video.receiving && p.video.sending);
        }
        assert_eq!(info.video.camera, CameraState::On);
    }
    alice.calls.end(&out.id).unwrap();
}
