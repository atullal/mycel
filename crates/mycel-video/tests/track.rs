//! Video between two real nodes (real QUIC) with test-pattern sources: the
//! receiver decodes every frame in Rust and reads the frame counter back
//! out of the pixels.
//!
//! Apple only: encoding and decoding need VideoToolbox (elsewhere video is
//! still a stub that refuses to start).
#![cfg(any(target_os = "macos", target_os = "ios"))]

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_crypto::DeviceKeys;
use mycel_net::iroh::endpoint::Connection;
use mycel_net::link::{Link, MemNet, PathKind};
use mycel_net::{ExtraProtocol, NetMode, Node, NodeOptions};
use mycel_video::pattern::read_counter;
use mycel_video::platform::H264Decoder;
use mycel_video::source::wall_us;
use mycel_video::{CameraState, TestPattern, UiFrame, UiSource, VideoCall, VideoSource};
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc};

const ALPN: &[u8] = b"test/video";

/// These tests measure frame rates and share the hardware encoder, so they
/// run one at a time: side by side they starve each other.
static MEASURING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Side {
    node: Arc<Node>,
    incoming: mpsc::UnboundedReceiver<Connection>,
}

async fn side(name: &str, ip: bool, nets: &[&MemNet]) -> Side {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = ip;
    opts.links = nets.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    let (tx, incoming) = mpsc::unbounded_channel();
    opts.extra_protocols.push(ExtraProtocol { alpn: ALPN.to_vec(), incoming: tx });
    Side { node: Arc::new(Node::spawn(keys, opts).await.unwrap()), incoming }
}

/// What a receiver decoded: (counter, capture → decoded µs, size).
#[derive(Default)]
struct Seen {
    frames: Vec<(u32, u64, (usize, usize), Instant)>,
    undecodable: u32,
}

/// Decode `peer`'s remote frames as they arrive, like the app's webview would.
fn watch(mut rx: broadcast::Receiver<UiFrame>, source: UiSource) -> Arc<Mutex<Seen>> {
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let out = seen.clone();
    std::thread::spawn(move || {
        let mut dec = H264Decoder::default();
        loop {
            let f = match rx.blocking_recv() {
                Ok(f) => f,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            if f.source != source {
                continue;
            }
            let pic = match dec.decode(&f.frame) {
                Ok(p) => p,
                Err(_) => {
                    out.lock().undecodable += 1;
                    continue;
                }
            };
            let (w, h, luma) = pic.luma().unwrap();
            let n = read_counter(&luma, w, h, w);
            let lat = wall_us().saturating_sub(f.frame.capture_us);
            match n {
                Some(n) => out.lock().frames.push((n, lat, (w, h), Instant::now())),
                None => out.lock().undecodable += 1,
            }
        }
    });
    seen
}

struct Pair {
    a: Arc<VideoCall>,
    b: Arc<VideoCall>,
    a_ui: broadcast::Sender<UiFrame>,
    b_ui: broadcast::Sender<UiFrame>,
    _conns: (Connection, Connection),
    _nodes: (Arc<Node>, Arc<Node>),
}

/// What the call engine does: hand the connection's video streams and
/// datagrams (by their kind byte) to the call's video.
fn route(conn: Connection, video: Arc<VideoCall>, peer: [u8; 32]) {
    {
        let (conn, video) = (conn.clone(), video.clone());
        tokio::spawn(async move {
            while let Ok(d) = conn.read_datagram().await {
                video.datagram(&peer, &d);
            }
        });
    }
    tokio::spawn(async move {
        while let Ok(mut rx) = conn.accept_uni().await {
            let mut kind = [0u8; 1];
            if rx.read_exact(&mut kind).await.is_ok() {
                let _ = video.stream(&peer, kind[0], rx);
            }
        }
    });
}

async fn pair(ip: bool, nets: &[&MemNet], path: Option<PathKind>) -> Pair {
    let a = side("alice", ip, nets).await;
    let mut b = side("bob", ip, nets).await;
    if ip {
        a.node.add_peer_addr(b.node.addr());
        b.node.add_peer_addr(a.node.addr());
    }
    let ca = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match a.node.connect(b.node.id(), ALPN).await {
                Ok(c) => return c,
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    })
    .await
    .expect("connected");
    let cb = b.incoming.recv().await.unwrap();
    let (a_ui, b_ui) = (broadcast::channel(512).0, broadcast::channel(512).0);
    let src = || Arc::new(TestPattern::default()) as Arc<dyn VideoSource>;
    let rt = tokio::runtime::Handle::current();
    let (ka, kb) = (a.node.id().0, b.node.id().0);
    let va = Arc::new(VideoCall::new(ka, src(), a_ui.clone(), rt.clone()));
    let vb = Arc::new(VideoCall::new(kb, src(), b_ui.clone(), rt));
    va.add_peer(kb, ca.clone(), path);
    vb.add_peer(ka, cb.clone(), path);
    route(ca.clone(), va.clone(), kb);
    route(cb.clone(), vb.clone(), ka);
    Pair { a: va, b: vb, a_ui, b_ui, _conns: (ca, cb), _nodes: (a.node, b.node) }
}

async fn camera(t: &VideoCall, on: bool) {
    // set_camera blocks (permission prompt); off the runtime
    tokio::task::block_in_place(|| t.set_camera(on)).unwrap();
}

/// Frames decoded in the last `secs`: (fps, mean latency ms, max latency ms).
fn recent(seen: &Mutex<Seen>, secs: f64) -> (f64, f64, f64) {
    let s = seen.lock();
    let cut = Instant::now() - Duration::from_secs_f64(secs);
    let r: Vec<_> = s.frames.iter().filter(|f| f.3 >= cut).collect();
    if r.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let mean = r.iter().map(|f| f.1 as f64).sum::<f64>() / r.len() as f64 / 1000.0;
    let max = r.iter().map(|f| f.1).max().unwrap() as f64 / 1000.0;
    (r.len() as f64 / secs, mean, max)
}

fn assert_in_order(seen: &Mutex<Seen>) {
    assert_in_order_from(seen, 0)
}

/// From frame `from` on (the test pattern counts from 0 again each time the
/// camera starts).
fn assert_in_order_from(seen: &Mutex<Seen>, from: usize) {
    let s = seen.lock();
    for (i, w) in s.frames.windows(2).enumerate().skip(from) {
        if w[1].0 <= w[0].0 {
            let around: Vec<_> =
                s.frames[i.saturating_sub(3)..(i + 4).min(s.frames.len())].iter().map(|f| (f.0, f.2)).collect();
            panic!("frames out of order or repeated: {} then {} ({around:?})", w[0].0, w[1].0);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn video_both_ways_over_ip() {
    let _measuring = MEASURING.lock().await;
    let p = pair(true, &[], Some(PathKind::Network)).await;
    let at_bob = watch(p.b_ui.subscribe(), UiSource::Remote);
    let at_alice = watch(p.a_ui.subscribe(), UiSource::Remote);
    let alice_self = watch(p.a_ui.subscribe(), UiSource::Local);
    camera(&p.a, true).await;
    camera(&p.b, true).await;
    tokio::time::sleep(Duration::from_secs(8)).await;

    let (fps, lat, max) = recent(&at_bob, 3.0);
    let ai = p.a.info();
    let bi = p.b.info();
    eprintln!(
        "over IP: bob sees {fps:.1} fps, capture→decoded {lat:.1} ms avg / {max:.1} ms max; alice sends {}x{} at {} bit/s ({:.1} fps, queue {} ms, {}); \
         frames sent {} received {} skipped {} keyframes {} requests {}",
        ai.send_width,
        ai.send_height,
        ai.bitrate,
        ai.send_fps,
        ai.queue_ms,
        ai.encoder,
        ai.frames_sent,
        bi.frames_received,
        ai.frames_skipped,
        ai.keyframes_sent,
        bi.keyframe_requests
    );
    assert_in_order(&at_bob);
    assert_eq!(at_bob.lock().undecodable, 0, "every frame decodes");
    assert!(fps > 25.0, "bob sees {fps:.1} fps");
    assert!(lat < 100.0 && max < 300.0, "latency {lat:.1} ms avg, {max:.1} max");
    let (back_fps, _, _) = recent(&at_alice, 3.0);
    assert!(back_fps > 25.0, "and the other way: {back_fps:.1} fps, {:?}", p.a.info());
    assert!(recent(&alice_self, 3.0).0 > 25.0, "self-view");
    assert_eq!((ai.send_width, ai.send_height), (1280, 720), "a clean fast path reaches 720p");
    assert!(ai.sending && !ai.paused && ai.camera == CameraState::On);
    assert!(bi.remote_camera && bi.receiving);
    assert_eq!((bi.recv_width, bi.recv_height), (1280, 720));
    let (_, _, size, _) = *at_bob.lock().frames.last().unwrap();
    assert_eq!(size, (1280, 720));

    // camera off: bob is told, frames stop
    assert_in_order(&at_alice);
    camera(&p.a, false).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!p.b.info().remote_camera, "bob sees alice's camera off");
    let n = at_bob.lock().frames.len();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(at_bob.lock().frames.len(), n, "nothing sent with the camera off");
    // and on again: a fresh keyframe, decodable at once
    camera(&p.a, true).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(p.b.info().remote_camera);
    assert!(recent(&at_bob, 1.0).0 > 20.0, "video back");
    assert_eq!(at_bob.lock().frames[n].0, 0, "the restarted camera's first frame");
    assert_in_order_from(&at_bob, n);
    assert_eq!(at_bob.lock().undecodable, 0);
}

/// Frames the sender gives up on: the receiver asks for a keyframe and
/// recovers within a fraction of a second, never decoding a broken picture.
#[tokio::test(flavor = "multi_thread")]
async fn recovers_from_lost_frames_with_keyframes() {
    let _measuring = MEASURING.lock().await;
    let p = pair(true, &[], Some(PathKind::Network)).await;
    let at_bob = watch(p.b_ui.subscribe(), UiSource::Remote);
    camera(&p.a, true).await;
    tokio::time::sleep(Duration::from_secs(6)).await; // ramped up to 30 fps
    p.a.drop_frames_for_test(45); // one lost frame every 1.5 s
    tokio::time::sleep(Duration::from_secs(9)).await;
    p.a.drop_frames_for_test(0);
    // over 2 s: a 1 s window counts whole frames, and a throttled CI
    // machine that delivers 25-26 of them read as exactly 25.0 fps
    tokio::time::sleep(Duration::from_secs(2)).await;

    let ai = p.a.info();
    let bi = p.b.info();
    let (fps, lat, _) = recent(&at_bob, 2.0);
    // gaps: how long the picture froze after each loss
    let freezes: Vec<f64> = {
        let s = at_bob.lock();
        s.frames
            .windows(2)
            .map(|w| w[1].3.duration_since(w[0].3).as_secs_f64() * 1000.0)
            .filter(|g| *g > 80.0)
            .collect()
    };
    eprintln!(
        "losses: keyframe requests {}, keyframes sent {}, freezes {:?} ms, after: {fps:.1} fps, {lat:.1} ms",
        bi.keyframe_requests,
        ai.keyframes_sent,
        freezes.iter().map(|f| f.round()).collect::<Vec<_>>()
    );
    assert_in_order(&at_bob);
    assert_eq!(at_bob.lock().undecodable, 0, "no broken pictures: deltas after a loss wait for the keyframe");
    assert!(bi.keyframe_requests >= 4, "asked for keyframes ({})", bi.keyframe_requests);
    assert!(ai.keyframes_sent >= 4);
    assert!(freezes.iter().all(|f| *f < 400.0), "each recovery is quick: {freezes:?}");
    assert!(fps >= 24.0, "back to full rate after the losses: {fps:.1} fps");
}

/// A link that can't carry what we'd like: the bitrate and resolution come
/// down to fit, frames keep coming in order, and delay stays bounded.
#[tokio::test(flavor = "multi_thread")]
async fn adapts_to_a_slow_link() {
    let _measuring = MEASURING.lock().await;
    let wifi = MemNet::new(7, PathKind::PeerWifi);
    // ~400 kbit/s
    wifi.set_rate_limit(Some(50_000));
    wifi.set_latency(Duration::from_millis(5));
    let p = pair(false, &[&wifi], Some(PathKind::PeerWifi)).await;
    let at_bob = watch(p.b_ui.subscribe(), UiSource::Remote);
    camera(&p.a, true).await;
    tokio::time::sleep(Duration::from_secs(12)).await;
    let ai = p.a.info();
    let (fps, lat, max) = recent(&at_bob, 4.0);
    eprintln!(
        "400 kbit/s link: {}x{} at {} bit/s target, {} bit/s sent, {fps:.1} fps decoded, latency {lat:.0} ms avg / {max:.0} max, queue {} ms, skipped {}",
        ai.send_width, ai.send_height, ai.bitrate, ai.sent_bitrate, ai.queue_ms, ai.frames_skipped
    );
    assert_in_order(&at_bob);
    assert_eq!(at_bob.lock().undecodable, 0);
    assert!(ai.sent_bitrate < 400_000, "what we send fits the link ({} bit/s)", ai.sent_bitrate);
    assert!(ai.send_height <= 360, "resolution came down ({}p)", ai.send_height);
    assert!(fps >= 8.0, "still moving: {fps:.1} fps");
    assert!(lat < 400.0, "delay bounded: {lat:.0} ms");
}
