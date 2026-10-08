//! Test devices for call tests: a real node (real QUIC) with a call manager
//! and test audio in place of a microphone and speaker.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use mycel_call::audio::{AudioIo, TestAudio, TestSource};
use mycel_call::level::{estimate_frequency, goertzel};
use mycel_call::{ALPN_CALL, BoxFuture, CallEvent, CallHost, CallInfo, CallManager, CallPhase};
use mycel_crypto::{DeviceKeys, Hash32, SignPk};
use mycel_net::iroh::endpoint::Connection;
use mycel_net::link::{Link, MemNet};
use mycel_net::{ExtraProtocol, MeshOptions, NetMode, Node, NodeOptions};
use mycel_trust::Role;
use parking_lot::Mutex;
use tokio::sync::mpsc;

pub struct Host {
    pub node: Arc<Node>,
    pub events: Arc<Mutex<Vec<CallEvent>>>,
}

impl CallHost for Host {
    fn me(&self) -> SignPk {
        self.node.id()
    }

    fn members(&self, space: &Hash32) -> anyhow::Result<Vec<SignPk>> {
        let me = self.node.id();
        let others: Vec<SignPk> = self.node.with_space(space, |r| {
            r.members().into_iter().filter(|(k, role)| k.sign_pk != me && *role != Role::Relay).map(|(k, _)| k.sign_pk).collect()
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
        Box::pin(async move { node.connect(peer, ALPN_CALL).await })
    }

    fn note_connection(&self, peer: &SignPk, conn: &Connection) {
        self.node.note_connection(*peer, conn);
    }

    fn emit(&self, event: CallEvent) {
        self.events.lock().push(event);
    }
}

pub struct Device {
    pub node: Arc<Node>,
    pub calls: CallManager,
    pub audio: Arc<TestAudio>,
    pub events: Arc<Mutex<Vec<CallEvent>>>,
}

impl Device {
    pub fn hex(&self) -> String {
        self.node.id().0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn status(&self) -> Vec<CallInfo> {
        self.calls.status()
    }

    pub fn live(&self) -> Vec<CallInfo> {
        self.status().into_iter().filter(|c| c.state != CallPhase::Ended).collect()
    }

    pub fn incoming(&self) -> Option<CallInfo> {
        self.events.lock().iter().rev().find_map(|e| match e {
            CallEvent::Incoming(c) => Some(c.clone()),
            _ => None,
        })
    }

    pub fn call(&self, id: &str) -> Option<CallInfo> {
        self.status().into_iter().find(|c| c.id == id)
    }

    /// Frequency of what this device heard in the last `secs` seconds.
    pub fn heard(&self, secs: f32) -> Option<f32> {
        let rec = self.audio.recording();
        let rec = rec.lock();
        let n = (48_000.0 * secs) as usize;
        let tail = &rec.samples[rec.samples.len().saturating_sub(n)..];
        estimate_frequency(tail, 48_000)
    }

    pub fn heard_power(&self, secs: f32, hz: f32) -> f32 {
        let rec = self.audio.recording();
        let rec = rec.lock();
        let n = (48_000.0 * secs) as usize;
        goertzel(&rec.samples[rec.samples.len().saturating_sub(n)..], hz, 48_000)
    }
}

pub async fn device(name: &str, source: TestSource, ip: bool, nets: &[&MemNet]) -> Device {
    device_with(name, source, ip, nets, None).await
}

#[allow(dead_code)] // not every test binary uses the mesh
pub async fn device_with(name: &str, source: TestSource, ip: bool, nets: &[&MemNet], mesh: Option<MeshOptions>) -> Device {
    let keys = Arc::new(DeviceKeys::generate());
    let mut opts = NodeOptions::new(NetMode::Local, name);
    opts.ip = ip;
    opts.mesh = mesh;
    opts.links = nets.iter().map(|n| n.link(keys.sign_pk()) as Arc<dyn Link>).collect();
    let (tx, rx) = mpsc::unbounded_channel();
    opts.extra_protocols.push(ExtraProtocol { alpn: ALPN_CALL.to_vec(), incoming: tx });
    let node = Arc::new(Node::spawn(keys, opts).await.unwrap());
    let events: Arc<Mutex<Vec<CallEvent>>> = Arc::default();
    let calls = CallManager::new(Arc::new(Host { node: node.clone(), events: events.clone() }));
    let audio = Arc::new(TestAudio::new(source));
    calls.set_audio(audio.clone() as Arc<dyn AudioIo>);
    calls.serve(rx);
    Device { node, calls, audio, events }
}

pub fn sine(hz: f32) -> TestSource {
    TestSource::Sine { hz, amp: 0.5 }
}

/// A conversation with both devices in it.
pub async fn shared_space(a: &Device, b: &Device) -> Hash32 {
    let (space, genesis) = a.node.create_space().unwrap();
    a.node.with_space(&space, |r| r.add_member(b.node.keys().public(), Role::Writer)).unwrap().unwrap();
    b.node.join_space(genesis).unwrap();
    b.node.sync_with(a.node.id(), space, true).await.unwrap();
    space
}

pub async fn eventually<T>(what: &str, secs: u64, mut f: impl FnMut() -> Option<T>) -> T {
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

