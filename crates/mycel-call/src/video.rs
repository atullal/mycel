//! Video in calls: the [`TrackSink`] that gives every person's connection
//! in a call a video track (`mycel_video::VideoCall`: one camera, a track
//! per peer, each at the quality its own path allows).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bytes::Bytes;
use mycel_crypto::SignPk;
use mycel_net::iroh::endpoint::{Connection, RecvStream};
use mycel_video::{CameraState, PeerVideo, UiFrame, VideoCall, VideoInfo, VideoSource};
use parking_lot::{Mutex, RwLock};
use tokio::sync::broadcast;

use crate::engine::TrackSink;
use crate::manager::selected_path;
use crate::proto::CallId;

pub struct VideoHub {
    me: SignPk,
    source: RwLock<Arc<dyn VideoSource>>,
    ui: broadcast::Sender<UiFrame>,
    calls: Mutex<HashMap<CallId, Arc<VideoCall>>>,
    /// Calls whose camera should be on (asked for before media started).
    wanted: Mutex<HashSet<CallId>>,
    /// Why the camera couldn't be turned on before media started.
    errors: Mutex<HashMap<CallId, String>>,
    /// Video streams that arrived before their leg was added (the engine
    /// accepts a connection's streams as soon as it has the leg; the
    /// other side's long-lived control stream can come first).
    early: Mutex<HashMap<(CallId, SignPk), Vec<EarlyStream>>>,
}

/// A video stream (its kind byte, and the rest) waiting for its leg.
type EarlyStream = (u8, RecvStream);

impl VideoHub {
    pub fn new(me: SignPk) -> VideoHub {
        VideoHub {
            me,
            source: RwLock::new(mycel_video::default_source()),
            ui: broadcast::channel(256).0,
            calls: Mutex::default(),
            wanted: Mutex::default(),
            errors: Mutex::default(),
            early: Mutex::default(),
        }
    }

    pub fn set_source(&self, source: Arc<dyn VideoSource>) {
        *self.source.write() = source;
    }

    pub fn frames(&self) -> broadcast::Receiver<UiFrame> {
        self.ui.subscribe()
    }

    fn call(&self, id: &CallId) -> Option<Arc<VideoCall>> {
        self.calls.lock().get(id).cloned()
    }

    /// Turn the camera on or off in a call (blocking: the first time, the
    /// system's camera prompt waits for the user).
    pub fn set_camera(&self, id: &CallId, on: bool) -> anyhow::Result<()> {
        if on {
            self.wanted.lock().insert(*id);
        } else {
            self.wanted.lock().remove(id);
        }
        self.errors.lock().remove(id);
        let r = match self.call(id) {
            Some(v) => v.set_camera(on),
            // no media yet: ask for permission now, turn it on with the call
            None if on => self.source.read().clone().prepare(),
            None => Ok(()),
        };
        if let Err(e) = &r {
            self.wanted.lock().remove(id);
            self.errors.lock().insert(*id, format!("{e:#}"));
        }
        r
    }

    pub fn keyframes(&self, id: &CallId) {
        if let Some(v) = self.call(id) {
            v.keyframes();
        }
    }

    /// The call is over: stop its video (off the async runtime: it joins threads).
    pub fn end(&self, id: &CallId) -> Option<impl FnOnce() + Send + 'static> {
        self.wanted.lock().remove(id);
        self.errors.lock().remove(id);
        self.early.lock().retain(|(c, _), _| c != id);
        self.calls.lock().remove(id).map(|v| move || drop(v))
    }

    pub fn info(&self, id: &CallId, live: bool) -> VideoInfo {
        if let Some(v) = self.call(id) {
            return v.info();
        }
        let error = self.errors.lock().get(id).cloned();
        VideoInfo {
            camera: match &error {
                Some(e) if e.contains("isn't allowed") => CameraState::Denied,
                Some(_) => CameraState::Failed,
                None if live && self.wanted.lock().contains(id) => CameraState::Starting,
                None => CameraState::Off,
            },
            error,
            source: self.source.read().describe(),
            ..Default::default()
        }
    }

    pub fn peer(&self, id: &CallId, peer: &SignPk) -> PeerVideo {
        self.call(id).and_then(|v| v.peer(&peer.0)).unwrap_or_default()
    }
}

impl TrackSink for VideoHub {
    fn leg_added(&self, call: &CallId, peer: &SignPk, conn: &Connection) {
        let (v, fresh) = {
            let mut calls = self.calls.lock();
            match calls.get(call) {
                Some(v) => (v.clone(), false),
                None => {
                    let v = Arc::new(VideoCall::new(
                        self.me.0,
                        self.source.read().clone(),
                        self.ui.clone(),
                        tokio::runtime::Handle::current(),
                    ));
                    calls.insert(*call, v.clone());
                    (v, true)
                }
            }
        };
        {
            // (under the early lock, so a stream can't slip in between
            // adding the track and draining what arrived before it)
            let mut early = self.early.lock();
            v.add_peer(peer.0, conn.clone(), selected_path(conn).0);
            for (kind, rx) in early.remove(&(*call, *peer)).unwrap_or_default() {
                let _ = v.stream(&peer.0, kind, rx);
            }
        }
        if fresh && self.wanted.lock().contains(call) {
            // (starting the camera may block a moment; a failure shows in
            // the call's video state)
            tokio::task::spawn_blocking(move || {
                let _ = v.set_camera(true);
            });
        }
    }

    fn leg_removed(&self, call: &CallId, peer: &SignPk) {
        if let Some(v) = self.call(call) {
            v.remove_peer(&peer.0);
        }
    }

    fn datagram(&self, call: &CallId, peer: &SignPk, kind: u8, data: Bytes) {
        if mycel_video::wire::is_video_kind(kind)
            && let Some(v) = self.call(call)
        {
            v.datagram(&peer.0, &data);
        }
    }

    fn stream(&self, call: &CallId, peer: &SignPk, kind: u8, stream: RecvStream) {
        if !mycel_video::wire::is_video_kind(kind) {
            return;
        }
        let mut early = self.early.lock();
        let left = match self.call(call) {
            Some(v) => v.stream(&peer.0, kind, stream),
            None => Some(stream),
        };
        if let Some(rx) = left {
            // hold it for the leg (a few at most: the control stream, a frame or two)
            let q = early.entry((*call, *peer)).or_default();
            if q.len() < 32 {
                q.push((kind, rx));
            }
        }
    }
}
