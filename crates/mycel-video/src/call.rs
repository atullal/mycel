//! A call's video: one camera, and a [`VideoTrack`] per other device in the
//! call (a 1:1 call has one; a group call one per peer, each encoded at the
//! quality its own path allows). The call engine tells it when peers come
//! and go and hands it their video streams.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use mycel_net::PathKind;
use mycel_net::iroh::endpoint::{Connection, RecvStream};
use parking_lot::Mutex;
use tokio::sync::broadcast;

use crate::source::{Picture, SourceHandle, VideoSource};
use crate::track::{CameraState, PeerVideo, TrackOptions, VideoInfo, VideoTrack};
use crate::wire::UiFrame;

type Tracks = Arc<Mutex<BTreeMap<[u8; 32], VideoTrack>>>;

pub struct VideoCall {
    me: [u8; 32],
    source: Arc<dyn VideoSource>,
    ui: broadcast::Sender<UiFrame>,
    rt: tokio::runtime::Handle,
    tracks: Tracks,
    camera: Mutex<Option<SourceHandle>>,
    state: Mutex<(CameraState, Option<String>)>,
}

impl VideoCall {
    pub fn new(me: [u8; 32], source: Arc<dyn VideoSource>, ui: broadcast::Sender<UiFrame>, rt: tokio::runtime::Handle) -> VideoCall {
        VideoCall {
            me,
            source,
            ui,
            rt,
            tracks: Arc::default(),
            camera: Mutex::new(None),
            state: Mutex::new((CameraState::Off, None)),
        }
    }

    /// A peer joined (or its connection was replaced): video with it on `conn`.
    pub fn add_peer(&self, peer: [u8; 32], conn: Connection, path: Option<PathKind>) {
        let t = VideoTrack::start(conn, self.ui.clone(), TrackOptions { me: self.me, peer, path }, self.rt.clone());
        t.set_camera(self.camera.lock().is_some());
        let mut tracks = self.tracks.lock();
        tracks.insert(peer, t);
        pick_self_view(&tracks);
    }

    pub fn remove_peer(&self, peer: &[u8; 32]) {
        let gone = {
            let mut tracks = self.tracks.lock();
            let gone = tracks.remove(peer);
            pick_self_view(&tracks);
            gone
        };
        // (joins the encoder thread)
        if let Some(t) = gone {
            self.rt.spawn_blocking(move || drop(t));
        }
    }

    /// A video stream from `peer` (its kind byte already read). Returns it
    /// if there's no track for `peer` (yet).
    pub fn stream(&self, peer: &[u8; 32], kind: u8, rx: RecvStream) -> Option<RecvStream> {
        match self.tracks.lock().get(peer) {
            Some(t) => {
                t.accept_stream(kind, rx);
                None
            }
            None => Some(rx),
        }
    }

    /// Ask for permission now if it's never been asked (blocking: the
    /// system prompt waits for the user). Errors say what to do.
    pub fn prepare(&self) -> Result<()> {
        self.source.prepare()
    }

    /// Turn our camera on or off. Turning it on may wait for the user to
    /// answer the camera prompt, so call it off the async runtime. If it
    /// can't start, the call goes on without our video and the error is
    /// kept for [`VideoCall::info`].
    pub fn set_camera(&self, on: bool) -> Result<()> {
        if !on {
            let handle = self.camera.lock().take();
            for t in self.tracks.lock().values() {
                t.set_camera(false);
            }
            drop(handle);
            *self.state.lock() = (CameraState::Off, None);
            return Ok(());
        }
        if self.camera.lock().is_some() {
            return Ok(());
        }
        *self.state.lock() = (CameraState::Starting, None);
        let tracks = Arc::downgrade(&self.tracks);
        let started = self.source.prepare().and_then(|()| {
            self.source.start(Arc::new(move |pic: Picture| {
                if let Some(tracks) = tracks.upgrade() {
                    for t in tracks.lock().values() {
                        t.push(pic.clone());
                    }
                }
            }))
        });
        match started {
            Ok(handle) => {
                *self.camera.lock() = Some(handle);
                for t in self.tracks.lock().values() {
                    t.set_camera(true);
                }
                *self.state.lock() = (CameraState::On, None);
                Ok(())
            }
            Err(e) => {
                let msg = format!("{e:#}");
                let denied = msg.contains("isn't allowed");
                *self.state.lock() = (if denied { CameraState::Denied } else { CameraState::Failed }, Some(msg));
                Err(e)
            }
        }
    }

    pub fn camera_on(&self) -> bool {
        self.camera.lock().is_some()
    }

    /// The app's decoders need a fresh start: keyframes from everyone, and
    /// for our self-view.
    pub fn keyframes(&self) {
        for t in self.tracks.lock().values() {
            t.request_keyframe();
            t.force_keyframe();
        }
    }

    /// Tests: give up on every `every`-th frame to each peer (0 = off).
    #[doc(hidden)]
    pub fn drop_frames_for_test(&self, every: u32) {
        for t in self.tracks.lock().values() {
            t.drop_frames_for_test(every);
        }
    }

    pub fn peer(&self, peer: &[u8; 32]) -> Option<PeerVideo> {
        self.tracks.lock().get(peer).map(|t| t.info())
    }

    /// Our camera, and (for a 1:1 call) video with the other device: the
    /// first peer's numbers. Per-peer numbers: [`VideoCall::peer`].
    pub fn info(&self) -> VideoInfo {
        let (camera, mut error) = self.state.lock().clone();
        let tracks = self.tracks.lock();
        let first = tracks.values().next();
        if error.is_none() {
            error = first.and_then(|t| t.encoder_error());
        }
        let p = first.map(|t| t.info()).unwrap_or_default();
        VideoInfo {
            camera,
            error,
            sending: p.sending,
            paused: p.paused,
            remote_camera: p.remote_camera,
            remote_paused: p.remote_paused,
            receiving: p.receiving,
            send_width: p.send_width,
            send_height: p.send_height,
            send_fps: p.send_fps,
            bitrate: p.bitrate,
            sent_bitrate: p.sent_bitrate,
            queue_ms: p.queue_ms,
            recv_width: p.recv_width,
            recv_height: p.recv_height,
            recv_fps: p.recv_fps,
            latency_ms: p.latency_ms,
            frames_sent: p.frames_sent,
            frames_received: p.frames_received,
            frames_skipped: p.frames_skipped,
            keyframes_sent: p.keyframes_sent,
            keyframe_requests: p.keyframe_requests,
            source: self.source.describe(),
            encoder: p.encoder,
        }
    }
}

/// Exactly one track feeds the self-view: the first.
fn pick_self_view(tracks: &BTreeMap<[u8; 32], VideoTrack>) {
    for (i, t) in tracks.values().enumerate() {
        t.set_self_view(i == 0);
    }
}

impl Drop for VideoCall {
    fn drop(&mut self) {
        self.camera.lock().take();
        self.tracks.lock().clear();
    }
}
