//! Limits on what peers can make us hold, and for how long: frame memory,
//! and how long a stream may wait for its peer. How many streams a peer
//! may have open at once is QUIC's own limit, per connection
//! (`link::transport_config`): a peer over it waits for one of its streams
//! to end, nothing is refused.
use anyhow::{Context, Result, anyhow, bail};
use mycel_crypto::SignPk;
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::wire::MAX_FRAME;

// ─────────────────────────────── deadlines ───────────────────────────────
//
// No exchange has a fixed total deadline: over Bluetooth (≈ 20 KB/s) or a
// multi-hop mesh a sync or a file can take many minutes, and that is fine
// for as long as its bytes keep moving. Each wait is bounded on its own.

/// A stream a peer opens must name its kind and start its first frame
/// within this long. Short: nothing is owed to a stream that sends nothing.
/// It only starts once the stream's first bytes have arrived (a stream is
/// accepted then), and the opener writes the rest right after them, so
/// this only has to cover a lost packet's retransmission on a slow radio.
pub(crate) const FIRST_FRAME: Duration = Duration::from_secs(10);
/// Bytes already under way (a frame, a file) may stop arriving for this
/// long: a path that dies is noticed in ~3 s and its successor carries on
/// (5 s path idle timeout), and a radio's queue can hold seconds of data.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a peer has to start answering us. Our request may first have
/// to fail over to another path or cross several mesh hops, and the peer
/// may have work to do (gathering a large sync, hashing a file) first.
pub(crate) const REPLY_TIMEOUT: Duration = Duration::from_secs(60);
/// The slowest delivery rate planned for (bytes/s): a loaded multi-hop
/// Bluetooth route shared with other streams.
const SLOWEST_RATE: u64 = 2 * 1024;
/// What we wrote is buffered, not delivered: QUIC accepts up to a stream
/// window of it (`link::transport_config`) before writes start to wait.
const MAX_UNDELIVERED: u64 = crate::link::STREAM_WINDOW as u64;
/// How long to wait for the answer to a message of `sent` bytes: the
/// part of it still buffered on our side must get there first, even over
/// the slowest link, then the peer has [`REPLY_TIMEOUT`] to answer.
pub(crate) fn reply_timeout(sent: usize) -> Duration {
    REPLY_TIMEOUT + Duration::from_secs((sent as u64).min(MAX_UNDELIVERED) / SLOWEST_RATE)
}

/// `future`, which waits for the peer, within `wait`.
pub(crate) async fn within<T, E>(
    wait: Duration,
    what: &str,
    future: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    match tokio::time::timeout(wait, future).await {
        Ok(res) => res.map_err(Into::into),
        Err(_) => bail!("{what}: nothing from the device for {} s", wait.as_secs()),
    }
}

/// One step of a transfer already under way (see [`IDLE_TIMEOUT`]).
pub(crate) async fn idle<T, E>(future: impl Future<Output = std::result::Result<T, E>>) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    within(IDLE_TIMEOUT, "transfer stalled", future).await
}

/// Reset the inactivity deadline after each successful write, so a slow
/// stream can keep progressing for longer than one timeout interval.
pub(crate) async fn write_all<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, mut bytes: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    while !bytes.is_empty() {
        let written = idle(writer.write(bytes)).await?;
        anyhow::ensure!(written > 0, "stream stopped accepting bytes");
        bytes = &bytes[written..];
    }
    Ok(())
}

/// The start of a stream a peer opened (see [`FIRST_FRAME`]).
pub(crate) async fn first<T, E>(future: impl Future<Output = std::result::Result<T, E>>) -> Result<T>
where
    E: Into<anyhow::Error>,
{
    within(FIRST_FRAME, "stream opened but not started", future).await
}

// ─────────────────────────────── frame memory ───────────────────────────────
//
// A frame is decoded whole, so it is held in memory whole: what peers send
// us costs memory until we have processed it. Two budgets cover that.
//
// - Each peer has a share, taken for a frame's declared length before any
//   of it is read. A peer that declares big frames and sends them slowly
//   only makes its own next frames wait (and QUIC then slows it down).
// - Each node has a pool that frames draw on only as their bytes arrive:
//   holding pool memory costs a peer the bandwidth to send it, and a frame
//   must keep arriving at [`MIN_RATE`] to keep it. A frame that can't get
//   room within [`POOL_WAIT`] is dropped (its sender tries again later).
//
// Devices we share a space with draw on one pool; devices we don't (anyone
// can make up new keys) on a small one of their own, so a crowd of
// strangers can't push out the people we talk to. The mesh has its own for
// its neighbours. Sizes count encoded bytes: decoded values add to them.
// Frames we send are our own memory and come out of no budget.

/// What devices we share a space with may make us hold, all together ...
const MEMBER_POOL: usize = 128 * 1024 * 1024;
/// ... and each of them: a quarter. A frame bigger than this (up to
/// [`MAX_FRAME`]) still comes in, alone: it takes the whole share.
const MEMBER_SHARE: usize = 32 * 1024 * 1024;
/// Devices we share no space with: contact cards, and an invitation to a
/// space (its membership and inventory). Nothing bigger is taken from them.
const STRANGER_POOL: usize = 32 * 1024 * 1024;
const STRANGER_SHARE: usize = 8 * 1024 * 1024;
/// Mesh neighbours: routing summaries and store-and-forward bundles
/// (256 KiB each by default, a few at a time; up to the last alone).
const NEIGHBOUR_POOL: usize = 32 * 1024 * 1024;
const NEIGHBOUR_SHARE: usize = 4 * 1024 * 1024;
const NEIGHBOUR_MAX: usize = 16 * 1024 * 1024;
/// A frame's bytes must arrive at this average rate (bytes/s) to keep the
/// memory they hold, after [`PROGRESS_GRACE`]: a peer can't hold memory by
/// trickling a byte now and then. Far below the slowest real route.
const MIN_RATE: u64 = 512;
const PROGRESS_GRACE: Duration = Duration::from_secs(60);
/// How long a frame waits for room in a full pool before it is dropped.
const POOL_WAIT: Duration = Duration::from_secs(10);

/// One node's budget for frames from one kind of peer (see above).
pub(crate) struct Frames {
    pool: Arc<Semaphore>,
    share: usize,
    /// The largest frame taken (alone, if bigger than `share`).
    max: usize,
    peers: Mutex<Shares>,
}

#[derive(Default)]
struct Shares {
    /// Live while one of the peer's frames is (or a handle to it).
    map: HashMap<SignPk, Weak<Semaphore>>,
    /// Drop dead entries when the map grows past this.
    sweep_at: usize,
}

impl Frames {
    pub(crate) fn new(pool: usize, share: usize, max: usize) -> Self {
        debug_assert!(share <= max && max <= pool && max <= MAX_FRAME);
        Frames { pool: Arc::new(Semaphore::new(pool)), share, max, peers: Mutex::default() }
    }

    /// Devices we share a space with.
    pub(crate) fn members() -> Self {
        Self::new(MEMBER_POOL, MEMBER_SHARE, MAX_FRAME)
    }

    /// Devices we share no space with.
    pub(crate) fn strangers() -> Self {
        Self::new(STRANGER_POOL, STRANGER_SHARE, STRANGER_SHARE)
    }

    /// Mesh neighbours.
    pub(crate) fn neighbours() -> Self {
        Self::new(NEIGHBOUR_POOL, NEIGHBOUR_SHARE, NEIGHBOUR_MAX)
    }

    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.pool.available_permits()
    }

    /// The budget for frames from `peer`.
    pub(crate) fn peer(&self, peer: &SignPk) -> PeerFrames {
        let mut peers = self.peers.lock();
        let share = match peers.map.get(peer).and_then(Weak::upgrade) {
            Some(share) => share,
            None => {
                if peers.map.len() >= peers.sweep_at {
                    peers.map.retain(|_, s| s.strong_count() > 0);
                    peers.sweep_at = (2 * peers.map.len()).max(64);
                }
                let share = Arc::new(Semaphore::new(self.share));
                peers.map.insert(*peer, Arc::downgrade(&share));
                share
            }
        };
        PeerFrames { pool: self.pool.clone(), share, size: self.share, max: self.max }
    }
}

/// One peer's frame budget.
#[derive(Clone)]
pub(crate) struct PeerFrames {
    pool: Arc<Semaphore>,
    share: Arc<Semaphore>,
    size: usize,
    max: usize,
}

impl PeerFrames {
    /// Outside a node (the public [`crate::wire::recv`]): only the size limit.
    pub(crate) fn unbudgeted() -> Self {
        Frames::new(MAX_FRAME, MAX_FRAME, MAX_FRAME).peer(&SignPk([0; 32]))
    }

    #[cfg(test)]
    pub(crate) fn available(&self) -> usize {
        self.share.available_permits()
    }

    /// Take a frame of `len` declared bytes: waits while the peer's other
    /// frames hold its share.
    pub(crate) async fn admit(&self, len: usize) -> Result<FramePermit> {
        if len > self.max {
            bail!("frame too large");
        }
        let need = u32::try_from(len.min(self.size)).context("frame too large")?;
        let share = self.share.clone().acquire_many_owned(need).await?;
        Ok(FramePermit { _share: share, pool: self.pool.clone(), held: None, started: Instant::now() })
    }
}

/// A frame being received or processed. Dropping it frees its memory.
#[derive(Debug)]
pub(crate) struct FramePermit {
    _share: OwnedSemaphorePermit,
    pool: Arc<Semaphore>,
    held: Option<OwnedSemaphorePermit>,
    started: Instant,
}

impl FramePermit {
    /// Hold `n` bytes of the pool in all (the frame's buffer has grown).
    pub(crate) async fn hold(&mut self, n: usize) -> Result<()> {
        let have = self.held.as_ref().map_or(0, OwnedSemaphorePermit::num_permits);
        if n <= have {
            return Ok(());
        }
        let more = u32::try_from(n - have).context("frame too large")?;
        let permit = match self.pool.clone().try_acquire_many_owned(more) {
            Ok(p) => p,
            Err(_) => tokio::time::timeout(POOL_WAIT, self.pool.clone().acquire_many_owned(more))
                .await
                .map_err(|_| anyhow!("no memory left for what other devices are sending"))??,
        };
        match &mut self.held {
            Some(held) => held.merge(permit),
            None => self.held = Some(permit),
        }
        Ok(())
    }

    /// When the next bytes must have arrived, `got` bytes in: within `idle`
    /// of the last ones, and at [`MIN_RATE`] on average.
    pub(crate) fn deadline(&self, got: usize, idle: Duration) -> Instant {
        let earned = PROGRESS_GRACE + Duration::from_secs_f64(got as f64 / MIN_RATE as f64);
        (Instant::now() + idle).min(self.started + earned)
    }
}

/// Read a frame body of `len` bytes (or, `to_end`, up to `len` bytes until
/// the stream ends) into memory, growing the buffer, and what it holds of
/// the pool, only as bytes arrive.
pub(crate) async fn read_body<R: AsyncRead + Unpin>(
    r: &mut R,
    len: usize,
    to_end: bool,
    mut permit: FramePermit,
    idle: Duration,
) -> Result<(Vec<u8>, FramePermit)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        // (one byte more than `len` when reading to the end: it must end there)
        let take = chunk.len().min(len + usize::from(to_end) - buf.len());
        if take == 0 {
            break;
        }
        let read = tokio::time::timeout_at(permit.deadline(buf.len(), idle), r.read(&mut chunk[..take]));
        let got = match read.await {
            Ok(got) => got?,
            Err(_) => bail!("frame stalled at {} of {len} bytes", buf.len()),
        };
        if got == 0 {
            if to_end {
                break;
            }
            bail!("truncated frame");
        }
        if buf.len() + got > len {
            bail!("frame too large");
        }
        if buf.capacity() < buf.len() + got {
            let target = (buf.len() + got).next_power_of_two().min(len);
            permit.hold(target).await?;
            buf.reserve_exact(target - buf.len());
        }
        buf.extend_from_slice(&chunk[..got]);
    }
    Ok((buf, permit))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(pool: usize, share: usize, max: usize) -> Frames {
        Frames::new(pool, share, max)
    }

    #[tokio::test]
    async fn frames_take_a_peers_share_up_front_and_the_pool_as_bytes_arrive() {
        let frames = budget(100, 40, 60);
        let (a, b) = (frames.peer(&SignPk([1; 32])), frames.peer(&SignPk([2; 32])));
        assert!(a.admit(61).await.is_err(), "bigger than any frame taken");
        let mut first = a.admit(30).await.unwrap();
        assert_eq!(frames.pool.available_permits(), 100, "nothing of the pool until bytes arrive");
        first.hold(10).await.unwrap();
        assert_eq!(frames.pool.available_permits(), 90);
        // a's next frame waits for a's share; b's doesn't
        assert!(tokio::time::timeout(Duration::from_millis(50), a.admit(20)).await.is_err());
        let mut other = b.admit(40).await.unwrap();
        other.hold(40).await.unwrap();
        drop(first);
        assert_eq!(frames.pool.available_permits(), 60);
        // a frame bigger than the share comes in alone, taking all of it
        let big = a.admit(60).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), a.admit(1)).await.is_err());
        drop((big, other));
        assert_eq!(frames.pool.available_permits(), 100);
        assert_eq!(frames.peer(&SignPk([1; 32])).share.available_permits(), 40);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_pool_drops_the_frame_after_a_while() {
        let frames = budget(10, 10, 10);
        let (a, b) = (frames.peer(&SignPk([1; 32])), frames.peer(&SignPk([2; 32])));
        let mut held = a.admit(10).await.unwrap();
        held.hold(8).await.unwrap();
        let mut waiting = b.admit(5).await.unwrap();
        let err = waiting.hold(5).await.unwrap_err();
        assert!(err.to_string().contains("no memory left"), "{err}");
        drop(held);
        waiting.hold(5).await.unwrap();
    }

    #[tokio::test]
    async fn frame_budgets_return_on_cancellation() {
        let frames = budget(64, 64, 64);
        let peer = frames.peer(&SignPk([1; 32]));
        let task = tokio::spawn(async move {
            let mut permit = peer.admit(64).await.unwrap();
            permit.hold(32).await.unwrap();
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        assert_eq!(frames.pool.available_permits(), 64);
        assert!(frames.peer(&SignPk([1; 32])).admit(64).await.is_ok());
    }

    #[test]
    fn peer_shares_are_swept() {
        let frames = budget(64, 1, 1);
        for i in 0..1000u32 {
            let mut pk = [0; 32];
            pk[..4].copy_from_slice(&i.to_le_bytes());
            drop(frames.peer(&SignPk(pk)));
        }
        assert!(frames.peers.lock().map.len() <= 128);
    }
}
