//! Shared process limits for untrusted incoming streams and frame buffers.
//! Admission is nonblocking: overload drops the stream instead of queuing a
//! task. The process limits cover every node and the mesh DTN protocol.
use anyhow::{Result, anyhow, bail};
use std::{
    future::Future,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// Eight streams per connection leave room for sync, presence, and parallel
// file ranges; the process cap prevents additional connections bypassing it.
pub(crate) const PROCESS_STREAMS: usize = 64;
pub(crate) const CONNECTION_STREAMS: usize = 8;
// Two maximum-sized frames, e.g. a received message and its serialized
// reply. This accounts encoded bytes, not the complete heap: decoded types,
// cloned store records and transport buffers can have additional overhead.
pub(crate) const FRAME_BYTES: usize = 128 * 1024 * 1024;

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
const MAX_UNDELIVERED: u64 = 8 * 1024 * 1024;
tokio::task_local! { static CONNECTION_FRAMES: Arc<Semaphore>; }
static STREAMS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(PROCESS_STREAMS)));
static FRAMES: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(FRAME_BYTES)));

pub(crate) struct Admission {
    global: Arc<Semaphore>,
    connection: Arc<Semaphore>,
    frames: Arc<Semaphore>,
}

impl Admission {
    pub(crate) fn new() -> Self {
        Self {
            global: STREAMS.clone(),
            connection: Arc::new(Semaphore::new(CONNECTION_STREAMS)),
            frames: Arc::new(Semaphore::new(FRAME_BYTES)),
        }
    }

    pub(crate) fn frames(&self) -> Arc<Semaphore> {
        self.frames.clone()
    }

    pub(crate) fn try_acquire(&self) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        let connection = self.connection.clone().try_acquire_owned().ok()?;
        Some((global, connection))
    }
}

pub(crate) async fn with_frames<T>(frames: Arc<Semaphore>, future: impl Future<Output = T>) -> T {
    CONNECTION_FRAMES.scope(frames, future).await
}

pub(crate) struct FramePermit {
    _global: OwnedSemaphorePermit,
    _connection: Option<OwnedSemaphorePermit>,
}

pub(crate) fn frame_bytes(len: usize) -> Result<FramePermit> {
    let count = u32::try_from(len).map_err(|_| anyhow!("frame too large"))?;
    let global = FRAMES.clone().try_acquire_many_owned(count).map_err(|_| anyhow!("frame memory budget exhausted"))?;
    let connection = CONNECTION_FRAMES
        .try_with(|frames| {
            frames
                .clone()
                .try_acquire_many_owned(count)
                .map_err(|_| anyhow!("connection frame memory budget exhausted"))
        })
        .ok()
        .transpose()?;
    Ok(FramePermit { _global: global, _connection: connection })
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_stream_admission_global_connection_and_release() {
        let global = Arc::new(Semaphore::new(3));
        let a = Admission {
            global: global.clone(),
            connection: Arc::new(Semaphore::new(2)),
            frames: Arc::new(Semaphore::new(64)),
        };
        let b = Admission { global, connection: Arc::new(Semaphore::new(2)), frames: Arc::new(Semaphore::new(64)) };
        let first = a.try_acquire().unwrap();
        let second = a.try_acquire().unwrap();
        assert!(a.try_acquire().is_none());
        let third = b.try_acquire().unwrap();
        assert!(b.try_acquire().is_none());
        drop(first);
        assert!(b.try_acquire().is_some());
        drop((second, third));
        assert_eq!(a.global.available_permits(), 3);
    }

    #[tokio::test]
    async fn security_stream_admission_returns_on_task_cancellation() {
        let a = Admission {
            global: Arc::new(Semaphore::new(1)),
            connection: Arc::new(Semaphore::new(1)),
            frames: Arc::new(Semaphore::new(64)),
        };
        let permit = a.try_acquire().unwrap();
        let task = tokio::spawn(async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        });
        task.abort();
        let _ = task.await;
        assert!(a.try_acquire().is_some());
    }
    #[tokio::test]
    async fn security_frame_budgets_reject_overload_without_waiting() {
        assert!(frame_bytes(FRAME_BYTES + 1).is_err());
        let frames = Arc::new(Semaphore::new(64));
        with_frames(frames.clone(), async {
            let first = frame_bytes(40).unwrap();
            assert!(frame_bytes(25).is_err());
            assert_eq!(frames.available_permits(), 24);
            drop(first);
            assert!(frame_bytes(64).is_ok());
        })
        .await;
        assert_eq!(frames.available_permits(), 64);
    }
}
