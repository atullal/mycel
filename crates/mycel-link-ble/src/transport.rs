//! The Iroh custom transport: QUIC packets in and out of the [`Hub`]. Never
//! blocks: sends go into a bounded per-channel queue (dropped when full),
//! receives come from a bounded channel the radio threads fill.

use std::io;
use std::sync::Arc;
use std::task::{Context, Poll};

use mycel_net::link::transports::{CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit};
use mycel_net::link::{CustomAddr, n0_watcher, noq_udp};
use tokio::sync::mpsc;

use crate::hub::{Hub, Inbound, addr_of, key_of};
use crate::wire::encode_packet;

pub struct BleTransport {
    pub hub: Arc<Hub>,
    pub rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Inbound>>>,
}

impl std::fmt::Debug for BleTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BleTransport")
    }
}

impl CustomTransport for BleTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let rx = self
            .rx
            .clone()
            .try_lock_owned()
            .map_err(|_| io::Error::other("bluetooth link already bound"))?;
        let local = addr_of(&self.hub.me);
        Ok(Box::new(BleEndpoint {
            hub: self.hub.clone(),
            addrs: n0_watcher::Watchable::new(vec![local.clone()]),
            local,
            rx,
        }))
    }
}

struct BleEndpoint {
    hub: Arc<Hub>,
    local: CustomAddr,
    addrs: n0_watcher::Watchable<Vec<CustomAddr>>,
    rx: tokio::sync::OwnedMutexGuard<mpsc::Receiver<Inbound>>,
}

impl std::fmt::Debug for BleEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BleEndpoint")
    }
}

impl CustomEndpoint for BleEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(BleSender { hub: self.hub.clone() })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let n = bufs.len();
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut packets = Vec::with_capacity(n);
        match self.rx.poll_recv_many(cx, &mut packets, n) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("bluetooth link closed"))),
            Poll::Ready(_) => {}
        }
        let mut count = 0;
        for p in packets {
            if bufs[count].len() < p.data.len() {
                continue;
            }
            bufs[count][..p.data.len()].copy_from_slice(&p.data);
            metas[count].len = p.data.len();
            metas[count].stride = p.data.len();
            recv_infos[count] = RecvInfo::new(addr_of(&p.from), Some(self.local.clone()));
            count += 1;
        }
        if count == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(count))
    }
}

#[derive(Debug)]
struct BleSender {
    hub: Arc<Hub>,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hub({})", crate::hub::short(&self.me))
    }
}

impl CustomSender for BleSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        key_of(addr).is_some()
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(to) = key_of(dst) else {
            return Poll::Ready(Err(io::Error::other("not a bluetooth address")));
        };
        // No channel right now: lost in the air. QUIC's path probing notices.
        let Some(sink) = self.hub.route(&to) else {
            return Poll::Ready(Ok(()));
        };
        let seg = transmit.segment_size.unwrap_or(transmit.contents.len()).max(1);
        for chunk in transmit.contents.chunks(seg) {
            if let Some(frame) = encode_packet(chunk) {
                sink.send(frame);
            }
        }
        Poll::Ready(Ok(()))
    }
}
