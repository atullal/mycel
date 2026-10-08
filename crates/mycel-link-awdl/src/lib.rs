//! Mycel link over Apple peer-to-peer Wi-Fi (AWDL — what AirDrop uses): two
//! Macs exchange QUIC packets with no shared Wi-Fi network, as long as Wi-Fi
//! is switched on.
//!
//! How (macOS): Network.framework, the only supported way onto AWDL.
//! * A UDP `nw_listener` with peer-to-peer enabled advertises the Bonjour
//!   service [`wire::SERVICE_TYPE`]; its TXT record carries the device key
//!   and display name.
//! * An `nw_browser` (peer-to-peer enabled) finds other devices. For each,
//!   an outbound UDP `nw_connection` to its Bonjour endpoint, with every
//!   non-peer-to-peer interface the result was seen on prohibited, so it
//!   resolves and runs over `awdl0`. Browsing/advertising with peer-to-peer
//!   enabled is what wakes AWDL up.
//! * Flows start with a [`wire::Control::Hello`] carrying the sender's key so
//!   the listener side knows which device an inbound flow is; the reply
//!   ([`wire::Control::Ack`]) proves the flow works both ways. Hellos repeat
//!   every couple of seconds as a liveness check.
//! * Iroh sees the device as `CustomAddr(TRANSPORT_PEER_WIFI, key)`; the link
//!   maps that to whichever flow currently works. QUIC packets are sent
//!   unframed, one per datagram.
//!
//! `MYCEL_AWDL_ANY_INTERFACE=1` drops the peer-to-peer-only restriction so
//! two processes on one Mac can talk over loopback/LAN (testing).
//!
//! On other platforms [`link`] returns a link that reports itself unavailable.

use std::sync::Arc;

use mycel_crypto::SignPk;
use mycel_net::Link;

pub mod wire;

#[cfg(target_os = "macos")]
mod macos;

/// Env var: allow any interface, not just peer-to-peer Wi-Fi (single-Mac tests).
pub const ANY_INTERFACE_ENV: &str = "MYCEL_AWDL_ANY_INTERFACE";

fn any_interface() -> bool {
    std::env::var(ANY_INTERFACE_ENV).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// The peer-to-peer Wi-Fi link for this device (honours
/// `MYCEL_AWDL_ANY_INTERFACE`).
pub fn link(me: SignPk, name: &str) -> Arc<dyn Link> {
    link_with(me, name, any_interface())
}

/// [`link`] with the interface restriction chosen explicitly:
/// `any_interface = true` also uses loopback / ordinary networks (tests).
pub fn link_with(me: SignPk, name: &str, any_interface: bool) -> Arc<dyn Link> {
    #[cfg(target_os = "macos")]
    {
        macos::AwdlLink::create(me, name, any_interface)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (me, name, any_interface);
        Arc::new(unavailable::Unavailable)
    }
}

/// The link on platforms without AWDL. Compiled everywhere so it is
/// type-checked and tested on macOS too.
#[cfg_attr(target_os = "macos", allow(dead_code))]
mod unavailable {
    use std::io;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use anyhow::{Result, bail};
    use mycel_net::link::transports::{
        CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
    };
    use mycel_net::link::{CustomAddr, n0_watcher, noq_udp};
    use mycel_net::{Link, LinkEvent, LinkStatus, PathKind};
    use tokio::sync::mpsc;

    pub struct Unavailable;

    /// Binds fine (so the node starts) but never carries anything.
    #[derive(Debug)]
    struct NoTransport;

    impl CustomTransport for NoTransport {
        fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
            Ok(Box::new(NoEndpoint(n0_watcher::Watchable::new(Vec::new()))))
        }
    }

    struct NoEndpoint(n0_watcher::Watchable<Vec<CustomAddr>>);

    impl std::fmt::Debug for NoEndpoint {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("NoEndpoint")
        }
    }

    impl CustomEndpoint for NoEndpoint {
        fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
            self.0.watch()
        }
        fn create_sender(&self) -> Arc<dyn CustomSender> {
            Arc::new(NoSender)
        }
        fn poll_recv(
            &mut self,
            _cx: &mut Context,
            _bufs: &mut [io::IoSliceMut<'_>],
            _metas: &mut [noq_udp::RecvMeta],
            _recv_infos: &mut [RecvInfo],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    #[derive(Debug)]
    struct NoSender;

    impl CustomSender for NoSender {
        fn is_valid_send_addr(&self, _addr: &CustomAddr) -> bool {
            false
        }
        fn poll_send(
            &self,
            _cx: &mut Context,
            _dst: &CustomAddr,
            _src: Option<&CustomAddr>,
            _transmit: &Transmit<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no peer-to-peer Wi-Fi",
            )))
        }
    }

    impl Link for Unavailable {
        fn kind(&self) -> PathKind {
            PathKind::PeerWifi
        }
        fn transport(&self) -> Arc<dyn CustomTransport> {
            Arc::new(NoTransport)
        }
        fn start(&self, _events: mpsc::UnboundedSender<LinkEvent>) -> Result<()> {
            bail!("peer-to-peer Wi-Fi is only available on Apple devices")
        }
        fn status(&self) -> LinkStatus {
            LinkStatus {
                kind: PathKind::PeerWifi,
                active: false,
                detail: Some("Peer-to-peer Wi-Fi is only available on Apple devices".into()),
                peers: 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mycel_crypto::DeviceKeys;
    use mycel_net::{Link, NetMode, Node, NodeOptions, PathKind};

    /// A node with the "unavailable" link (non-macOS) still starts, and the
    /// link says why it isn't working.
    #[tokio::test]
    async fn unavailable_link_is_harmless() {
        let keys = Arc::new(DeviceKeys::generate());
        let mut opts = NodeOptions::new(NetMode::Local, "x");
        opts.links = vec![Arc::new(super::unavailable::Unavailable) as Arc<dyn Link>];
        let node = Node::spawn(keys, opts).await.unwrap();
        let st = node.link_status();
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].kind, PathKind::PeerWifi);
        assert!(!st[0].active);
        assert!(st[0].detail.as_deref().unwrap().contains("Apple"));
        node.shutdown().await.unwrap();
    }
}
