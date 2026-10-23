//! Entry points for the fuzz targets in `fuzz/` (docs/TESTING.md,
//! "Fuzzing"), compiled only under `--cfg fuzzing`, which cargo-fuzz sets.
//! They reach decoders of untrusted bytes that are private to this crate
//! through the functions the node itself calls. Nothing here is API.

use std::io::Cursor;

use mycel_crypto::SignPk;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::mesh::{self, dtn};
use crate::resources::{self, Frames, PeerFrames};
use crate::version::WireVersion;
use crate::wire::{self, BlobReq, BlobResp, ContactCard, EphMsg, SyncMsg};

/// How a stream's frames are read, as the node picks it per stream kind.
#[derive(Clone, Copy, Debug)]
pub enum Reader {
    /// A sync session (either side): [`SyncMsg`] frames, member budget.
    Sync,
    /// An ephemeral uni-stream: one [`EphMsg`], size-checked before decryption.
    Ephemeral,
    /// A blob request, as the server reads it.
    BlobReq,
    /// A blob answer, as the client reads it.
    BlobResp,
    /// A contact card, as the dialer reads it.
    Card,
}

thread_local! {
    static RUNTIME: tokio::runtime::Runtime =
        tokio::runtime::Builder::new_current_thread().enable_time().build().expect("a current-thread runtime");
}

/// Read `bytes` as a peer's stream: length-prefixed frames, each decoded as
/// `reader` decodes them, until one fails or the bytes run out. Each decoded
/// message must re-encode canonically (decode, encode, decode, encode gives
/// the same bytes twice). Returns how many frames decoded.
pub fn read_stream(reader: Reader, bytes: &[u8]) -> usize {
    RUNTIME.with(|rt| {
        rt.block_on(async {
            let budget = Frames::members();
            let frames = budget.peer(&SignPk([7; 32]));
            let mut r = Cursor::new(bytes);
            let mut n = 0;
            loop {
                let ok = match reader {
                    Reader::Sync => frame::<SyncMsg>(&mut r, wire::MAX_FRAME, &frames).await,
                    Reader::BlobReq => frame::<BlobReq>(&mut r, wire::MAX_SMALL_FRAME, &frames).await,
                    Reader::BlobResp => frame::<BlobResp>(&mut r, wire::MAX_SMALL_FRAME, &frames).await,
                    Reader::Card => frame::<ContactCard>(&mut r, wire::MAX_SMALL_FRAME, &frames).await,
                    Reader::Ephemeral => match wire::recv_ephemeral(&mut r, &frames, wire::MAX_EPHEMERAL).await {
                        Ok((msg, _permit)) => {
                            canonical::<EphMsg>(&msg);
                            true
                        }
                        Err(_) => false,
                    },
                };
                if !ok {
                    return n;
                }
                n += 1;
            }
        })
    })
}

async fn frame<T: Serialize + DeserializeOwned>(r: &mut Cursor<&[u8]>, max: usize, frames: &PeerFrames) -> bool {
    let idle = resources::IDLE_TIMEOUT;
    match wire::recv_frame::<T, _>(r, resources::FIRST_FRAME, idle, max, frames).await {
        Ok((msg, _permit)) => {
            canonical(&msg);
            true
        }
        Err(_) => false,
    }
}

fn canonical<T: Serialize + DeserializeOwned>(msg: &T) {
    let once = wire::encode_bounded(msg, wire::MAX_FRAME).expect("a decoded message encodes");
    let back: T = postcard::from_bytes(&once).expect("our own encoding decodes");
    let twice = wire::encode_bounded(&back, wire::MAX_FRAME).expect("a decoded message encodes");
    assert_eq!(once, twice, "re-encoding is stable");
}

/// A neighbour's store-and-forward summary (the stream after its kind byte).
pub fn dtn_summary(body: &[u8]) -> Option<dtn::Summary> {
    mesh::decode_summary(body).ok()
}

/// Our encoding of a summary, as sent to neighbours (`None` if too large).
pub fn encode_dtn_summary(s: dtn::Summary) -> Option<Vec<u8>> {
    mesh::encode_summary(s).ok()
}

/// A neighbour's bundle offer: its first frame, kind byte included (`None`
/// for a malformed offer or one of a kind this build doesn't know). The
/// format may be one this build can't check, which the node refuses.
pub fn dtn_offer(head: &[u8]) -> Option<dtn::Offer> {
    mesh::decode_offer(head).ok().flatten()
}

/// Our offer on a hop of wire `version` (see [`crate::version`]); `None`
/// if that hop can't take the bundle (a version 1 hop only takes version 1
/// bundles) or the offer is too large.
pub fn encode_dtn_offer(version: WireVersion, o: &dtn::Offer) -> Option<Vec<u8>> {
    mesh::encode_offer(version, o).ok().flatten()
}

/// Whether what `c` remembers from its neighbours is within the caps that
/// keep a hostile neighbour from growing it without end; the error says
/// what grew.
pub fn dtn_bounds(c: &dtn::Carrier) -> Result<(), String> {
    c.check_bounds()
}

/// A neighbour's answer to our offer (see `mesh::decode_answer`).
pub fn dtn_answer(body: &[u8]) -> Option<Result<Option<u64>, bool>> {
    mesh::decode_answer(body).ok()
}

/// Bonjour SRV record data, as the system daemon hands it over (parsed on
/// Apple platforms; fuzzed everywhere).
pub fn mdns_srv(rdata: &[u8]) -> Option<(String, u16)> {
    crate::mdns_records::parse_srv(rdata)
}

/// Bonjour TXT record data: a peer's Iroh user data (parsed on Apple
/// platforms; fuzzed everywhere).
pub fn mdns_txt(txt: &[u8]) -> Option<String> {
    crate::mdns_records::parse_txt(txt).map(|u| u.as_ref().to_string())
}

/// A partial download's `.ranges` file as read back from storage (a damaged
/// or foreign file included), then `inserts` as received pieces would be
/// marked. Returns whether the file loaded; panics on invalid ranges.
pub fn blob_ranges(file: &[u8], total: Option<u64>, inserts: &[(u64, u64)]) -> bool {
    crate::blobs::fuzz_ranges(file, total, inserts)
}
