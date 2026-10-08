//! Encode the test pattern with VideoToolbox and write the frames as the app
//! receives them (u32 LE length + `UiFrame`), to check a webview's decoder:
//!
//! ```text
//! cargo run -p mycel-video --example dump_frames -- out.bin [width height count]
//! ```

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    use mycel_video::platform::{H264Encoder, PixelBuffer};
    use mycel_video::{UiFrame, UiSource, pattern};

    let args: Vec<String> = std::env::args().collect();
    let out = args.get(1).cloned().unwrap_or_else(|| "frames.bin".into());
    let w: u32 = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(1280);
    let h: u32 = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(720);
    let n: u32 = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(60);
    let mut enc = H264Encoder::new(w, h, 30, 2_000_000)?;
    let mut bytes = Vec::new();
    for i in 0..n {
        let pb = PixelBuffer::from_nv12(&pattern::draw(i, 1280, 720))?;
        let Some(mut f) = enc.encode(&pb, i as i64 * 33_333, i == n / 2)? else { continue };
        f.seq = i;
        f.capture_us = 1_700_000_000_000_000 + i as u64 * 33_333;
        let ui = UiFrame { source: UiSource::Remote, peer: [7; 32], frame: f }.encode();
        bytes.extend_from_slice(&(ui.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&ui);
    }
    std::fs::write(&out, &bytes)?;
    println!("{n} frames, {} bytes, {}", bytes.len(), enc.describe());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {}
