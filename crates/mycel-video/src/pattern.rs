//! A test picture (`MYCEL_VIDEO=test`): a moving pattern with the frame
//! counter drawn into it as 16 black-or-white blocks along the top, big
//! enough to survive compression and scaling down to 160×90. A receiver
//! that decodes the video reads the counter back from the pixels, which
//! proves frames arrive whole, decodable and in order.

/// Blocks across the top strip: one bit each, most significant first.
pub const BITS: u32 = 16;

/// An NV12 picture (Y plane, then interleaved U/V at half resolution).
pub struct Nv12 {
    pub width: u32,
    pub height: u32,
    pub y: Vec<u8>,
    pub uv: Vec<u8>,
}

/// Draw test frame number `n`.
pub fn draw(n: u32, width: u32, height: u32) -> Nv12 {
    let (w, h) = (width as usize, height as usize);
    let mut y = vec![0u8; w * h];
    let strip = h / 6;
    let block = w / BITS as usize;
    // counter strip
    for row in 0..strip {
        let line = &mut y[row * w..(row + 1) * w];
        for (bit, px) in line.chunks_mut(block).enumerate().take(BITS as usize) {
            let on = (n >> (BITS - 1 - bit as u32)) & 1 == 1;
            px.fill(if on { 235 } else { 16 });
        }
    }
    // a diagonal gradient that scrolls, and a bar sweeping across
    let bar_w = (w / 12).max(2);
    let bar_x = (n as usize * (w / 60).max(1)) % w;
    for row in strip..h {
        let line = &mut y[row * w..(row + 1) * w];
        for (x, px) in line.iter_mut().enumerate() {
            let inside = x >= bar_x && x < bar_x + bar_w;
            *px = if inside { 220 } else { (40 + ((x + row + n as usize * 2) % 128)) as u8 };
        }
    }
    let mut uv = vec![128u8; w * h.div_ceil(2)];
    for row in (strip / 2)..h / 2 {
        for x in 0..w / 2 {
            let i = row * w + x * 2;
            uv[i] = (96 + (x * 64 / (w / 2).max(1))) as u8;
            uv[i + 1] = (160 - (row * 64 / (h / 2).max(1))) as u8;
        }
    }
    Nv12 { width, height, y, uv }
}

/// Read the counter back from a luma plane (`stride` bytes per row), at any
/// resolution the picture was scaled to. `None` if a block isn't clearly
/// black or white (not a test picture, or badly damaged).
pub fn read_counter(luma: &[u8], width: usize, height: usize, stride: usize) -> Option<u32> {
    let strip = height / 6;
    let block = width / BITS as usize;
    if strip < 2 || block < 2 {
        return None;
    }
    let mut n = 0u32;
    for bit in 0..BITS as usize {
        // average the middle half of the block
        let (x0, x1) = (bit * block + block / 4, bit * block + block * 3 / 4);
        let (y0, y1) = (strip / 4, strip * 3 / 4);
        let mut sum = 0u64;
        let mut count = 0u64;
        for row in y0..y1.max(y0 + 1) {
            for x in x0..x1.max(x0 + 1) {
                sum += luma[row * stride + x] as u64;
                count += 1;
            }
        }
        let avg = sum / count.max(1);
        let on = match avg {
            0..=70 => false,
            180..=255 => true,
            _ => return None,
        };
        n = (n << 1) | on as u32;
    }
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_round_trips_at_every_ladder_size() {
        for (w, h) in [(1280, 720), (848, 480), (424, 240), (160, 90)] {
            for n in [0, 1, 0x5a5a, 0xffff, 12345] {
                let p = draw(n, w, h);
                assert_eq!(read_counter(&p.y, w as usize, h as usize, w as usize), Some(n), "{w}x{h} #{n}");
            }
        }
    }

    #[test]
    fn frames_differ() {
        assert_ne!(draw(1, 320, 180).y, draw(2, 320, 180).y, "the picture moves");
    }
}
