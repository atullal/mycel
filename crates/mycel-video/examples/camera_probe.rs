//! Which camera, whether we may use it, and (only if access is already
//! granted) a few seconds of capture: frames, size, rate. Never prompts.
//!
//! ```text
//! cargo run -p mycel-video --example camera_probe
//! ```

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use mycel_video::mac::{CameraPermission, camera, camera_permission};

    let cam = camera();
    let p = camera_permission();
    if p == CameraPermission::Authorized {
        let _ = cam.prepare(); // (looks up the name)
    }
    println!("camera: {}", cam.describe());
    println!("permission: {p:?}");
    if p != CameraPermission::Authorized {
        println!("not capturing (that would ask for permission)");
        return Ok(());
    }
    let count = Arc::new(AtomicU32::new(0));
    let size = Arc::new(parking_lot::Mutex::new((0, 0)));
    let (c, s) = (count.clone(), size.clone());
    let handle = cam.start(Arc::new(move |pic| {
        c.fetch_add(1, Ordering::Relaxed);
        *s.lock() = (pic.width, pic.height);
    }))?;
    std::thread::sleep(std::time::Duration::from_secs(3));
    drop(handle);
    println!("captured {} frames in 3 s at {:?}", count.load(Ordering::Relaxed), *size.lock());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {}
