//! How promptly timers fire: the emulated links (MemNet) deliver every
//! packet from a timer, and the tests that rank links by speed need them
//! within a few ms. (Windows' default tick is 15.6 ms; `fine_timers` asks
//! for 1 ms.)

use std::time::{Duration, Instant};

async fn sleeps(label: &str) -> (Duration, Duration) {
    let n = 200u32;
    let mut worst = Duration::ZERO;
    let start = Instant::now();
    for _ in 0..n {
        let t = Instant::now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        worst = worst.max(t.elapsed());
    }
    let mean = start.elapsed() / n;
    println!("{label}: sleep(1 ms) takes {mean:?} on average, {worst:?} at worst");
    (mean, worst)
}

#[tokio::test(flavor = "multi_thread")]
async fn timers_fire_within_a_few_ms() {
    sleeps("before fine_timers").await;
    mycel_net::fine_timers();
    let (mean, _) = sleeps("after fine_timers").await;
    // std's sleep too (not tokio's)
    let t = Instant::now();
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(1));
    }
    println!("std::thread::sleep(1 ms) takes {:?} on average", t.elapsed() / 100);
    assert!(mean < Duration::from_millis(4), "timers are coarse: {mean:?} for a 1 ms sleep");
}
