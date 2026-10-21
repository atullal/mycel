//! Catching up while a phone's OS lends Mycel a little time, and what the UI
//! says about delivery in the background.
//!
//! There is no push server, so nothing can wake a phone the moment a message
//! is sent. What each OS offers instead:
//! - **iOS / iPadOS** ("slow mode"): `BGAppRefreshTask` and
//!   `BGProcessingTask` launches at times iOS picks (registered and scheduled
//!   in `gen/apple/Sources/mycel-host/main.mm`, which calls
//!   [`mycel_background_catch_up`]), Bluetooth events while a nearby device
//!   runs Mycel (`mycel-link-ble` opts into state restoration), and the
//!   usual grace period after leaving the app (`finish_in_background` in
//!   lib.rs). Delivery may wait until the app is opened.
//! - **Android**: `MycelService`, a foreground service, keeps the runtime
//!   running; it restarts after a reboot or an update (`BootReceiver`), and a
//!   periodic WorkManager job (`CatchUpWorker`) catches up if the phone
//!   stopped it anyway (`android.rs`).
//!
//! A catch-up syncs every conversation now, then stays awake a little longer
//! so peers that hold messages for us (keepers, store-and-forward relays)
//! can deliver them, then flushes to disk. It never outlives its budget.

// Only phones lend background time, but the logic is built and tested
// everywhere.
#![cfg_attr(not(any(target_os = "android", target_os = "ios")), allow(dead_code))]

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

/// After the sync round, stay connected this long (within the budget) for
/// deliveries that peers push once we're reachable.
const LINGER: Duration = Duration::from_secs(10);
/// Leave this much of the OS's budget for flushing and telling the OS we're done.
const MARGIN: Duration = Duration::from_secs(3);
/// How often a running catch-up looks at its cancel flag.
const POLL: Duration = Duration::from_millis(100);

/// How a catch-up went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// Every sync finished within the budget.
    pub synced: bool,
    /// The OS took the time back first.
    pub cancelled: bool,
}

/// Wait until `cancel` is set (polled: the flag is set from OS callbacks on
/// any thread).
async fn cancelled(cancel: &AtomicBool) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(POLL).await;
    }
}

/// Run `sync`, then linger for deliveries (`linger`, [`LINGER`] outside
/// tests): all within `budget` (less a margin), and stopping as soon as
/// `cancel` is set.
pub(crate) async fn catch_up(
    sync: impl Future<Output = ()>,
    budget: Duration,
    linger: Duration,
    cancel: &AtomicBool,
) -> Outcome {
    let start = tokio::time::Instant::now();
    let deadline = start + budget.saturating_sub(MARGIN);
    let synced = tokio::select! {
        biased;
        _ = cancelled(cancel) => return Outcome { synced: false, cancelled: true },
        done = tokio::time::timeout_at(deadline, sync) => done.is_ok(),
    };
    let linger_until = deadline.min(tokio::time::Instant::now() + linger);
    tokio::select! {
        biased;
        _ = cancelled(cancel) => Outcome { synced, cancelled: true },
        _ = tokio::time::sleep_until(linger_until) => Outcome { synced, cancelled: false },
    }
}

/// When the last background catch-up that synced finished (ms since the
/// epoch; 0 = none in this process), for the UI: one whose sync the budget
/// or the OS cut short doesn't count.
static LAST_CATCH_UP: AtomicU64 = AtomicU64::new(0);
/// One catch-up at a time: an OS can hand out a refresh and a processing
/// launch together.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Holds [`RUNNING`] for one catch-up, and lets go when dropped, also when
/// the catch-up panics (the OS entry points catch that, and the next launch
/// must still run).
struct Running;

impl Running {
    fn claim() -> Option<Running> {
        (!RUNNING.swap(true, Ordering::AcqRel)).then_some(Running)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Tickets kept at once: a few OS launches overlap at most. A ticket that
/// falls off (never used, or its owner never called back) can no longer be
/// cancelled, and running with it is like running with a fresh one.
const TICKETS: usize = 16;

/// Each catch-up's own cancel flag, by ticket. The OS can take the time
/// back before the catch-up begins (while the runtime opens, or before the
/// queued block runs), and a cancel meant for one launch must not stop
/// another's: so a launch takes a ticket first ([`begin_catch_up`]), and
/// both the catch-up and the cancel name it.
struct Tickets {
    next: u64,
    open: std::collections::VecDeque<(u64, Arc<AtomicBool>)>,
}

static TICKET_FLAGS: Mutex<Tickets> = Mutex::new(Tickets { next: 1, open: std::collections::VecDeque::new() });

fn tickets() -> std::sync::MutexGuard<'static, Tickets> {
    TICKET_FLAGS.lock().unwrap_or_else(|e| e.into_inner())
}

/// A new catch-up ticket (never 0).
pub(crate) fn begin_catch_up() -> u64 {
    let mut t = tickets();
    let ticket = t.next;
    t.next += 1;
    t.open.push_back((ticket, Arc::new(AtomicBool::new(false))));
    if t.open.len() > TICKETS {
        t.open.pop_front();
    }
    ticket
}

/// Forget ticket `ticket`: its catch-up is over.
fn release_ticket(ticket: u64) {
    tickets().open.retain(|(id, _)| *id != ticket);
}

/// Stop the catch-up holding `ticket` now, or as soon as it begins (the OS
/// is taking its time back). Others keep running.
pub(crate) fn cancel_catch_up(ticket: u64) {
    if let Some((_, flag)) = tickets().open.iter().find(|(id, _)| *id == ticket) {
        flag.store(true, Ordering::Release);
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Catch up with the open runtime for at most `budget`, blocking the calling
/// (OS-provided, never the main) thread, under `ticket` from
/// [`begin_catch_up`]. `false` if there is no runtime to catch up with,
/// another catch-up is running, or it was cancelled or cut short.
pub(crate) fn catch_up_now(ticket: u64, budget: Duration) -> bool {
    catch_up_with(ticket, budget, LINGER)
}

fn catch_up_with(ticket: u64, budget: Duration, linger: Duration) -> bool {
    // The flag stays registered while the catch-up runs, so a cancel
    // reaches it; released on the way out (a panic leaves it until it
    // falls off).
    let cancel = flag_for(ticket);
    let result = (|| {
        if cancel.load(Ordering::Acquire) {
            eprintln!("mycel-host: background catch-up cancelled before it began");
            return false;
        }
        let Some(core) = crate::core() else {
            eprintln!("mycel-host: background catch-up skipped: Mycel isn't open");
            return false;
        };
        let Some(_running) = Running::claim() else {
            return false;
        };
        let runtime = core.runtime.clone();
        let started = Instant::now();
        let outcome = tauri::async_runtime::block_on(catch_up(runtime.sync_now(), budget, linger, &cancel));
        if let Err(error) = runtime.flush() {
            eprintln!("mycel-host: background persistence failed: {error}");
        }
        if outcome.synced {
            LAST_CATCH_UP.store(now_ms(), Ordering::Release);
        }
        eprintln!(
            "mycel-host: background catch-up: {} in {:.1} s{}",
            if outcome.synced { "synced" } else { "sync incomplete" },
            started.elapsed().as_secs_f32(),
            if outcome.cancelled { ", cut short by the system" } else { "" }
        );
        outcome.synced && !outcome.cancelled
    })();
    release_ticket(ticket);
    result
}

/// [`catch_up_now`] with a short linger (the host's own tests).
#[cfg(test)]
pub(crate) fn catch_up_for_test(ticket: u64, budget: Duration, linger: Duration) -> bool {
    catch_up_with(ticket, budget, linger)
}

#[cfg(test)]
pub(crate) fn last_catch_up_for_test() -> Option<u64> {
    last_catch_up()
}

/// Ticket `ticket`'s flag, left registered so [`cancel_catch_up`] finds it
/// (a fresh, registered one if it fell off).
fn flag_for(ticket: u64) -> Arc<AtomicBool> {
    let mut t = tickets();
    if let Some((_, flag)) = t.open.iter().find(|(id, _)| *id == ticket) {
        return flag.clone();
    }
    let flag = Arc::new(AtomicBool::new(false));
    t.open.push_back((ticket, flag.clone()));
    if t.open.len() > TICKETS {
        t.open.pop_front();
    }
    flag
}

/// iOS `BGTaskScheduler` launch handlers (main.mm) take a ticket first, on
/// the launch handler's own thread, before the expiration handler can fire.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn mycel_background_begin() -> u64 {
    begin_catch_up()
}

/// The launch, on a background queue, with the seconds it may use. Returns
/// whether the catch-up completed (the task's success).
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn mycel_background_catch_up(ticket: u64, seconds: u32) -> bool {
    std::panic::catch_unwind(|| catch_up_now(ticket, Duration::from_secs(seconds.into()))).unwrap_or(false)
}

/// A `BGTask`'s expiration handler (main.mm): stop that launch's catch-up.
#[cfg(target_os = "ios")]
#[unsafe(no_mangle)]
pub extern "C" fn mycel_background_cancel(ticket: u64) {
    cancel_catch_up(ticket);
}

/// What the Profile panel says about delivery while Mycel is in the
/// background (`backgroundStatus.ts`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundStatus {
    /// `android`, `ios` or `desktop`.
    pub platform: &'static str,
    /// `always`: the runtime keeps running in the background (Android's
    /// service, computers). `slow`: the OS suspends Mycel; it catches up when
    /// the OS lends it time, and delivery may wait until it is opened (iOS).
    pub mode: &'static str,
    /// Android: exempt from battery optimisation (Doze can't pause it).
    pub battery_unrestricted: Option<bool>,
    /// Android: the user restricted Mycel's background use in Settings.
    pub background_restricted: Option<bool>,
    /// Android: the app standby bucket (`active`, `working_set`, `frequent`,
    /// `rare`, `restricted`).
    pub standby_bucket: Option<String>,
    /// Android: the phone's manufacturer, lower case, for the right
    /// battery-settings tip (some vendors stop apps regardless).
    pub manufacturer: Option<String>,
    /// When the last background catch-up that synced finished (ms since the
    /// epoch); one whose sync was cut short doesn't count.
    pub last_catch_up: Option<u64>,
}

/// What `MycelRuntime.backgroundStatus` reports (JSON; `android.rs` reads
/// it). Parsed here so it is tested on every platform.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
struct KotlinStatus {
    battery_unrestricted: Option<bool>,
    background_restricted: Option<bool>,
    standby_bucket: Option<String>,
    manufacturer: Option<String>,
}

impl BackgroundStatus {
    /// The status from `MycelRuntime.backgroundStatus`'s JSON.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub(crate) fn from_android_json(json: &str) -> Result<BackgroundStatus, String> {
        let s: KotlinStatus = serde_json::from_str(json).map_err(|e| format!("background status: {e}"))?;
        Ok(BackgroundStatus {
            platform: "android",
            mode: "always",
            battery_unrestricted: s.battery_unrestricted,
            background_restricted: s.background_restricted,
            standby_bucket: s.standby_bucket,
            manufacturer: s.manufacturer.map(|m| m.trim().to_lowercase()),
            last_catch_up: None,
        })
    }
}

fn last_catch_up() -> Option<u64> {
    Some(LAST_CATCH_UP.load(Ordering::Acquire)).filter(|ms| *ms > 0)
}

#[tauri::command]
pub async fn background_status() -> Result<BackgroundStatus, String> {
    #[cfg(target_os = "android")]
    {
        let mut status = crate::android::background_status()?;
        status.last_catch_up = last_catch_up();
        Ok(status)
    }
    #[cfg(target_os = "ios")]
    return Ok(BackgroundStatus {
        platform: "ios",
        mode: "slow",
        last_catch_up: last_catch_up(),
        ..Default::default()
    });
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Ok(BackgroundStatus { platform: "desktop", mode: "always", ..Default::default() })
}

/// Android: show the system's "let Mycel run in the background" prompt (the
/// UI explains why first). Nothing to ask for elsewhere.
#[tauri::command]
pub async fn request_background_exemption() -> Result<(), String> {
    #[cfg(target_os = "android")]
    return crate::android::request_battery_exemption();
    #[cfg(not(target_os = "android"))]
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn flag() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[tokio::test(start_paused = true)]
    async fn a_quick_sync_lingers_for_deliveries_then_stops() {
        let start = tokio::time::Instant::now();
        let cancel = flag();
        let outcome = catch_up(async {}, Duration::from_secs(30), LINGER, &cancel).await;
        assert_eq!(outcome, Outcome { synced: true, cancelled: false });
        assert_eq!(start.elapsed(), LINGER);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_sync_is_cut_at_the_budget_less_the_margin() {
        let start = tokio::time::Instant::now();
        let cancel = flag();
        let never = std::future::pending::<()>();
        let outcome = catch_up(never, Duration::from_secs(30), LINGER, &cancel).await;
        assert_eq!(outcome, Outcome { synced: false, cancelled: false });
        assert_eq!(start.elapsed(), Duration::from_secs(30) - MARGIN);
    }

    #[tokio::test(start_paused = true)]
    async fn lingering_never_outlives_the_budget() {
        let start = tokio::time::Instant::now();
        let cancel = flag();
        let sync = tokio::time::sleep(Duration::from_secs(20));
        let outcome = catch_up(sync, Duration::from_secs(25), LINGER, &cancel).await;
        assert_eq!(outcome, Outcome { synced: true, cancelled: false });
        assert_eq!(start.elapsed(), Duration::from_secs(25) - MARGIN);
        // A budget smaller than the margin ends at once.
        let start = tokio::time::Instant::now();
        let outcome = catch_up(async {}, Duration::from_secs(1), LINGER, &cancel).await;
        assert!(outcome.synced && start.elapsed() == Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn the_os_taking_time_back_stops_it_promptly() {
        let cancel = flag();
        let setter = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            setter.store(true, Ordering::Release);
        });
        let start = tokio::time::Instant::now();
        let outcome = catch_up(std::future::pending::<()>(), Duration::from_secs(300), LINGER, &cancel).await;
        assert_eq!(outcome, Outcome { synced: false, cancelled: true });
        assert!(start.elapsed() <= Duration::from_secs(2) + POLL);
        // Cancelled while lingering: the sync still counts.
        let cancel = flag();
        let setter = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            setter.store(true, Ordering::Release);
        });
        let outcome = catch_up(async {}, Duration::from_secs(300), LINGER, &cancel).await;
        assert_eq!(outcome, Outcome { synced: true, cancelled: true });
    }

    /// Regression: a cancel that arrives before the catch-up begins (while
    /// the runtime opens, or before iOS runs the queued block) used to be
    /// wiped when the catch-up claimed the shared flag.
    #[test]
    fn a_cancel_before_the_catch_up_begins_ends_it_at_once() {
        let _serial = crate::tests::serial();
        let last = LAST_CATCH_UP.load(Ordering::Acquire);
        let ticket = begin_catch_up();
        cancel_catch_up(ticket);
        let start = Instant::now();
        assert!(!catch_up_with(ticket, Duration::from_secs(300), LINGER));
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(LAST_CATCH_UP.load(Ordering::Acquire), last, "a cancelled catch-up isn't a check");
        assert!(tickets().open.iter().all(|(id, _)| *id != ticket), "its ticket is released");
    }

    /// Regression: one launch's cancel (a worker WorkManager stopped) used to
    /// stop another's catch-up (the service's) through one shared flag.
    #[test]
    fn a_cancel_stops_only_its_own_catch_up() {
        let _serial = crate::tests::serial();
        let (a, b) = (begin_catch_up(), begin_catch_up());
        assert!(a != 0 && a != b);
        let (flag_a, flag_b) = (flag_for(a), flag_for(b));
        cancel_catch_up(a);
        assert!(flag_a.load(Ordering::Acquire));
        assert!(!flag_b.load(Ordering::Acquire), "b keeps running");
        release_ticket(a);
        release_ticket(b);
        // Cancelling a finished (or unknown) ticket does nothing.
        cancel_catch_up(a);
        assert!(!flag_for(a).load(Ordering::Acquire));
        release_ticket(a);
    }

    #[test]
    fn tickets_stay_bounded() {
        let _serial = crate::tests::serial();
        let first = begin_catch_up();
        let later: Vec<u64> = (0..TICKETS * 2).map(|_| begin_catch_up()).collect();
        assert!(tickets().open.len() <= TICKETS);
        // The oldest fell off: cancelling it is a no-op, and a catch-up
        // under it runs like a fresh one.
        cancel_catch_up(first);
        assert!(!flag_for(first).load(Ordering::Acquire));
        for t in later.into_iter().chain([first]) {
            release_ticket(t);
        }
    }

    #[test]
    fn one_catch_up_at_a_time_even_after_a_panic() {
        let _serial = crate::tests::serial();
        let first = Running::claim().expect("nothing running");
        assert!(Running::claim().is_none(), "a second launch waits its turn");
        drop(first);
        let panicked = std::panic::catch_unwind(|| {
            let _running = Running::claim().expect("released");
            panic!("a catch-up failed");
        });
        assert!(panicked.is_err());
        assert!(Running::claim().is_some(), "a panic must not block every later catch-up");
    }

    #[test]
    fn kotlin_status_maps_to_the_ui_status() {
        let status = BackgroundStatus::from_android_json(
            r#"{"batteryUnrestricted":false,"backgroundRestricted":true,"standbyBucket":"restricted","manufacturer":" Xiaomi "}"#,
        )
        .unwrap();
        assert_eq!((status.platform, status.mode), ("android", "always"));
        assert_eq!(status.battery_unrestricted, Some(false));
        assert_eq!(status.background_restricted, Some(true));
        assert_eq!(status.standby_bucket.as_deref(), Some("restricted"));
        assert_eq!(status.manufacturer.as_deref(), Some("xiaomi"));
        assert!(BackgroundStatus::from_android_json("{}").unwrap().battery_unrestricted.is_none());
        assert!(BackgroundStatus::from_android_json("not json").is_err());
    }

    #[test]
    fn status_serializes_for_the_ui() {
        let status = BackgroundStatus {
            platform: "android",
            mode: "always",
            battery_unrestricted: Some(false),
            standby_bucket: Some("rare".into()),
            ..Default::default()
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["batteryUnrestricted"], false);
        assert_eq!(json["standbyBucket"], "rare");
        assert_eq!(json["lastCatchUp"], serde_json::Value::Null);
    }
}
