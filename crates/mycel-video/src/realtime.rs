//! Real-time scheduling for media threads.
//!
//! A call's media threads wake every few milliseconds to move audio between
//! the device and the network, and a test camera wakes once a frame. They
//! must wake on time. On Apple platforms an ordinary thread can't count on
//! that: the kernel coalesces timers to save power, and the slack it allows
//! grows with the process's quality of service. Measured on an M-series Mac
//! (`thread::sleep`, 200 samples): asking for 3 ms takes 4.5 ms in a normal
//! process, but 17–27 ms (p50–p90, up to 66 ms) once the process is
//! throttled to the utility class, as an app in the background or a CI
//! runner's job can be; 10 ms takes 66–90 ms. A call's playout keeps only
//! ~25 ms queued, so wake-ups that late starve the speaker and the delay
//! piles up in the jitter buffer.
//!
//! [`promote_current_thread`] gives the calling thread the time-constraint
//! (real-time) policy, which is what Core Audio gives its own I/O threads.
//! Measured the same way, a real-time thread's 3 ms sleep takes 3.01 ms
//! (p99 3.04 ms) whether or not the process is throttled. A thread that
//! uses more than its declared `computation` per `period` is preempted
//! (the policy is set preemptible), and one that hogs the CPU is demoted by
//! the kernel's real-time fail-safe, so a bug can't freeze the machine.
//! A process in the darwin background band (`taskpolicy -b`) stays
//! throttled even so: real-time is a request, not a guarantee.
//!
//! Elsewhere this does nothing and returns `false`: Linux timers already
//! wake within ~50 µs of the deadline for ordinary threads (real-time
//! priority there needs privileges or a session broker such as rtkit), and
//! Rust's sleep on Windows uses high-resolution waitable timers. Tests of
//! the call engine pass on both without it.

use std::time::Duration;

/// Ask for real-time scheduling of the calling thread: it wakes at least
/// every `period` and needs about `computation` of CPU each time. Returns
/// whether the OS accepted it. Call it at the top of the thread, before its
/// loop.
pub fn promote_current_thread(period: Duration, computation: Duration) -> bool {
    imp::promote(period, computation)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    use std::time::Duration;

    use mach2::kern_return::KERN_SUCCESS;
    use mach2::mach_time::{mach_timebase_info, mach_timebase_info_data_t};
    use mach2::thread_policy::{
        THREAD_TIME_CONSTRAINT_POLICY, THREAD_TIME_CONSTRAINT_POLICY_COUNT, thread_policy_set,
        thread_time_constraint_policy_data_t,
    };

    /// XNU accepts a computation between 50 µs and 50 ms.
    const MIN_COMPUTATION: Duration = Duration::from_micros(50);
    const MAX_COMPUTATION: Duration = Duration::from_millis(50);

    pub fn promote(period: Duration, computation: Duration) -> bool {
        let computation = computation.clamp(MIN_COMPUTATION, MAX_COMPUTATION);
        // the deadline is the end of the period; never shorter than the work
        let period = period.max(computation);
        let mut tb = mach_timebase_info_data_t::default();
        // SAFETY: mach_timebase_info only writes the struct it's given.
        if unsafe { mach_timebase_info(&mut tb) } != KERN_SUCCESS || tb.numer == 0 {
            return false;
        }
        // nanoseconds → Mach absolute time units
        let ticks = |d: Duration| -> u32 {
            let t = d.as_nanos() * u128::from(tb.denom) / u128::from(tb.numer);
            u32::try_from(t).unwrap_or(u32::MAX)
        };
        let mut policy = thread_time_constraint_policy_data_t {
            period: ticks(period),
            computation: ticks(computation),
            constraint: ticks(period),
            preemptible: 1,
        };
        // SAFETY: pthread_mach_thread_np returns the calling thread's port
        // without taking a reference (nothing to deallocate), and
        // thread_policy_set reads exactly COUNT integers from `policy`.
        let rc = unsafe {
            thread_policy_set(
                libc::pthread_mach_thread_np(libc::pthread_self()),
                THREAD_TIME_CONSTRAINT_POLICY,
                (&mut policy as *mut thread_time_constraint_policy_data_t).cast(),
                THREAD_TIME_CONSTRAINT_POLICY_COUNT,
            )
        };
        rc == KERN_SUCCESS
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
mod imp {
    use std::time::Duration;

    pub fn promote(_period: Duration, _computation: Duration) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On Apple platforms a promoted thread wakes on time even when the
    /// process is throttled (try it: `taskpolicy -c utility` on the test
    /// binary). This is what the call engine and the test camera rely on.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn promoted_thread_wakes_on_time() {
        use std::time::Instant;

        let late = std::thread::spawn(|| {
            assert!(promote_current_thread(Duration::from_millis(10), Duration::from_millis(1)));
            let mut late: Vec<Duration> = (0..100)
                .map(|_| {
                    let t = Instant::now();
                    std::thread::sleep(Duration::from_millis(3));
                    t.elapsed().saturating_sub(Duration::from_millis(3))
                })
                .collect();
            late.sort();
            late
        })
        .join()
        .unwrap();
        // p90: a CI machine may still preempt us now and then
        assert!(late[90] < Duration::from_millis(2), "3 ms sleeps woke up to {:?} late (p90)", late[90]);
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn promotion_is_a_no_op_elsewhere() {
        assert!(!promote_current_thread(Duration::from_millis(10), Duration::from_millis(1)));
    }

    /// Out-of-range requests are clamped into what the kernel accepts, not refused.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn odd_requests_are_clamped() {
        for (period, computation) in [(0, 0), (1, 5), (20, 200), (1000, 1)] {
            let ok = std::thread::spawn(move || {
                promote_current_thread(Duration::from_millis(period), Duration::from_millis(computation))
            })
            .join()
            .unwrap();
            assert!(ok, "period {period} ms, computation {computation} ms");
        }
    }
}
