//! In-code fault injection for simulation, after FoundationDB's `BUGGIFY`
//! (<https://apple.github.io/foundationdb/testing.html>): a call site
//! `buggify!("purpose")` marks a rare but legal path (a dial that fails, a
//! queue that is full, a stream the peer never read, a timer that fires
//! late) and, in a simulation that turned it on, takes it now and then, so
//! the code around it is exercised where the medium's faults rarely reach.
//!
//! **Compiled out** without the `sim` feature: the macro is the constant
//! `false`, the branch it guards is dead code, and no purpose string
//! reaches the binary (`tests::compiled_out_of_default_builds` checks the
//! test binary itself). With the feature, nothing fires until `buggify::enable`.
//! No release build turns the feature on.
//!
//! **When it fires.** As in FoundationDB, each site is active for a whole
//! run with probability 1/4 and an active site fires on 1/4 of its
//! evaluations (FoundationDB's defaults, `P_BUGGIFIED_SECTION_ACTIVATED`
//! and `P_BUGGIFIED_SECTION_FIRES`, both 0.25 in
//! `flow/include/flow/Buggify.h`). Every draw is a common
//! random number keyed by (seed, purpose, k), with k the site's own
//! evaluation count (docs/SIMULATION.md, "Common random numbers"): two runs
//! of one seed make the same choices at every site that is reached the
//! same number of times, whatever happens elsewhere.

#[cfg(feature = "sim")]
mod imp {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static SEED: AtomicU64 = AtomicU64::new(0);
    static FIRED: AtomicU64 = AtomicU64::new(0);

    /// Sites active per run, and evaluations an active site fires on, in 1/256.
    const ACTIVE_256: u64 = 64;
    const FIRES_256: u64 = 64;

    /// SplitMix64's finaliser: a bijective mix with full avalanche.
    fn mix(mut x: u64) -> u64 {
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    fn hash(s: &str) -> u64 {
        s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
    }

    /// Turn injection on for a run with this seed.
    pub fn enable(seed: u64) {
        SEED.store(seed, Ordering::SeqCst);
        FIRED.store(0, Ordering::SeqCst);
        ENABLED.store(true, Ordering::SeqCst);
    }

    /// Turn it off again.
    pub fn disable() {
        ENABLED.store(false, Ordering::SeqCst);
    }

    /// Times any site fired since [`enable`].
    pub fn fired() -> u64 {
        FIRED.load(Ordering::Relaxed)
    }

    /// Whether the site for `purpose` is active in the run with `seed`.
    pub fn active(seed: u64, purpose: &str) -> bool {
        mix(seed ^ hash(purpose)) & 0xff < ACTIVE_256
    }

    /// One injection site (the macro makes one static per call site).
    pub struct Site {
        purpose: &'static str,
        evals: AtomicU64,
    }

    impl Site {
        pub const fn new(purpose: &'static str) -> Site {
            Site { purpose, evals: AtomicU64::new(0) }
        }

        pub fn fire(&self) -> bool {
            if !ENABLED.load(Ordering::Relaxed) {
                return false;
            }
            let seed = SEED.load(Ordering::Relaxed);
            if !active(seed, self.purpose) {
                return false;
            }
            let k = self.evals.fetch_add(1, Ordering::Relaxed);
            let fire = mix(mix(seed ^ hash(self.purpose)) ^ k) & 0xff < FIRES_256;
            if fire {
                FIRED.fetch_add(1, Ordering::Relaxed);
            }
            fire
        }
    }
}

#[cfg(feature = "sim")]
pub use imp::{Site, active, disable, enable, fired};

/// `buggify!("purpose")`: whether to take the rare path here now. The
/// purpose names a behaviour the real system can show; see the module docs.
#[cfg(feature = "sim")]
macro_rules! buggify {
    ($purpose:literal) => {{
        static SITE: $crate::buggify::Site = $crate::buggify::Site::new(concat!("mycel-buggify-site:", $purpose));
        SITE.fire()
    }};
}

/// `buggify!("purpose")`: the constant `false` without the `sim` feature.
#[cfg(not(feature = "sim"))]
macro_rules! buggify {
    ($purpose:literal) => {
        false
    };
}

pub(crate) use buggify;

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "sim"))]
    #[test]
    fn compiled_out_of_default_builds() {
        const { assert!(!buggify!("test: never")) };
        // No site's purpose string is in this binary, which links every
        // module of the crate (the needle is built at run time, so this
        // test's own source doesn't put it there).
        let needle = ["mycel-buggify", "-site:"].concat();
        let exe = std::fs::read(std::env::current_exe().expect("own path")).expect("own binary");
        assert!(
            !exe.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "a buggify site was compiled into a build without the `sim` feature"
        );
    }

    #[cfg(feature = "sim")]
    #[test]
    fn fires_only_when_enabled_and_reproducibly() {
        use super::{Site, active, disable, enable};
        // (one test: enabling is process-wide)
        disable();
        assert!(!buggify!("test: off"));
        let seed = (0..u64::MAX).find(|s| active(*s, "mycel-buggify-site:test: a")).expect("some seed");
        let run = |seed: u64| {
            enable(seed);
            let site = Site::new("mycel-buggify-site:test: a");
            let v: Vec<bool> = (0..256).map(|_| site.fire()).collect();
            disable();
            v
        };
        let (a, b) = (run(seed), run(seed));
        assert_eq!(a, b, "same seed, same choices");
        let n = a.iter().filter(|x| **x).count();
        assert!((32..=96).contains(&n), "fires on about 1/4 of evaluations: {n}/256");
        let inactive = (0..u64::MAX).find(|s| !active(*s, "mycel-buggify-site:test: a")).expect("some seed");
        assert!(run(inactive).iter().all(|x| !x), "an inactive site never fires");
    }
}
