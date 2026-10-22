//! In-code fault injection for simulation, after FoundationDB's `BUGGIFY`
//! (<https://apple.github.io/foundationdb/testing.html>): a call site
//! `buggify!("purpose", entity)` marks a rare but legal path (a dial that
//! fails, a queue that is full, a stream the peer never read, a timer that
//! fires late) and, in a simulation that turned it on, takes it now and
//! then, so the code around it is exercised where the medium's faults
//! rarely reach. `entity` is the 32-byte public key of the device whose
//! code is running (the pool's endpoint, the mesh driver's own key).
//!
//! **Compiled out** without the `sim` feature: the macro is the constant
//! `false`, the branch it guards is dead code, the entity expression is
//! never evaluated, and no purpose string reaches the binary
//! (`tests::compiled_out_of_default_builds` checks the test binary itself).
//! No release build turns the feature on (`scripts/ci/check-release-features.sh`
//! fails the app builds if one would).
//!
//! **Runs.** With the feature, nothing fires until a [`Run`] (only with
//! the `sim` feature) registers a device: a site fires only for devices
//! that a live run registered, so tests that run side by side in one
//! process, or simulations of different seeds on different threads, don't
//! inject faults into each other. Each device carries a run-chosen label
//! (its index in the scenario, not its random key), so a rerun with fresh
//! keys makes the same choices. Dropping the run unregisters its devices.
//!
//! **When it fires.** As in FoundationDB, each site is active for a whole
//! run with probability 1/4 and an active site fires on 1/4 of its
//! evaluations (FoundationDB's defaults, `P_BUGGIFIED_SECTION_ACTIVATED`
//! and `P_BUGGIFIED_SECTION_FIRES`, both 0.25 in
//! `flow/include/flow/Buggify.h`). Every draw is a common random number
//! keyed by (seed, purpose, entity label, k), with k the number of times
//! that site was evaluated for that device before in this run
//! (docs/SIMULATION.md, "Common random numbers"; sim-fidelity design §8
//! item 1): two runs of one seed make the same choices for a device at
//! every site it reaches the same number of times, however the other
//! devices' evaluations interleave with its own, and whatever earlier runs
//! in the same process did.

#[cfg(feature = "sim")]
mod imp {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;

    /// Sites active per run, and evaluations an active site fires on, in 1/256.
    const ACTIVE_256: u64 = 64;
    const FIRES_256: u64 = 64;

    /// What the macro puts before a site's purpose (the marker the
    /// compiled-out test looks for).
    const PREFIX: &str = "mycel-buggify-site:";

    /// SplitMix64's finaliser: a bijective mix with full avalanche.
    fn mix(mut x: u64) -> u64 {
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    /// FNV-1a: a stable hash of the site (`std`'s hasher may change).
    fn hash(site: &str) -> u64 {
        site.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ b as u64).wrapping_mul(0x0100_0000_01b3))
    }

    fn is_active(seed: u64, site: &str) -> bool {
        mix(seed ^ hash(site)) & 0xff < ACTIVE_256
    }

    fn draw(seed: u64, site: &str, label: u64, k: u64) -> bool {
        mix(mix(mix(seed ^ hash(site)) ^ label) ^ k) & 0xff < FIRES_256
    }

    /// Whether the site for `purpose` (as written at the call site) is
    /// active in a run with `seed` (made with [`Run::new`]).
    pub fn active(seed: u64, purpose: &str) -> bool {
        is_active(seed, &format!("{PREFIX}{purpose}"))
    }

    /// Whether the `k`th evaluation (from 0) of the site for `purpose`, if
    /// active, fires on the device labelled `label` in a run with `seed`:
    /// lets a test pick a seed whose run takes the paths it needs.
    pub fn fires(seed: u64, purpose: &str, label: u64, k: u64) -> bool {
        draw(seed, &format!("{PREFIX}{purpose}"), label, k)
    }

    struct RunState {
        seed: u64,
        every_site: bool,
        fired: Mutex<BTreeMap<&'static str, u64>>,
    }

    struct Device {
        run: Arc<RunState>,
        label: u64,
        /// Evaluations so far, per site.
        evals: HashMap<&'static str, u64>,
    }

    /// Devices registered by live runs, by public key.
    static DEVICES: Mutex<Option<HashMap<[u8; 32], Device>>> = Mutex::new(None);
    /// How many there are: with none, a site returns without locking.
    static LIVE: AtomicUsize = AtomicUsize::new(0);

    /// One simulation run with injection on: the seed its draws are keyed
    /// by and the devices it covers. Faults stop when it is dropped.
    pub struct Run {
        state: Arc<RunState>,
        keys: Mutex<Vec<[u8; 32]>>,
    }

    impl Run {
        /// A run with this seed, covering no device yet.
        pub fn new(seed: u64) -> Run {
            Run {
                state: Arc::new(RunState { seed, every_site: false, fired: Mutex::default() }),
                keys: Mutex::default(),
            }
        }

        /// Every site active (each still fires on 1/4 of its evaluations):
        /// for a test that must reach every injected path in one run.
        pub fn every_site(seed: u64) -> Run {
            Run {
                state: Arc::new(RunState { seed, every_site: true, fired: Mutex::default() }),
                keys: Mutex::default(),
            }
        }

        /// Inject faults into the device with public key `key`, labelled
        /// `label` for the draws (stable across reruns: its index, say).
        ///
        /// # Panics
        ///
        /// If a live run already covers that device.
        pub fn add(&self, key: [u8; 32], label: u64) {
            let mut devices = DEVICES.lock();
            let map = devices.get_or_insert_with(HashMap::new);
            assert!(!map.contains_key(&key), "buggify: a device can be in one run only");
            map.insert(key, Device { run: self.state.clone(), label, evals: HashMap::new() });
            LIVE.fetch_add(1, Ordering::SeqCst);
            self.keys.lock().push(key);
        }

        /// Times each site fired in this run, by purpose (with the
        /// macro's `mycel-buggify-site:` marker before it).
        pub fn fired(&self) -> BTreeMap<&'static str, u64> {
            self.state.fired.lock().clone()
        }

        /// Times any site fired in this run.
        pub fn fired_total(&self) -> u64 {
            self.state.fired.lock().values().sum()
        }
    }

    impl Drop for Run {
        fn drop(&mut self) {
            let mut devices = DEVICES.lock();
            if let Some(map) = devices.as_mut() {
                for k in self.keys.lock().drain(..) {
                    if map.remove(&k).is_some() {
                        LIVE.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            }
        }
    }

    /// One evaluation of the site for `purpose` on device `key` (what the
    /// macro expands to).
    pub fn fire(purpose: &'static str, key: &[u8; 32]) -> bool {
        if LIVE.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let mut devices = DEVICES.lock();
        let Some(d) = devices.as_mut().and_then(|m| m.get_mut(key)) else {
            return false;
        };
        let seed = d.run.seed;
        if !d.run.every_site && !is_active(seed, purpose) {
            return false;
        }
        let k = d.evals.entry(purpose).or_insert(0);
        let fire = draw(seed, purpose, d.label, *k);
        *k += 1;
        if fire {
            *d.run.fired.lock().entry(purpose).or_insert(0) += 1;
        }
        fire
    }
}

#[cfg(feature = "sim")]
pub use imp::{Run, active, fire, fires};

/// `buggify!("purpose", entity)`: whether to take the rare path here now
/// on the device whose 32-byte public key `entity` is. The purpose names a
/// behaviour the real system can show; see the module docs.
#[cfg(feature = "sim")]
macro_rules! buggify {
    ($purpose:literal, $entity:expr) => {
        $crate::buggify::fire(concat!("mycel-buggify-site:", $purpose), $entity)
    };
}

/// `buggify!("purpose", entity)`: the constant `false` without the `sim`
/// feature (`entity` is not evaluated).
#[cfg(not(feature = "sim"))]
macro_rules! buggify {
    ($purpose:literal, $entity:expr) => {
        false
    };
}

pub(crate) use buggify;

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "sim"))]
    #[test]
    fn compiled_out_of_default_builds() {
        const { assert!(!buggify!("test: never", &[0u8; 32])) };
        // No site's purpose string is in this binary, which links every
        // module of the crate. The needle is built at run time from its
        // reverse, so this test doesn't put it there itself (two halves can
        // end up side by side in the binary).
        let needle: String = ":etis-yfiggub-lecym".chars().rev().collect();
        let exe = std::fs::read(std::env::current_exe().expect("own path")).expect("own binary");
        assert!(
            !exe.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "a buggify site was compiled into a build without the `sim` feature"
        );
    }

    #[cfg(feature = "sim")]
    mod sim {
        use super::super::{Run, active};

        /// One real call site (the macro, as the crate's code uses it).
        fn site(entity: &[u8; 32]) -> bool {
            buggify!("test: a", entity)
        }

        const PURPOSE: &str = "test: a";

        fn key(tag: u8, i: u8) -> [u8; 32] {
            let mut k = [tag; 32];
            k[31] = i;
            k
        }

        /// `seed` with the test site active.
        fn active_seed() -> u64 {
            (1..u64::MAX).find(|s| active(*s, PURPOSE)).expect("some seed")
        }

        /// A run of `seed` over two devices with fresh keys (`tag`), the
        /// evaluations of the second interleaved with the first's as
        /// `interleave` says; each device's choices.
        fn run(seed: u64, tag: u8, interleave: &[bool]) -> (Vec<bool>, Vec<bool>, u64) {
            let r = Run::new(seed);
            let (a, b) = (key(tag, 0), key(tag, 1));
            r.add(a, 0);
            r.add(b, 1);
            let (mut va, mut vb) = (Vec::new(), Vec::new());
            for &second in interleave {
                if second { vb.push(site(&b)) } else { va.push(site(&a)) }
            }
            (va, vb, r.fired_total())
        }

        #[test]
        fn same_seed_same_choices_in_one_process() {
            let seed = active_seed();
            let even: Vec<bool> = (0..512).map(|i| i % 2 == 1).collect();
            // the second run: other keys, the other device's evaluations
            // bunched differently
            let bunched: Vec<bool> = (0..512).map(|i| i >= 256).collect();
            let first = run(seed, 0xa0, &even);
            let second = run(seed, 0xa1, &bunched);
            assert_eq!(first.0, second.0, "device 0: same seed, same choices, rerun in the same process");
            assert_eq!(first.1, second.1, "device 1: likewise, whatever the interleaving");
            assert_ne!(first.0, first.1, "devices draw independently");
            let n = first.0.iter().filter(|x| **x).count();
            assert!((32..=96).contains(&n), "fires on about 1/4 of evaluations: {n}/256");
            assert_eq!(first.2 as usize, first.0.iter().chain(&first.1).filter(|x| **x).count());
        }

        #[test]
        fn concurrent_runs_dont_disturb_each_other() {
            let seed = active_seed();
            let alone = run(seed, 0xb0, &[false; 256]).0;
            // eight runs of the same seed at once, on threads, and devices
            // no run covers evaluating the site all the while
            let stop = std::sync::atomic::AtomicBool::new(false);
            std::thread::scope(|s| {
                s.spawn(|| {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        assert!(!site(&key(0xbf, 0)), "a device no run covers never fires");
                    }
                });
                let runs: Vec<_> = (0..8u8).map(|t| s.spawn(move || run(seed, 0xb1 + t, &[false; 256]).0)).collect();
                for r in runs {
                    assert_eq!(r.join().expect("run"), alone, "a concurrent run of the seed chose the same");
                }
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
            });
        }

        #[test]
        fn inactive_sites_and_dropped_runs_never_fire() {
            let inactive = (1..u64::MAX).find(|s| !active(*s, PURPOSE)).expect("some seed");
            let (a, b, fired) = run(inactive, 0xc0, &[false, true].repeat(128));
            assert!(a.iter().chain(&b).all(|x| !x) && fired == 0, "an inactive site never fires");
            let r = Run::every_site(inactive);
            r.add(key(0xc1, 0), 0);
            assert!((0..256).any(|_| site(&key(0xc1, 0))), "every_site turns it on");
            drop(r);
            assert!((0..256).all(|_| !site(&key(0xc1, 0))), "nothing fires once the run is dropped");
            // and the device can join a new run
            let r = Run::new(inactive);
            r.add(key(0xc1, 0), 0);
        }
    }
}
