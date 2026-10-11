//! Identity provisioning is a durable, fail-closed protocol. iOS uses the
//! device-only Keychain; other platforms deliberately retain the file backend.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use mycel_crypto::{DeviceKeys, random};
use serde::{Deserialize, Serialize};

const SEED: &str = "identity.key";
const MARKER: &str = "identity-state.json";
const LOCK: &str = ".identity.lock";

/// A process-wide, OS-released profile lease, held until the runtime is dropped.
/// Never remove this file: unlinking a locked inode defeats mutual exclusion.
pub(crate) struct ProfileLock(File);

impl ProfileLock {
    pub(crate) fn acquire(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).context("create profile directory")?;
        let meta = fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            bail!("profile directory must be a real directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(dir)
                .context("open real profile directory")?;
            directory
                .set_permissions(fs::Permissions::from_mode(0o700))
                .context("restrict profile permissions")?;
            directory
                .sync_all()
                .context("persist private profile permissions")?;
        }
        let path = dir.join(LOCK);
        reject_nonregular(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        private_options(&mut options);
        let file = options.open(path).context("open profile lock")?;
        if !file.metadata()?.is_file() {
            bail!("profile lock must be a regular file");
        }
        file.try_lock()
            .context("profile is already open or cannot be locked")?;
        Ok(Self(file))
    }
}

impl Drop for ProfileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn private_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the link itself, not its target.
        options.custom_flags(0x00200000);
    }
}

fn reject_nonregular(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            bail!("{} must be a regular file, not a link", path.display())
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("inspect {}", path.display())),
    }
}

/// Only NotFound is absence. Bounds prevent corrupt files consuming memory.
pub(crate) fn read_optional(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    reject_nonregular(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    private_options(&mut options);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if !file.metadata()?.is_file() {
        bail!("{} must be a regular file", path.display());
    }
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("{} exceeds its expected size", path.display());
    }
    Ok(Some(bytes))
}

fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(dir)?
        .sync_all()
        .context("persist profile directory")?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Write a private, unpredictable create-new file; sync contents before the
/// atomic install and sync the directory afterwards. Identity creation uses a
/// no-clobber install, so even an uncooperative writer cannot replace
/// the seed. Replacement is only for nonsecret markers/settings under our lock.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let dir = path.parent().context("file has no parent")?;
    reject_nonregular(path)?;
    let name = path
        .file_name()
        .context("file has no name")?
        .to_str()
        .context("identity/settings filename is not UTF-8")?;
    let temporary = dir.join(format!(".{name}-tmp-{}", hex::encode(random::<16>())));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_options(&mut options);
    let mut file = options
        .open(&temporary)
        .context("create private temporary file")?;
    // On error, leave recoverable bytes rather than hiding an incomplete
    // provisioning attempt. A later open fails closed if no seed was installed.
    file.write_all(bytes)?;
    file.sync_all()
        .context("persist identity/settings contents")?;
    drop(file);
    reject_nonregular(path)?;
    if replace {
        fs::rename(&temporary, path).context("install identity/settings state")?;
    } else {
        install_new(&temporary, path)?;
    }
    sync_dir(dir)
}

fn install_new(temporary: &Path, path: &Path) -> Result<()> {
    #[cfg(target_vendor = "apple")]
    {
        use std::os::unix::ffi::OsStrExt;
        let source = std::ffi::CString::new(temporary.as_os_str().as_bytes())?;
        let destination = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        // An atomic exclusive rename avoids a crash window with an extra seed
        // hard link that would survive iOS Keychain migration cleanup.
        let result = unsafe {
            libc::renameatx_np(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("install identity without replacing an existing file");
        }
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        fs::hard_link(temporary, path)
            .context("install identity without replacing an existing file")?;
        fs::remove_file(temporary)?;
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    backend: Backend,
    state: State,
    account: Option<String>,
    public_key: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Backend {
    File,
    IosKeychain,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Pending,
    Committed,
}

impl Marker {
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported identity marker version");
        }
        match (self.backend, self.state, self.account.as_deref()) {
            (Backend::File, State::Committed, None) => Ok(()),
            (Backend::IosKeychain, _, Some(account))
                if account.len() == 64 && account.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                Ok(())
            }
            _ => bail!("corrupt identity marker"),
        }
    }
    fn verify(&self, seed: [u8; 32]) -> Result<DeviceKeys> {
        let keys = DeviceKeys::from_seed(seed);
        if keys.sign_pk().0 != self.public_key {
            bail!("identity public-key binding mismatch; existing identity was preserved");
        }
        Ok(keys)
    }
}

// Isolate durable filesystem operations from the migration protocol, so tests
// can crash at each durable boundary without ever touching the real Keychain.
trait ProfileStorage {
    fn read_seed(&self) -> Result<Option<[u8; 32]>>;
    fn read_marker(&self) -> Result<Option<Marker>>;
    fn is_pristine(&self) -> Result<bool>;
    fn write_seed(&mut self, seed: [u8; 32]) -> Result<()>;
    fn write_marker(&mut self, marker: &Marker, replace: bool) -> Result<()>;
    #[cfg(any(target_os = "ios", test))]
    fn remove_seed(&mut self) -> Result<()>;
}

struct DiskProfile<'a>(&'a Path);
impl ProfileStorage for DiskProfile<'_> {
    fn read_seed(&self) -> Result<Option<[u8; 32]>> {
        // Never complete a migration while an interrupted provisioning attempt
        // leaves a second raw seed behind. Marker/settings temporaries contain
        // no secret and do not prevent the durable protocol from resuming.
        for entry in fs::read_dir(self.0)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".identity.key-tmp-") || name == "identity.tmp" {
                bail!(
                    "interrupted identity provisioning requires recovery; existing files were preserved"
                );
            }
        }
        read_optional(&self.0.join(SEED), 32)?
            .map(|b| {
                b.try_into()
                    .map_err(|_| anyhow::anyhow!("identity.key is corrupt"))
            })
            .transpose()
    }
    fn read_marker(&self) -> Result<Option<Marker>> {
        read_optional(&self.0.join(MARKER), 4096)?
            .map(|b| {
                let marker: Marker =
                    serde_json::from_slice(&b).context("corrupt identity marker")?;
                marker.validate()?;
                Ok(marker)
            })
            .transpose()
    }
    fn is_pristine(&self) -> Result<bool> {
        for entry in fs::read_dir(self.0)? {
            if entry?.file_name() != LOCK {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn write_seed(&mut self, seed: [u8; 32]) -> Result<()> {
        atomic_write(&self.0.join(SEED), &seed, false)
    }
    fn write_marker(&mut self, marker: &Marker, replace: bool) -> Result<()> {
        atomic_write(&self.0.join(MARKER), &serde_json::to_vec(marker)?, replace)
    }
    #[cfg(any(target_os = "ios", test))]
    fn remove_seed(&mut self) -> Result<()> {
        reject_nonregular(&self.0.join(SEED))?;
        fs::remove_file(self.0.join(SEED)).context("remove migrated file seed")?;
        sync_dir(self.0)
    }
}

/// The lease is required at the call site and retained by Runtime.
pub(crate) fn load(dir: &Path, _lease: &ProfileLock) -> Result<DeviceKeys> {
    let mut profile = DiskProfile(dir);
    #[cfg(target_os = "ios")]
    return load_keychain(&mut profile, &mut ios::Keychain);
    #[cfg(not(target_os = "ios"))]
    load_file(&mut profile)
}

fn initial_seed(profile: &mut impl ProfileStorage) -> Result<[u8; 32]> {
    if let Some(seed) = profile.read_seed()? {
        return Ok(seed);
    }
    if !profile.is_pristine()? {
        bail!("identity is missing from an existing profile; refusing to generate a replacement");
    }
    let seed = random::<32>();
    // A new Keychain identity first has a recoverable durable seed. Never
    // regenerate it after a failed pending-marker write or Keychain operation.
    profile.write_seed(seed)?;
    Ok(seed)
}

#[cfg_attr(target_os = "ios", allow(dead_code))]
fn load_file(profile: &mut impl ProfileStorage) -> Result<DeviceKeys> {
    if let Some(marker) = profile.read_marker()? {
        marker.validate()?;
        if marker.backend != Backend::File {
            bail!("this identity requires the iOS Keychain");
        }
        let seed = profile
            .read_seed()?
            .context("identity missing from existing profile")?;
        return marker.verify(seed);
    }
    let seed = initial_seed(profile)?;
    let keys = DeviceKeys::from_seed(seed);
    profile.write_marker(
        &Marker {
            version: 1,
            backend: Backend::File,
            state: State::Committed,
            account: None,
            public_key: keys.sign_pk().0,
        },
        false,
    )?;
    Ok(keys)
}

#[cfg(any(target_os = "ios", test))]
trait SecretStorage {
    /// Creates only. Duplicate slots must be read and compared, never updated.
    fn add(&mut self, account: &str, seed: [u8; 32]) -> Result<()>;
    fn read(&self, account: &str) -> Result<Option<[u8; 32]>>;
}

#[cfg(any(target_os = "ios", test))]
fn load_keychain(
    profile: &mut impl ProfileStorage,
    secrets: &mut impl SecretStorage,
) -> Result<DeviceKeys> {
    let existing = profile.read_marker()?;
    if let Some(marker) = &existing {
        marker.validate()?;
    }
    let mut marker = match existing {
        Some(marker) if marker.backend == Backend::IosKeychain => marker,
        file_marker => {
            let seed = if let Some(marker) = &file_marker {
                let seed = profile
                    .read_seed()?
                    .context("identity missing from existing profile")?;
                marker.verify(seed)?;
                seed
            } else {
                initial_seed(profile)?
            };
            let marker = Marker {
                version: 1,
                backend: Backend::IosKeychain,
                state: State::Pending,
                account: Some(hex::encode(random::<32>())),
                public_key: DeviceKeys::from_seed(seed).sign_pk().0,
            };
            // Account reference is stable across container moves, and durable
            // before a Keychain slot is created. It contains no seed material.
            profile.write_marker(&marker, file_marker.is_some())?;
            marker
        }
    };
    let account = marker
        .account
        .as_deref()
        .context("missing Keychain account reference")?;
    let legacy = profile.read_seed()?;
    if let Some(seed) = legacy {
        marker.verify(seed)?;
    }
    if marker.state == State::Pending {
        if let Some(seed) = legacy {
            secrets.add(account, seed)?;
        }
        let seed = secrets
            .read(account)?
            .context("pending Keychain identity is missing")?;
        marker.verify(seed)?;
        if legacy.is_some_and(|old| old != seed) {
            bail!("Keychain identity conflicts with existing seed");
        }
        marker.state = State::Committed;
        profile.write_marker(&marker, true)?;
    }
    // A committed marker never permits fallback, re-add, or identity creation.
    let seed = secrets
        .read(account)?
        .context("committed Keychain identity is missing")?;
    let keys = marker.verify(seed)?;
    if let Some(old) = legacy {
        if old != seed {
            bail!("Keychain identity conflicts with existing seed");
        }
        profile.remove_seed()?;
    }
    Ok(keys)
}

#[cfg(target_os = "ios")]
mod ios {
    use super::*;
    use core_foundation::{
        base::TCFType, data::CFData, dictionary::CFDictionary, string::CFString,
    };
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{PasswordOptions, generic_password};
    use security_framework_sys::{
        base::{errSecDuplicateItem, errSecItemNotFound},
        item::*,
        keychain_item::SecItemAdd,
    };

    const SERVICE: &str = "app.mycel.device-identity.v1";
    pub(super) struct Keychain;

    fn options(account: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, account);
        options.set_access_synchronized(Some(false));
        options
    }

    impl SecretStorage for Keychain {
        fn add(&mut self, account: &str, seed: [u8; 32]) -> Result<()> {
            let mut options = options(account);
            options.set_access_control(
                SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                    0,
                )
                .context("create device-only Keychain protection")?,
            );
            // The high-level password setter upserts. Build the add dictionary
            // explicitly so a duplicate can never overwrite an existing seed.
            #[allow(deprecated)]
            let query = {
                options.query.push((
                    unsafe { CFString::wrap_under_get_rule(kSecValueData) },
                    CFData::from_buffer(&seed).into_CFType(),
                ));
                CFDictionary::from_CFType_pairs(&options.query)
            };
            let status = unsafe { SecItemAdd(query.as_concrete_TypeRef(), std::ptr::null_mut()) };
            match status {
                0 => Ok(()),
                code if code == errSecDuplicateItem => {
                    if self.read(account)? == Some(seed) {
                        Ok(())
                    } else {
                        bail!("existing Keychain identity conflicts; no item was changed")
                    }
                }
                _ => bail!("Keychain identity creation failed (status {status})"),
            }
        }
        fn read(&self, account: &str) -> Result<Option<[u8; 32]>> {
            match generic_password(options(account)) {
                Ok(bytes) => {
                    Ok(Some(bytes.try_into().map_err(|_| {
                        anyhow::anyhow!("corrupt Keychain identity")
                    })?))
                }
                Err(e) if e.code() == errSecItemNotFound => Ok(None),
                Err(e) => bail!("Keychain identity unavailable (status {})", e.code()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    // Unit tests never access a device Keychain, even when built for iOS.
    fn load(dir: &Path, _lease: &ProfileLock) -> Result<DeviceKeys> {
        load_file(&mut DiskProfile(dir))
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "mycel-identity-test-{}",
                hex::encode(random::<16>())
            ));
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn file_roundtrip_and_no_replacement_after_seed_loss() {
        let dir = TestDir::new();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        let pk = load(&dir.0, &lease).unwrap().sign_pk();
        assert_eq!(load(&dir.0, &lease).unwrap().sign_pk(), pk);
        fs::remove_file(dir.0.join(SEED)).unwrap();
        assert!(load(&dir.0, &lease).is_err());
        assert!(!dir.0.join(SEED).exists());
    }

    #[test]
    fn corrupt_seed_and_unknown_marker_remain_unchanged() {
        let dir = TestDir::new();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        fs::write(dir.0.join(SEED), b"corrupt").unwrap();
        assert!(load(&dir.0, &lease).is_err());
        assert_eq!(fs::read(dir.0.join(SEED)).unwrap(), b"corrupt");
        fs::write(dir.0.join(SEED), [42; 32]).unwrap();
        fs::write(dir.0.join(MARKER), br#"{"version":999}"#).unwrap();
        assert!(load(&dir.0, &lease).is_err());
        assert_eq!(fs::read(dir.0.join(SEED)).unwrap(), [42; 32]);
    }

    #[test]
    fn missing_identity_in_established_profile_is_an_error() {
        let dir = TestDir::new();
        fs::write(dir.0.join("mycel.redb"), b"existing profile").unwrap();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        assert!(load(&dir.0, &lease).is_err());
        assert!(!dir.0.join(SEED).exists());
    }

    #[test]
    fn orphan_seed_temp_blocks_migration_without_deleting_recovery_material() {
        let dir = TestDir::new();
        let _lease = ProfileLock::acquire(&dir.0).unwrap();
        fs::write(dir.0.join(SEED), [13; 32]).unwrap();
        let orphan = dir.0.join(".identity.key-tmp-interrupted");
        fs::write(&orphan, [14; 32]).unwrap();
        let mut profile = DiskProfile(&dir.0);
        let mut secrets = MemorySecrets::default();
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        assert_eq!(secrets.adds, 0);
        assert_eq!(fs::read(dir.0.join(SEED)).unwrap(), [13; 32]);
        assert_eq!(fs::read(orphan).unwrap(), [14; 32]);
    }

    #[test]
    fn concurrent_profile_open_is_rejected() {
        let dir = TestDir::new();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        assert!(ProfileLock::acquire(&dir.0).is_err());
        drop(lease);
        assert!(ProfileLock::acquire(&dir.0).is_ok());
    }

    #[test]
    fn existing_legacy_seed_is_preserved_exactly() {
        let dir = TestDir::new();
        fs::write(dir.0.join(SEED), [19; 32]).unwrap();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        let keys = load(&dir.0, &lease).unwrap();
        assert_eq!(keys.sign_pk(), DeviceKeys::from_seed([19; 32]).sign_pk());
        assert_eq!(fs::read(dir.0.join(SEED)).unwrap(), [19; 32]);
        assert!(atomic_write(&dir.0.join(SEED), &[22; 32], false).is_err());
        assert_eq!(fs::read(dir.0.join(SEED)).unwrap(), [19; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn private_permissions_and_symlink_rejection() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = TestDir::new();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        load(&dir.0, &lease).unwrap();
        assert_eq!(
            fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.0.join(SEED)).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(dir.0.join(SEED)).unwrap();
        let victim = dir.0.join("victim");
        fs::write(&victim, [1; 32]).unwrap();
        symlink(&victim, dir.0.join(SEED)).unwrap();
        assert!(load(&dir.0, &lease).is_err());
        assert!(atomic_write(&dir.0.join(SEED), &[2; 32], false).is_err());
        assert!(atomic_write(&dir.0.join(SEED), &[2; 32], true).is_err());
        assert_eq!(fs::read(victim).unwrap(), [1; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_identity_and_nonregular_files_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        let path = dir.0.join(SEED);
        fs::write(&path, [9; 32]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0)).unwrap();
        // Root can read mode 000; the CI/user process must exercise denial.
        if unsafe { libc::geteuid() } != 0 {
            assert!(load(&dir.0, &lease).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&path).unwrap(), [9; 32]);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(load(&dir.0, &lease).is_err());
    }

    #[test]
    fn network_mode_absence_corruption_and_atomic_save() {
        let dir = TestDir::new();
        let path = dir.0.join("network-mode");
        assert!(
            crate::Runtime::saved_network_mode(&dir.0)
                .unwrap()
                .is_none()
        );
        atomic_write(&path, b"lan", true).unwrap();
        assert_eq!(
            crate::Runtime::saved_network_mode(&dir.0).unwrap(),
            Some(crate::api::NetworkMode::Lan)
        );
        atomic_write(&path, b"garbage", true).unwrap();
        assert!(crate::Runtime::saved_network_mode(&dir.0).is_err());
        atomic_write(&path, &[255], true).unwrap();
        assert!(crate::Runtime::saved_network_mode(&dir.0).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            atomic_write(&path, b"lan", true).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0)).unwrap();
            if unsafe { libc::geteuid() } != 0 {
                assert!(crate::Runtime::saved_network_mode(&dir.0).is_err());
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::remove_file(&path).unwrap();
            symlink(dir.0.join("absent"), &path).unwrap();
            assert!(crate::Runtime::saved_network_mode(&dir.0).is_err());
        }
    }

    #[derive(Default, Clone)]
    struct MemoryProfile {
        seed: Option<[u8; 32]>,
        marker: Option<Marker>,
        established: bool,
        // Fail immediately after the nth durable mutation, simulating a crash.
        crash_after: Option<usize>,
        events: Vec<&'static str>,
    }
    impl MemoryProfile {
        fn mutate(&mut self, event: &'static str) -> Result<()> {
            self.events.push(event);
            if let Some(n) = &mut self.crash_after {
                *n -= 1;
                if *n == 0 {
                    self.crash_after = None;
                    bail!("injected crash after durable {event}");
                }
            }
            Ok(())
        }
    }
    impl ProfileStorage for MemoryProfile {
        fn read_seed(&self) -> Result<Option<[u8; 32]>> {
            Ok(self.seed)
        }
        fn read_marker(&self) -> Result<Option<Marker>> {
            Ok(self.marker.clone())
        }
        fn is_pristine(&self) -> Result<bool> {
            Ok(!self.established && self.seed.is_none() && self.marker.is_none())
        }
        fn write_seed(&mut self, seed: [u8; 32]) -> Result<()> {
            assert!(self.seed.is_none());
            self.seed = Some(seed);
            self.mutate("seed")
        }
        fn write_marker(&mut self, marker: &Marker, replace: bool) -> Result<()> {
            assert!(replace || self.marker.is_none());
            self.marker = Some(marker.clone());
            self.mutate(if marker.state == State::Pending {
                "pending"
            } else {
                "committed"
            })
        }
        fn remove_seed(&mut self) -> Result<()> {
            assert!(
                self.marker
                    .as_ref()
                    .is_some_and(|m| m.state == State::Committed)
            );
            self.seed = None;
            self.mutate("removed")
        }
    }
    #[derive(Default)]
    struct MemorySecrets {
        values: HashMap<String, [u8; 32]>,
        denied: bool,
        crash_after_add: bool,
        read_failure: bool,
        adds: usize,
    }
    impl SecretStorage for MemorySecrets {
        fn add(&mut self, account: &str, seed: [u8; 32]) -> Result<()> {
            self.adds += 1;
            if self.denied {
                bail!("denied");
            }
            let stored = self.values.entry(account.to_string()).or_insert(seed);
            if *stored != seed {
                bail!("conflicting slot");
            }
            if self.crash_after_add {
                self.crash_after_add = false;
                bail!("crash after add");
            }
            Ok(())
        }
        fn read(&self, account: &str) -> Result<Option<[u8; 32]>> {
            if self.denied || self.read_failure {
                bail!("unavailable");
            }
            Ok(self.values.get(account).copied())
        }
    }

    #[test]
    fn migration_roundtrip_preserves_key_and_stable_reference() {
        let mut profile = MemoryProfile {
            seed: Some([71; 32]),
            ..Default::default()
        };
        let mut secrets = MemorySecrets::default();
        let expected = DeviceKeys::from_seed([71; 32]).sign_pk();
        assert_eq!(
            load_keychain(&mut profile, &mut secrets).unwrap().sign_pk(),
            expected
        );
        let account = profile.marker.as_ref().unwrap().account.clone();
        assert_eq!(profile.events, ["pending", "committed", "removed"]);
        assert!(profile.seed.is_none());
        // The marker can move into a new container; the path is never used.
        let mut moved_profile = profile.clone();
        assert_eq!(
            load_keychain(&mut moved_profile, &mut secrets)
                .unwrap()
                .sign_pk(),
            expected
        );
        assert_eq!(moved_profile.marker.unwrap().account, account);
        assert_eq!(secrets.adds, 1);
    }

    #[test]
    fn every_durable_provisioning_boundary_resumes_without_identity_change() {
        for boundary in 1..=4 {
            let mut profile = MemoryProfile {
                crash_after: Some(boundary),
                ..Default::default()
            };
            let mut secrets = MemorySecrets::default();
            assert!(load_keychain(&mut profile, &mut secrets).is_err());
            let expected = profile
                .marker
                .as_ref()
                .map(|m| m.public_key)
                .unwrap_or_else(|| DeviceKeys::from_seed(profile.seed.unwrap()).sign_pk().0);
            assert_eq!(
                load_keychain(&mut profile, &mut secrets)
                    .unwrap()
                    .sign_pk()
                    .0,
                expected
            );
            assert!(profile.seed.is_none());
        }
    }

    #[test]
    fn add_crash_and_failed_readback_preserve_legacy_seed_and_resume() {
        for read_failure in [false, true] {
            let mut profile = MemoryProfile {
                seed: Some([18; 32]),
                ..Default::default()
            };
            let mut secrets = MemorySecrets {
                crash_after_add: !read_failure,
                read_failure,
                ..Default::default()
            };
            assert!(load_keychain(&mut profile, &mut secrets).is_err());
            assert_eq!(profile.seed, Some([18; 32]));
            assert!(profile.marker.as_ref().unwrap().state == State::Pending);
            let account = profile.marker.as_ref().unwrap().account.clone();
            secrets.read_failure = false;
            assert_eq!(
                load_keychain(&mut profile, &mut secrets).unwrap().sign_pk(),
                DeviceKeys::from_seed([18; 32]).sign_pk()
            );
            assert_eq!(profile.marker.as_ref().unwrap().account, account);
        }
    }

    #[test]
    fn denied_missing_conflicting_and_unknown_keychain_state_never_fallback() {
        let mut profile = MemoryProfile {
            seed: Some([4; 32]),
            ..Default::default()
        };
        let mut secrets = MemorySecrets {
            denied: true,
            ..Default::default()
        };
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        assert_eq!(profile.seed, Some([4; 32]));
        let account = profile.marker.as_ref().unwrap().account.clone().unwrap();
        secrets.denied = false;
        secrets.values.insert(account.clone(), [8; 32]);
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        assert_eq!(profile.seed, Some([4; 32]));
        assert_eq!(secrets.values[&account], [8; 32]);
        secrets.values.insert(account.clone(), [4; 32]);
        load_keychain(&mut profile, &mut secrets).unwrap();
        secrets.values.clear();
        // Even with a surviving legacy file a committed identity cannot re-add.
        profile.seed = Some([4; 32]);
        let adds = secrets.adds;
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        assert_eq!(secrets.adds, adds);
        assert_eq!(profile.seed, Some([4; 32]));
        profile.marker.as_mut().unwrap().version = 99;
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        assert_eq!(secrets.adds, adds);
    }

    #[test]
    fn pending_without_seed_requires_matching_existing_slot() {
        let mut profile = MemoryProfile {
            seed: Some([5; 32]),
            crash_after: Some(1),
            ..Default::default()
        };
        let mut secrets = MemorySecrets::default();
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        let account = profile.marker.as_ref().unwrap().account.clone().unwrap();
        profile.seed = None;
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        secrets.values.insert(account.clone(), [8; 32]);
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        secrets.values.insert(account, [5; 32]);
        assert_eq!(
            load_keychain(&mut profile, &mut secrets).unwrap().sign_pk(),
            DeviceKeys::from_seed([5; 32]).sign_pk()
        );
        assert_eq!(secrets.adds, 0);
    }
}
