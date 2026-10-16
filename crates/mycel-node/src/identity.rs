//! Identity provisioning is a durable, fail-closed protocol. iOS uses the
//! device-only Keychain; other platforms deliberately retain the file backend.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mycel_crypto::{DeviceKeys, random};
use serde::{Deserialize, Serialize};

const SEED: &str = "identity.key";
const MARKER: &str = "identity-state.json";
const LOCK: &str = ".identity.lock";
/// The temporary seed name of releases before the durable protocol.
const LEGACY_SEED_TEMP: &str = "identity.tmp";

/// What Mycel keeps in a profile folder. Any of these means the profile is
/// established, so a missing identity must never be silently replaced.
/// Nothing else counts: platform files (Android's `cache/`, `code_cache/`,
/// `files/`, WebView data), the host's `mycel.log`/`mycel.log.1` and
/// `link-diagnostics` switch (both may exist before the profile is opened),
/// and set-aside profiles.
/// (On Android the profile folder is the app's data root, so the attachment
/// folder `files/` is also the platform's own and proves nothing.)
const PROFILE_STATE: &[&str] =
    &[SEED, MARKER, "mycel.redb", "network-mode", "blobs", "uploads", "http-token", "notification-targets.json"];

const ALREADY_OPEN: &str = "this Mycel profile is already open in another process";
const CANNOT_LOCK: &str = "cannot lock the Mycel profile folder (its file system may not support file locks)";

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
            directory.set_permissions(fs::Permissions::from_mode(0o700)).context("restrict profile permissions")?;
            directory.sync_all().context("persist private profile permissions")?;
        }
        // Before anything is written: the profile is bound to this device's
        // Keychain, and encrypted conversations stay out of cloud backups.
        #[cfg(target_os = "ios")]
        ios::exclude_from_backup(dir);
        let path = dir.join(LOCK);
        reject_nonregular(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        private_options(&mut options);
        let file = options.open(path).context("open profile lock")?;
        if !file.metadata()?.is_file() {
            bail!("profile lock must be a regular file");
        }
        lock_exclusive(&file)?;
        Ok(Self(file))
    }
}

/// `File::try_lock` is unimplemented on Android (it fails as an I/O error), so
/// Unix uses flock(2), which macOS, iOS, Linux and Android all provide. Its
/// lock belongs to the open file, so a second open in this process conflicts
/// too, and the OS releases it when the process dies.
#[cfg(unix)]
fn lock_exclusive(file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    loop {
        // SAFETY: flock on a file descriptor this File owns.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EWOULDBLOCK) => bail!(ALREADY_OPEN),
            _ => return Err(error).context(CANNOT_LOCK),
        }
    }
}

#[cfg(windows)]
fn lock_exclusive(file: &File) -> Result<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => bail!(ALREADY_OPEN),
        Err(std::fs::TryLockError::Error(error)) => Err(error).context(CANNOT_LOCK),
    }
}

impl Drop for ProfileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: unlock the descriptor this File owns (closing would too).
            unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
        #[cfg(windows)]
        let _ = self.0.unlock();
    }
}

fn private_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
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

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
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
    File::open(dir)?.sync_all().context("persist profile directory")?;
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
    let name =
        path.file_name().context("file has no name")?.to_str().context("identity/settings filename is not UTF-8")?;
    let temporary = dir.join(format!(".{name}-tmp-{}", hex::encode(random::<16>())));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_options(&mut options);
    let mut file = options.open(&temporary).context("create private temporary file")?;
    // On error, leave recoverable bytes rather than hiding an incomplete
    // provisioning attempt. `DiskProfile::recover` resolves what a crash in
    // our own protocol can leave; anything else fails closed.
    file.write_all(bytes)?;
    file.sync_all().context("persist identity/settings contents")?;
    drop(file);
    reject_nonregular(path)?;
    if replace {
        fs::rename(&temporary, path).context("install identity/settings state")?;
    } else {
        install_new(&temporary, path, bytes)?;
    }
    sync_dir(dir)
}

/// Install a synced temporary file at `path` only if nothing is there.
#[cfg(target_vendor = "apple")]
fn install_new(temporary: &Path, path: &Path, _bytes: &[u8]) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = std::ffi::CString::new(temporary.as_os_str().as_bytes())?;
    let destination = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // An atomic exclusive rename avoids a crash window with an extra seed
    // hard link that would survive iOS Keychain migration cleanup.
    let result = unsafe {
        libc::renameatx_np(libc::AT_FDCWD, source.as_ptr(), libc::AT_FDCWD, destination.as_ptr(), libc::RENAME_EXCL)
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context(NO_CLOBBER);
    }
    Ok(())
}

/// Install a synced temporary file at `path` only if nothing is there.
#[cfg(not(target_vendor = "apple"))]
fn install_new(temporary: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    // The same atomic exclusive rename where the kernel offers one.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if rename_noreplace(temporary, path).context(NO_CLOBBER)? {
        return Ok(());
    }
    // A hard link never replaces either. A crash before the temporary is
    // removed leaves two names for one seed, which `recover` resolves.
    // Android 10+ denies links in app data, and FAT volumes lack them.
    match fs::hard_link(temporary, path) {
        Ok(()) => {
            fs::remove_file(temporary)?;
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(e).context(NO_CLOBBER);
        }
        Err(_) => {}
    }
    install_by_copy(temporary, path, bytes).context(NO_CLOBBER)
}

const NO_CLOBBER: &str = "install identity without replacing an existing file";

/// Last resort: exclusive create, write and sync. The complete, synced
/// temporary stays until the copy is durable, so `recover` can finish (or
/// clean up after) a copy that a crash interrupted.
#[cfg_attr(target_vendor = "apple", allow(dead_code))]
fn install_by_copy(temporary: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_options(&mut options);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    sync_dir(path.parent().context("file has no parent")?)?;
    fs::remove_file(temporary)?;
    Ok(())
}

/// renameat2(RENAME_NOREPLACE): Linux 3.15+. `Ok(false)` when this kernel,
/// file system or sandbox can't do it, so the caller falls back.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_noreplace(from: &Path, to: &Path) -> std::io::Result<bool> {
    use std::os::unix::ffi::OsStrExt;
    // Before Android 11 the app seccomp filter may not allow renameat2, and a
    // disallowed system call kills the process instead of failing.
    #[cfg(target_os = "android")]
    if android_api_level() < 30 {
        return Ok(false);
    }
    let from = std::ffi::CString::new(from.as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes())?;
    const RENAME_NOREPLACE: libc::c_uint = 1;
    // SAFETY: NUL-terminated paths relative to the working directory.
    let result = unsafe {
        libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, from.as_ptr(), libc::AT_FDCWD, to.as_ptr(), RENAME_NOREPLACE)
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES | libc::EOPNOTSUPP) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(target_os = "android")]
fn android_api_level() -> u32 {
    let mut value = [0 as libc::c_char; 92]; // PROP_VALUE_MAX
    // SAFETY: a NUL-terminated key and a PROP_VALUE_MAX buffer.
    let n = unsafe { libc::__system_property_get(c"ro.build.version.sdk".as_ptr(), value.as_mut_ptr()) };
    if n <= 0 {
        return 0;
    }
    // SAFETY: __system_property_get NUL-terminates what it wrote.
    let level = unsafe { std::ffi::CStr::from_ptr(value.as_ptr()) };
    level.to_str().ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
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
    /// Move all profile state into a new folder (never deleting anything) and
    /// return it, leaving a pristine profile.
    #[cfg(any(target_os = "ios", test))]
    fn set_aside(&mut self) -> Result<PathBuf>;
}

/// What an interrupted no-clobber install left at `path`: nothing yet, or a
/// prefix of its temporary (some file systems zero-fill after a crash).
fn interrupted_copy(installed: &[u8], temporary: &[u8]) -> bool {
    installed.len() < temporary.len() && (temporary.starts_with(installed) || installed.iter().all(|b| *b == 0))
}

struct DiskProfile<'a>(&'a Path);
impl DiskProfile<'_> {
    /// Finish or clean up what a crash during our own protocol leaves: a
    /// seed/marker temporary next to its completed or partial install, or a
    /// first-launch seed that was never installed. A temporary in any other
    /// state is preserved, and `read_seed` then refuses to continue.
    fn recover(&mut self) -> Result<()> {
        let marker_exists = exists(&self.0.join(MARKER))?;
        let mut changed = false;
        for entry in fs::read_dir(self.0)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            let target = if name.starts_with(".identity.key-tmp-") || name == LEGACY_SEED_TEMP {
                SEED
            } else if name.starts_with(".identity-state.json-tmp-") {
                MARKER
            } else {
                continue;
            };
            let temporary = self.0.join(&*name);
            let path = self.0.join(target);
            let Ok(Some(bytes)) = read_optional(&temporary, 4096) else {
                continue;
            };
            match read_optional(&path, 4096)? {
                // The install finished; only the temporary's removal did not.
                Some(installed) if installed == bytes => fs::remove_file(&temporary)?,
                // A copy-install stopped part way: it never became an identity
                // (no marker binds it), so complete it from the synced original.
                Some(installed)
                    if interrupted_copy(&installed, &bytes)
                        && (target == MARKER || (bytes.len() == 32 && !marker_exists)) =>
                {
                    fs::remove_file(&path)?;
                    install_new(&temporary, &path, &bytes)?;
                }
                // Markers contain no secret; an unfinished replacement is moot.
                _ if target == MARKER => fs::remove_file(&temporary)?,
                // A first-launch seed that was never installed was never used.
                None if !marker_exists && self.is_pristine()? => fs::remove_file(&temporary)?,
                _ => continue,
            }
            changed = true;
        }
        if changed {
            sync_dir(self.0)?;
        }
        Ok(())
    }
}

impl ProfileStorage for DiskProfile<'_> {
    fn read_seed(&self) -> Result<Option<[u8; 32]>> {
        // Never complete a migration while an interrupted provisioning attempt
        // leaves a second raw seed behind. Marker/settings temporaries contain
        // no secret and do not prevent the durable protocol from resuming.
        for entry in fs::read_dir(self.0)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".identity.key-tmp-") || name == LEGACY_SEED_TEMP {
                bail!("interrupted identity provisioning requires recovery; existing files were preserved");
            }
        }
        read_optional(&self.0.join(SEED), 32)?
            .map(|b| b.try_into().map_err(|_| anyhow::anyhow!("identity.key is corrupt")))
            .transpose()
    }
    fn read_marker(&self) -> Result<Option<Marker>> {
        read_optional(&self.0.join(MARKER), 4096)?
            .map(|b| {
                let marker: Marker = serde_json::from_slice(&b).context("corrupt identity marker")?;
                marker.validate()?;
                Ok(marker)
            })
            .transpose()
    }
    fn is_pristine(&self) -> Result<bool> {
        for name in PROFILE_STATE {
            if exists(&self.0.join(name))? {
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
    #[cfg(any(target_os = "ios", test))]
    fn set_aside(&mut self) -> Result<PathBuf> {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let kept = (0..)
            .map(|n| match n {
                0 => self.0.join(format!("unrecoverable-{secs}")),
                n => self.0.join(format!("unrecoverable-{secs}-{n}")),
            })
            .find(|dir| !dir.exists())
            .context("no folder name for the unrecoverable profile")?;
        fs::create_dir(&kept).context("create a folder for the unrecoverable profile")?;
        for entry in fs::read_dir(self.0)? {
            let name = entry?.file_name();
            let text = name.to_string_lossy();
            // On iOS the folder is Mycel's alone: decrypted attachments too.
            let ours = PROFILE_STATE.contains(&&*text)
                || text == "files"
                || text == LEGACY_SEED_TEMP
                || text.starts_with(".identity.key-tmp-")
                || text.starts_with(".identity-state.json-tmp-");
            if ours {
                fs::rename(self.0.join(&name), kept.join(&name)).with_context(|| format!("set aside {text}"))?;
            }
        }
        sync_dir(&kept)?;
        sync_dir(self.0)?;
        Ok(kept)
    }
}

/// A loaded identity. `replaced` is where an unusable profile (its identity
/// isn't on this device) was kept when a new identity had to be started.
pub(crate) struct Identity {
    pub keys: DeviceKeys,
    pub replaced: Option<PathBuf>,
}

/// The lease is required at the call site and retained by Runtime.
pub(crate) fn load(dir: &Path, _lease: &ProfileLock) -> Result<Identity> {
    let mut profile = DiskProfile(dir);
    profile.recover()?;
    #[cfg(target_os = "ios")]
    return load_keychain(&mut profile, &mut ios::Keychain).map(|(keys, replaced)| Identity { keys, replaced });
    #[cfg(not(target_os = "ios"))]
    load_file(&mut profile).map(|keys| Identity { keys, replaced: None })
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
        let seed = profile.read_seed()?.context("identity missing from existing profile")?;
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
    /// `Ok(None)` only when the item definitely doesn't exist (not while the
    /// Keychain is merely unavailable, e.g. before the first unlock).
    fn read(&self, account: &str) -> Result<Option<[u8; 32]>>;
}

/// Keychain items are device-only, so a profile restored onto another device
/// (from a backup taken before profiles were excluded from backups, or by a
/// device-to-device transfer) names an identity this device doesn't have.
/// That profile is kept aside, never deleted, and a new identity is started:
/// refusing would leave the app unable to start, forever.
#[cfg(any(target_os = "ios", test))]
fn load_keychain(
    profile: &mut impl ProfileStorage,
    secrets: &mut impl SecretStorage,
) -> Result<(DeviceKeys, Option<PathBuf>)> {
    if let Some(keys) = provision_keychain(profile, secrets)? {
        return Ok((keys, None));
    }
    let kept = profile.set_aside()?;
    eprintln!(
        "mycel: this profile's identity isn't on this device (it was restored or moved from another device); \
         kept that profile in {} and started a new identity",
        kept.display()
    );
    let keys = provision_keychain(profile, secrets)?.context("a new identity could not be created")?;
    Ok((keys, Some(kept)))
}

/// `Ok(None)`: the identity this profile is bound to is definitely absent.
#[cfg(any(target_os = "ios", test))]
fn provision_keychain(
    profile: &mut impl ProfileStorage,
    secrets: &mut impl SecretStorage,
) -> Result<Option<DeviceKeys>> {
    let existing = profile.read_marker()?;
    if let Some(marker) = &existing {
        marker.validate()?;
    }
    let mut marker = match existing {
        Some(marker) if marker.backend == Backend::IosKeychain => marker,
        file_marker => {
            let seed = if let Some(marker) = &file_marker {
                let seed = profile.read_seed()?.context("identity missing from existing profile")?;
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
    let account = marker.account.as_deref().context("missing Keychain account reference")?;
    let legacy = profile.read_seed()?;
    if let Some(seed) = legacy {
        marker.verify(seed)?;
    }
    if marker.state == State::Pending {
        if let Some(seed) = legacy {
            secrets.add(account, seed)?;
        }
        let Some(seed) = secrets.read(account)? else {
            // No file seed (only removed after commit) and no Keychain item.
            return Ok(None);
        };
        marker.verify(seed)?;
        if legacy.is_some_and(|old| old != seed) {
            bail!("Keychain identity conflicts with existing seed");
        }
        marker.state = State::Committed;
        profile.write_marker(&marker, true)?;
    }
    // A committed marker never permits fallback or identity creation. The
    // only re-add is the verified seed this marker is bound to.
    let seed = match (secrets.read(account)?, legacy) {
        (Some(seed), _) => seed,
        (None, Some(seed)) => {
            secrets.add(account, seed)?;
            secrets.read(account)?.context("committed Keychain identity could not be restored")?
        }
        (None, None) => return Ok(None),
    };
    let keys = marker.verify(seed)?;
    if let Some(old) = legacy {
        if old != seed {
            bail!("Keychain identity conflicts with existing seed");
        }
        profile.remove_seed()?;
    }
    Ok(Some(keys))
}

#[cfg(target_os = "ios")]
mod ios {
    use super::*;
    use core_foundation::{base::TCFType, data::CFData, dictionary::CFDictionary, string::CFString};
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
                Ok(bytes) => Ok(Some(bytes.try_into().map_err(|_| anyhow::anyhow!("corrupt Keychain identity"))?)),
                Err(e) if e.code() == errSecItemNotFound => Ok(None),
                Err(e) => bail!("Keychain identity unavailable (status {})", e.code()),
            }
        }
    }

    /// Keep the profile out of iCloud and computer backups. Its identity is
    /// a device-only Keychain item that a restore never brings back, and its
    /// conversations are private. Failure is logged, never fatal.
    pub(super) fn exclude_from_backup(dir: &Path) {
        use core_foundation::{boolean::CFBoolean, error::CFError, url::CFURL};
        use core_foundation_sys::url::{CFURLSetResourcePropertyForKey, kCFURLIsExcludedFromBackupKey};
        let Some(url) = CFURL::from_path(dir, true) else {
            eprintln!("mycel: can't exclude the profile from backups (bad path)");
            return;
        };
        let mut error = std::ptr::null_mut();
        // SAFETY: valid CF objects; an error is returned retained (create rule).
        let ok = unsafe {
            CFURLSetResourcePropertyForKey(
                url.as_concrete_TypeRef(),
                kCFURLIsExcludedFromBackupKey,
                CFBoolean::true_value().as_CFTypeRef(),
                &mut error,
            )
        };
        if ok == 0 {
            let reason = if error.is_null() {
                String::new()
            } else {
                unsafe { CFError::wrap_under_create_rule(error) }.description().to_string()
            };
            eprintln!("mycel: can't exclude the profile from backups: {reason}");
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
        let mut profile = DiskProfile(dir);
        profile.recover()?;
        load_file(&mut profile)
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("mycel-identity-test-{}", hex::encode(random::<16>())));
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

    #[test]
    fn concurrent_open_and_unlockable_folders_explain_themselves() {
        let dir = TestDir::new();
        let _lease = ProfileLock::acquire(&dir.0).unwrap();
        let error = ProfileLock::acquire(&dir.0).err().unwrap();
        assert!(error.to_string().contains("already open"), "{error:#}");
    }

    #[test]
    fn platform_files_and_logs_are_not_an_established_profile() {
        // Android's app data root, where the host may already have logged.
        let dir = TestDir::new();
        for platform in ["cache", "code_cache", "files", "app_webview", "shared_prefs"] {
            fs::create_dir(dir.0.join(platform)).unwrap();
        }
        // The host logs and reads its diagnostics switch before opening.
        fs::write(dir.0.join("mycel.log"), b"early log").unwrap();
        fs::write(dir.0.join("mycel.log.1"), b"older log").unwrap();
        fs::write(dir.0.join("link-diagnostics"), b"2").unwrap();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        assert!(DiskProfile(&dir.0).is_pristine().unwrap());
        let pk = load(&dir.0, &lease).unwrap().sign_pk();
        assert_eq!(load(&dir.0, &lease).unwrap().sign_pk(), pk);
        // Mycel's own state still protects a profile whose identity is gone.
        for state in ["network-mode", "blobs", "notification-targets.json"] {
            let other = TestDir::new();
            fs::create_dir(other.0.join("cache")).unwrap();
            if state == "blobs" {
                fs::create_dir(other.0.join(state)).unwrap();
            } else {
                fs::write(other.0.join(state), b"lan").unwrap();
            }
            let lease = ProfileLock::acquire(&other.0).unwrap();
            assert!(load(&other.0, &lease).is_err(), "{state}");
            assert!(!other.0.join(SEED).exists());
        }
    }

    #[test]
    fn baseline_profile_upgrades_with_the_same_identity() {
        // Releases before the durable protocol: a bare seed, no marker.
        let dir = TestDir::new();
        fs::write(dir.0.join(SEED), [57; 32]).unwrap();
        fs::write(dir.0.join("mycel.redb"), b"existing database").unwrap();
        fs::write(dir.0.join("network-mode"), b"lan").unwrap();
        fs::create_dir(dir.0.join("blobs")).unwrap();
        let expected = DeviceKeys::from_seed([57; 32]).sign_pk();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        assert_eq!(load(&dir.0, &lease).unwrap().sign_pk(), expected);
        assert!(dir.0.join(MARKER).exists());
        assert_eq!(fs::read(dir.0.join(SEED)).unwrap(), [57; 32]);
        drop(lease);
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        assert_eq!(load(&dir.0, &lease).unwrap().sign_pk(), expected);
    }

    #[test]
    fn interrupted_installs_are_finished_or_cleaned_up() {
        let temp = |dir: &TestDir| dir.0.join(".identity.key-tmp-0123456789abcdef");
        // A link install that stopped before removing the temporary.
        let dir = TestDir::new();
        fs::write(dir.0.join(SEED), [3; 32]).unwrap();
        fs::write(temp(&dir), [3; 32]).unwrap();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        assert_eq!(load(&dir.0, &lease).unwrap().sign_pk(), DeviceKeys::from_seed([3; 32]).sign_pk());
        assert!(!temp(&dir).exists());
        drop(lease);

        // A copy install that stopped part way, before any marker existed.
        for partial in [&[6u8; 10][..], &[][..], &[0u8; 20][..]] {
            let dir = TestDir::new();
            fs::write(dir.0.join(SEED), partial).unwrap();
            fs::write(temp(&dir), [6; 32]).unwrap();
            let lease = ProfileLock::acquire(&dir.0).unwrap();
            assert_eq!(load(&dir.0, &lease).unwrap().sign_pk(), DeviceKeys::from_seed([6; 32]).sign_pk());
            assert_eq!(fs::read(dir.0.join(SEED)).unwrap(), [6; 32]);
            assert!(!temp(&dir).exists());
        }

        // A first launch that stopped before installing: nothing used it.
        for leftover in [".identity.key-tmp-0123456789abcdef", LEGACY_SEED_TEMP] {
            let dir = TestDir::new();
            fs::create_dir(dir.0.join("cache")).unwrap();
            fs::write(dir.0.join(leftover), [8; 32]).unwrap();
            let lease = ProfileLock::acquire(&dir.0).unwrap();
            load(&dir.0, &lease).unwrap();
            assert!(!dir.0.join(leftover).exists());
            assert!(dir.0.join(SEED).exists());
        }

        // The same leftover in an established profile is never discarded.
        let dir = TestDir::new();
        fs::write(dir.0.join("mycel.redb"), b"existing database").unwrap();
        fs::write(temp(&dir), [8; 32]).unwrap();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        assert!(load(&dir.0, &lease).is_err());
        assert_eq!(fs::read(temp(&dir)).unwrap(), [8; 32]);
        assert!(!dir.0.join(SEED).exists());
        drop(lease);

        // A different complete seed next to the identity fails closed.
        let dir = TestDir::new();
        fs::write(dir.0.join(SEED), [1; 32]).unwrap();
        fs::write(temp(&dir), [2; 32]).unwrap();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        assert!(load(&dir.0, &lease).is_err());
        assert_eq!(fs::read(dir.0.join(SEED)).unwrap(), [1; 32]);
        assert_eq!(fs::read(temp(&dir)).unwrap(), [2; 32]);
        drop(lease);

        // Marker leftovers hold no secret: a partial copy is completed and
        // an unfinished replacement is dropped.
        let dir = TestDir::new();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        let pk = load(&dir.0, &lease).unwrap().sign_pk();
        let marker = fs::read(dir.0.join(MARKER)).unwrap();
        let marker_temp = dir.0.join(".identity-state.json-tmp-0123456789abcdef");
        fs::write(&marker_temp, &marker).unwrap();
        fs::write(dir.0.join(MARKER), &marker[..marker.len() / 2]).unwrap();
        assert_eq!(load(&dir.0, &lease).unwrap().sign_pk(), pk);
        assert_eq!(fs::read(dir.0.join(MARKER)).unwrap(), marker);
        fs::write(&marker_temp, b"{\"unfinished\":").unwrap();
        assert_eq!(load(&dir.0, &lease).unwrap().sign_pk(), pk);
        assert!(!marker_temp.exists());
    }

    #[test]
    fn set_aside_keeps_every_profile_file_and_leaves_platform_files() {
        let dir = TestDir::new();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        let pk = load(&dir.0, &lease).unwrap().sign_pk();
        fs::write(dir.0.join("mycel.redb"), b"database").unwrap();
        fs::create_dir(dir.0.join("files")).unwrap();
        fs::create_dir(dir.0.join("cache")).unwrap();
        fs::write(dir.0.join("mycel.log"), b"log").unwrap();
        let kept = DiskProfile(&dir.0).set_aside().unwrap();
        assert!(kept.starts_with(&dir.0));
        for moved in [SEED, MARKER, "mycel.redb", "files"] {
            assert!(kept.join(moved).exists() && !dir.0.join(moved).exists(), "{moved}");
        }
        for stays in ["cache", "mycel.log", LOCK] {
            assert!(dir.0.join(stays).exists(), "{stays}");
        }
        assert!(DiskProfile(&dir.0).is_pristine().unwrap());
        assert_ne!(load(&dir.0, &lease).unwrap().sign_pk(), pk);
        let again = DiskProfile(&dir.0).set_aside().unwrap();
        assert_ne!(again, kept);
        assert_eq!(fs::read(kept.join("mycel.redb")).unwrap(), b"database");
    }

    #[test]
    fn copy_install_never_replaces_and_removes_its_temporary_last() {
        let dir = TestDir::new();
        let (temporary, path) = (dir.0.join(".identity.key-tmp-1"), dir.0.join(SEED));
        fs::write(&temporary, [4; 32]).unwrap();
        fs::write(&path, [5; 32]).unwrap();
        assert!(install_by_copy(&temporary, &path, &[4; 32]).is_err());
        assert_eq!(fs::read(&path).unwrap(), [5; 32]);
        assert_eq!(fs::read(&temporary).unwrap(), [4; 32]);
        fs::remove_file(&path).unwrap();
        install_by_copy(&temporary, &path, &[4; 32]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), [4; 32]);
        assert!(!temporary.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_permissions_and_symlink_rejection() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = TestDir::new();
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        let lease = ProfileLock::acquire(&dir.0).unwrap();
        load(&dir.0, &lease).unwrap();
        assert_eq!(fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(dir.0.join(SEED)).unwrap().permissions().mode() & 0o777, 0o600);
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
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
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
        assert!(crate::Runtime::saved_network_mode(&dir.0).unwrap().is_none());
        assert_eq!(
            crate::Runtime::launch_network_mode(&dir.0, crate::api::NetworkMode::Internet),
            crate::api::NetworkMode::Internet
        );
        atomic_write(&path, b"lan", true).unwrap();
        assert_eq!(crate::Runtime::saved_network_mode(&dir.0).unwrap(), Some(crate::api::NetworkMode::Lan));
        atomic_write(&path, b"garbage", true).unwrap();
        assert!(crate::Runtime::saved_network_mode(&dir.0).is_err());
        for default in [crate::api::NetworkMode::Internet, crate::api::NetworkMode::Lan] {
            assert_eq!(
                crate::Runtime::launch_network_mode(&dir.0, default),
                crate::api::NetworkMode::Lan,
                "unreadable means the most private mode, never a wider one"
            );
        }
        atomic_write(&path, &[255], true).unwrap();
        assert!(crate::Runtime::saved_network_mode(&dir.0).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            atomic_write(&path, b"lan", true).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            if unsafe { libc::geteuid() } != 0 {
                assert!(crate::Runtime::saved_network_mode(&dir.0).is_err());
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::remove_file(&path).unwrap();
            symlink(dir.0.join("absent"), &path).unwrap();
            assert!(crate::Runtime::saved_network_mode(&dir.0).is_err());
        }
    }

    #[tokio::test]
    async fn truncated_network_mode_starts_local_only_and_is_repaired() {
        let dir = TestDir::new();
        let runtime = crate::Runtime::open(&dir.0, crate::api::NetworkMode::Local, None).await.unwrap();
        runtime.set_network_mode(crate::api::NetworkMode::Internet).unwrap();
        runtime.shutdown().await.unwrap();
        drop(runtime);
        // What an interrupted non-atomic write by an older release leaves.
        fs::write(dir.0.join("network-mode"), b"inter").unwrap();
        let mode = crate::Runtime::launch_network_mode(&dir.0, crate::api::NetworkMode::Internet);
        assert_eq!(mode, crate::api::NetworkMode::Lan);
        let runtime = crate::Runtime::open(&dir.0, crate::api::NetworkMode::Local, None).await.unwrap();
        assert!(runtime.notices().contains(&crate::api::Notice::NetworkModeReset));
        assert_eq!(runtime.network_status().next_mode, crate::api::NetworkMode::Lan);
        assert_eq!(fs::read(dir.0.join("network-mode")).unwrap(), b"lan");
        runtime.shutdown().await.unwrap();
    }

    #[derive(Default, Clone)]
    struct MemoryProfile {
        seed: Option<[u8; 32]>,
        marker: Option<Marker>,
        established: bool,
        // Fail immediately after the nth durable mutation, simulating a crash.
        crash_after: Option<usize>,
        events: Vec<&'static str>,
        kept: Option<(Option<[u8; 32]>, Option<Marker>)>,
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
            self.mutate(if marker.state == State::Pending { "pending" } else { "committed" })
        }
        fn remove_seed(&mut self) -> Result<()> {
            assert!(self.marker.as_ref().is_some_and(|m| m.state == State::Committed));
            self.seed = None;
            self.mutate("removed")
        }
        fn set_aside(&mut self) -> Result<PathBuf> {
            self.kept = Some((self.seed.take(), self.marker.take()));
            self.established = false;
            self.mutate("set aside")?;
            Ok(PathBuf::from("unrecoverable"))
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
        let mut profile = MemoryProfile { seed: Some([71; 32]), ..Default::default() };
        let mut secrets = MemorySecrets::default();
        let expected = DeviceKeys::from_seed([71; 32]).sign_pk();
        assert_eq!(load_keychain(&mut profile, &mut secrets).unwrap().0.sign_pk(), expected);
        let account = profile.marker.as_ref().unwrap().account.clone();
        assert_eq!(profile.events, ["pending", "committed", "removed"]);
        assert!(profile.seed.is_none());
        // The marker can move into a new container; the path is never used.
        let mut moved_profile = profile.clone();
        assert_eq!(load_keychain(&mut moved_profile, &mut secrets).unwrap().0.sign_pk(), expected);
        assert_eq!(moved_profile.marker.unwrap().account, account);
        assert_eq!(secrets.adds, 1);
    }

    #[test]
    fn every_durable_provisioning_boundary_resumes_without_identity_change() {
        for boundary in 1..=4 {
            let mut profile = MemoryProfile { crash_after: Some(boundary), ..Default::default() };
            let mut secrets = MemorySecrets::default();
            assert!(load_keychain(&mut profile, &mut secrets).is_err());
            let expected = profile
                .marker
                .as_ref()
                .map(|m| m.public_key)
                .unwrap_or_else(|| DeviceKeys::from_seed(profile.seed.unwrap()).sign_pk().0);
            assert_eq!(load_keychain(&mut profile, &mut secrets).unwrap().0.sign_pk().0, expected);
            assert!(profile.seed.is_none());
        }
    }

    #[test]
    fn add_crash_and_failed_readback_preserve_legacy_seed_and_resume() {
        for read_failure in [false, true] {
            let mut profile = MemoryProfile { seed: Some([18; 32]), ..Default::default() };
            let mut secrets = MemorySecrets { crash_after_add: !read_failure, read_failure, ..Default::default() };
            assert!(load_keychain(&mut profile, &mut secrets).is_err());
            assert_eq!(profile.seed, Some([18; 32]));
            assert!(profile.marker.as_ref().unwrap().state == State::Pending);
            let account = profile.marker.as_ref().unwrap().account.clone();
            secrets.read_failure = false;
            assert_eq!(
                load_keychain(&mut profile, &mut secrets).unwrap().0.sign_pk(),
                DeviceKeys::from_seed([18; 32]).sign_pk()
            );
            assert_eq!(profile.marker.as_ref().unwrap().account, account);
        }
    }

    #[test]
    fn denied_missing_conflicting_and_unknown_keychain_state_never_fallback() {
        let mut profile = MemoryProfile { seed: Some([4; 32]), ..Default::default() };
        let mut secrets = MemorySecrets { denied: true, ..Default::default() };
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
        // A committed identity re-adds only the seed its marker is bound to.
        secrets.values.clear();
        profile.seed = Some([9; 32]);
        let adds = secrets.adds;
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        assert_eq!(secrets.adds, adds);
        assert_eq!(profile.seed, Some([9; 32]));
        profile.seed = Some([4; 32]);
        let (keys, replaced) = load_keychain(&mut profile, &mut secrets).unwrap();
        assert_eq!(keys.sign_pk(), DeviceKeys::from_seed([4; 32]).sign_pk());
        assert!(replaced.is_none());
        assert_eq!(secrets.adds, adds + 1);
        assert_eq!(profile.seed, None);
        let adds = secrets.adds;
        profile.marker.as_mut().unwrap().version = 99;
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        assert_eq!(secrets.adds, adds);
    }

    #[test]
    fn restored_profile_without_its_keychain_identity_is_kept_and_replaced() {
        let mut profile = MemoryProfile { seed: Some([31; 32]), ..Default::default() };
        let mut secrets = MemorySecrets::default();
        let old = load_keychain(&mut profile, &mut secrets).unwrap().0.sign_pk();
        let marker = profile.marker.clone().unwrap();
        // A restore onto another device: the marker came back, the
        // device-only Keychain item did not.
        let mut restored = MemoryProfile { marker: Some(marker.clone()), established: true, ..Default::default() };
        let mut other_device = MemorySecrets::default();
        let (keys, replaced) = load_keychain(&mut restored, &mut other_device).unwrap();
        assert_eq!(replaced, Some(PathBuf::from("unrecoverable")));
        assert_ne!(keys.sign_pk(), old);
        let (_, kept_marker) = restored.kept.clone().unwrap();
        assert_eq!(kept_marker.unwrap().public_key, marker.public_key);
        // The new identity is now the device's and loads normally.
        let (again, replaced) = load_keychain(&mut restored, &mut other_device).unwrap();
        assert_eq!(again.sign_pk(), keys.sign_pk());
        assert!(replaced.is_none());
        // A Keychain that is merely unavailable never triggers a replacement.
        let mut locked = MemoryProfile { marker: Some(marker), established: true, ..Default::default() };
        let mut unavailable = MemorySecrets { read_failure: true, ..Default::default() };
        assert!(load_keychain(&mut locked, &mut unavailable).is_err());
        assert!(locked.kept.is_none() && locked.marker.is_some());
    }

    #[test]
    fn pending_without_seed_requires_matching_existing_slot() {
        let mut profile = MemoryProfile { seed: Some([5; 32]), crash_after: Some(1), ..Default::default() };
        let mut secrets = MemorySecrets::default();
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        let account = profile.marker.as_ref().unwrap().account.clone().unwrap();
        profile.seed = None;
        secrets.values.insert(account.clone(), [8; 32]);
        assert!(load_keychain(&mut profile, &mut secrets).is_err());
        assert!(profile.kept.is_none(), "a conflicting slot is never replaced");
        secrets.values.insert(account.clone(), [5; 32]);
        let mut resumed = profile.clone();
        assert_eq!(
            load_keychain(&mut resumed, &mut secrets).unwrap().0.sign_pk(),
            DeviceKeys::from_seed([5; 32]).sign_pk()
        );
        assert_eq!(secrets.adds, 0);
        // With neither the file seed nor the slot, the identity is gone: the
        // profile is kept aside rather than leaving the app unable to start.
        secrets.values.remove(&account);
        let (_, replaced) = load_keychain(&mut profile, &mut secrets).unwrap();
        assert!(replaced.is_some());
        assert!(profile.kept.as_ref().unwrap().1.is_some());
    }
}
