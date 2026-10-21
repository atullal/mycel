//! The Mycel Host: a Tauri shell around one `mycel_node::Runtime`.
//!
//! Every command in docs/RUNTIME_API.md is exposed as a `#[tauri::command]`
//! that forwards to the runtime held in managed state; runtime events are
//! forwarded to the webview as the `mycel://event` Tauri event. Apps never see
//! Tauri directly: they go through `@mycel/sdk`.
//!
//! Environment:
//! - `MYCEL_DATA_DIR`: where the runtime keeps keys and data (default: the
//!   platform app-data dir). Give each instance its own to run several on one
//!   machine.
//! - `MYCEL_NET`: `internet` (default: every path, including relays), `lan`
//!   (local paths only: same network, peer-to-peer Wi-Fi, Bluetooth) or
//!   `local`. Without it, the mode chosen in the Network panel is used.
//! - `MYCEL_LINKS`: which non-IP links to run (`all`, `none`, `awdl`, `ble`).
//! - `MYCEL_NAME`: display name to use when creating a new profile.
//! - `MYCEL_BLE_LOG`: Bluetooth link diagnostics on stderr / `mycel.log`
//!   (1, or 2 for every state change). Off by default in release builds,
//!   level 1 in debug builds that log to a file. Where there are no
//!   environment variables (a phone), a `link-diagnostics` file in the data
//!   folder holding the level turns them on (see `link_diagnostics`).

#[cfg(target_os = "android")]
mod android;
mod background;
mod commands;
mod notify;
mod open_file;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use mycel_node::api::{Event, NetworkMode};
use mycel_node::{Runtime, RuntimeOptions};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tokio::sync::broadcast::error::RecvError;

/// Tauri event carrying one runtime `Event` to the webview.
pub const EVENT: &str = "mycel://event";

/// Runtime handle kept in Tauri managed state.
pub type Rt = Arc<Runtime>;

fn network_mode(data_dir: &std::path::Path) -> Result<NetworkMode, String> {
    // Tests never reach a network (nor read the environment, which other
    // threads may be changing).
    if cfg!(test) {
        return Ok(NetworkMode::Local);
    }
    match std::env::var("MYCEL_NET").ok().as_deref().map(str::trim) {
        // An unreadable saved mode means local paths only, never wider.
        None | Some("") => Ok(Runtime::launch_network_mode(data_dir, NetworkMode::Internet)),
        Some("lan") => Ok(NetworkMode::Lan),
        Some("internet") => Ok(NetworkMode::Internet),
        Some("local") => Ok(NetworkMode::Local),
        Some(other) => Err(format!("MYCEL_NET={other:?} is not a network mode; use lan, internet or local")),
    }
}

/// Window title carries the profile name so several instances can be told apart.
pub(crate) fn set_window_title(app: &AppHandle, name: &str) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_title(&format!("{name} — Mycel"));
    }
}

/// The app, once there is a window: a phone can run the runtime before
/// (Android, `start_in_background`), and the window adopts it.
pub(crate) type AppSlot = Arc<OnceLock<AppHandle>>;

/// Forward runtime events to the webview until the runtime shuts down. The
/// chat layer's alerts go to the notification bridge instead (never blocks).
/// With no window yet, only the alerts go anywhere.
fn forward_events(app: AppSlot, runtime: Rt, notifier: Arc<notify::Notifier>) {
    // Subscribe before spawning so nothing emitted after startup is missed.
    let mut rx = runtime.subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) if event.is_for_shell() => notifier.on_event(&event),
                Ok(event) => {
                    let Some(app) = app.get() else { continue };
                    if let Err(e) = app.emit(EVENT, &event) {
                        eprintln!("mycel-host: failed to emit event: {e}");
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    let Some(app) = app.get() else { continue };
                    // We dropped events: tell the UI to refresh everything it shows.
                    eprintln!("mycel-host: event stream lagged by {skipped}; asking UI to refresh");
                    let mut refresh = vec![
                        Event::ContactsChanged,
                        Event::NearbyChanged,
                        Event::NetworkChanged,
                        Event::NoticesChanged,
                    ];
                    refresh.extend(
                        runtime.conversations().into_iter().map(|c| Event::ConversationUpdated { conversation: c.id }),
                    );
                    for event in refresh {
                        let _ = app.emit(EVENT, &event);
                    }
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}

/// Escape glob metacharacters so a literal path can be used inside a scope pattern.
fn glob_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '?' | '*' | '[' | ']' => {
                out.push('[');
                out.push(c);
                out.push(']');
            }
            _ => out.push(c),
        }
    }
    out
}

/// The webview may only show and open decrypted attachments, which the runtime
/// keeps under `<data dir>/files/`. Everything else in the data dir (keys, the
/// store) stays out of reach of the asset protocol and the opener.
///
/// The static capability already allows `$APPDATA/files/**`; this adds the
/// data dir actually in use (it differs when `MYCEL_DATA_DIR` is set).
fn allow_attachment_files(app: &tauri::App, data_dir: &std::path::Path) -> Result<(), String> {
    let files = data_dir.join("files");
    std::fs::create_dir_all(&files).map_err(|e| format!("cannot create {}: {e}", files.display()))?;

    // Show downloaded attachments (convertFileSrc).
    app.asset_protocol_scope().allow_directory(&files, true).map_err(|e| e.to_string())?;

    // Open them with the system app. Scope paths are glob patterns, so escape
    // the directory; list both the given and the canonical form (on macOS
    // /tmp is really /private/tmp, and the opener checks canonical paths).
    let mut dirs = vec![files.clone()];
    if let Ok(canonical) = std::fs::canonicalize(&files)
        && canonical != files
    {
        dirs.push(canonical);
    }
    let allowed: Vec<serde_json::Value> = dirs
        .iter()
        .map(|d| {
            let pattern = format!("{}/**", glob_escape(&d.to_string_lossy()));
            serde_json::json!({ "path": pattern })
        })
        .collect();
    app.add_capability(tauri::ipc::CapabilityBuilder::new("attachment-files").window("main").permission_scoped(
        "opener:allow-open-path",
        allowed,
        Vec::new(),
    ))
    .map_err(|e| format!("cannot allow opening attachments: {e}"))
}

/// Opened from Finder or the Start menu, or on a phone, there's no terminal,
/// so stderr (where the runtime and the peer-to-peer Wi-Fi / Bluetooth links
/// log) goes nowhere. Send it to `<data dir>/mycel.log` instead (the previous
/// run is kept as `mycel.log.1`). Called before the runtime opens, so
/// profile, storage and migration messages are in it too.
///
/// The log is private: created owner-only, never through a symlink (a fresh
/// file after rotation, and the previous one is narrowed to owner-only too).
/// Another copy of Mycel started on the same data folder stops at the
/// profile lease, but only after this: it leaves a log that's in use alone
/// instead of rotating it away (`log_in_use`).
fn log_to_file(data_dir: &std::path::Path) {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        return;
    }
    let path = data_dir.join("mycel.log");
    if log_in_use(&path) {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Ok(previous) =
            std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path)
            && previous.metadata().is_ok_and(|metadata| metadata.is_file())
        {
            let _ = previous.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
    }
    let _ = std::fs::rename(&path, data_dir.join("mycel.log.1"));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    if let Ok(file) = options.open(&path) {
        // Advisory and held as long as stderr points at the file (the lock
        // belongs to the open file, which dup2 shares): marks the log in use.
        #[cfg(unix)]
        let _ = file.try_lock();
        redirect_stderr(file);
        link_diagnostics(data_dir);
    }
}

/// Is another running copy of Mycel writing this log?
fn log_in_use(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // That copy holds an advisory lock on it (log_to_file). Ours is
        // released when `file` closes, before the rotation.
        let Ok(file) =
            std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
        else {
            return false;
        };
        file.metadata().is_ok_and(|m| m.is_file()) && matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // That copy keeps the file open for good (it's its stderr), so an
        // exclusive open fails. (No lock: Windows locks are mandatory and
        // would stop anyone reading the log while Mycel runs.)
        const ERROR_SHARING_VIOLATION: i32 = 32;
        matches!(
            std::fs::OpenOptions::new().read(true).share_mode(0).open(path),
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

/// Bluetooth and peer-to-peer Wi-Fi link diagnostics in the log. They name
/// nearby devices and when they came and went, so a release build leaves
/// them off unless asked: `MYCEL_BLE_LOG` (Android: the `debug.mycel.ble_log`
/// property), or, where a developer can't set either (an iPhone), a file
/// named `link-diagnostics` in the data folder holding the level, 1 or 2
/// (`xcrun devicectl device copy to --domain-type appDataContainer ...` on a
/// development-signed build). Debug builds turn level 1 on by themselves.
fn link_diagnostics(data_dir: &std::path::Path) {
    // Set once, before the runtime starts: never again once it runs (a
    // window adopting a background start logs to the file again).
    if std::env::var_os("MYCEL_BLE_LOG").is_some() || CORE.get().is_some() {
        return;
    }
    let level = diagnostics_level(&data_dir.join("link-diagnostics")).or(cfg!(debug_assertions).then_some(1));
    if let Some(level) = level {
        eprintln!("mycel-host: link diagnostics on (level {level})");
        // SAFETY: during startup, before the runtime (and its link threads)
        // starts and reads the environment.
        unsafe { std::env::set_var("MYCEL_BLE_LOG", level.to_string()) };
    }
}

/// The level in a `link-diagnostics` file: 1 when it's empty, nothing when
/// it's missing, not a regular file, or says something else.
fn diagnostics_level(path: &std::path::Path) -> Option<u8> {
    use std::io::Read;
    if !std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path).ok()?.take(16).read_to_string(&mut text).ok()?;
    match text.trim() {
        "" => Some(1),
        level => level.parse().ok().filter(|l| (1..=2).contains(l)),
    }
}

/// Retain exactly one owned copy of a pipe writer until its owner is dropped.
#[cfg(all(unix, any(target_os = "ios", test)))]
fn retain_pipe_writer(retained: &mut Option<std::os::fd::OwnedFd>, writer: std::os::fd::RawFd) -> std::io::Result<()> {
    use std::os::fd::FromRawFd;
    if retained.is_none() {
        // SAFETY: dup creates a separately owned descriptor; an error acquires
        // no descriptor and leaves the caller's original writer untouched.
        let duplicate = unsafe { libc::dup(writer) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error());
        }
        *retained = Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) });
    }
    Ok(())
}

#[cfg(all(unix, test))]
mod logging_tests {
    use super::retain_pipe_writer;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[test]
    fn retained_writer_prevents_eof_and_repeated_initialization_keeps_one_descriptor() {
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let flags = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }, 0);

        let mut retained = None;
        retain_pipe_writer(&mut retained, write.as_raw_fd()).unwrap();
        let duplicate = retained.as_ref().unwrap().as_raw_fd();
        for _ in 0..10 {
            retain_pipe_writer(&mut retained, write.as_raw_fd()).unwrap();
            assert_eq!(retained.as_ref().unwrap().as_raw_fd(), duplicate);
        }
        // Replacing stderr closes the original pipe writer. The retained copy
        // must leave an empty pipe pending, rather than permanently EOF-ready.
        drop(write);
        let mut byte = 0u8;
        assert_eq!(unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) }, -1);
        assert_eq!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock);
        drop(retained);
        assert_eq!(unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) }, 0);

        let mut failed = None;
        assert!(retain_pipe_writer(&mut failed, -1).is_err());
        assert!(failed.is_none());
    }

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("mycel-host-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_log_another_copy_is_writing_is_in_use_until_it_closes() {
        let dir = TempDir::new("log-in-use");
        let log = dir.0.join("mycel.log");
        assert!(!super::log_in_use(&log), "no log yet");
        let writer = std::fs::File::create(&log).unwrap();
        assert!(!super::log_in_use(&log), "an unlocked log is a leftover from a previous run");
        writer.try_lock().unwrap();
        assert!(super::log_in_use(&log));
        assert!(super::log_in_use(&log), "checking doesn't take the lock over");
        drop(writer);
        assert!(!super::log_in_use(&log));
    }

    #[test]
    fn link_diagnostics_file_gives_a_level_only_when_it_says_one() {
        let dir = TempDir::new("link-diagnostics");
        let file = dir.0.join("link-diagnostics");
        assert_eq!(super::diagnostics_level(&file), None);
        for (text, level) in
            [("", Some(1)), ("1", Some(1)), ("2\n", Some(2)), (" 2 ", Some(2)), ("0", None), ("7", None), ("yes", None)]
        {
            std::fs::write(&file, text).unwrap();
            assert_eq!(super::diagnostics_level(&file), level, "{text:?}");
        }
        std::fs::remove_file(&file).unwrap();
        let target = dir.0.join("elsewhere");
        std::fs::write(&target, "2").unwrap();
        std::os::unix::fs::symlink(&target, &file).unwrap();
        assert_eq!(super::diagnostics_level(&file), None, "a symlink is ignored");
    }
}

#[cfg(unix)]
fn redirect_stderr(file: std::fs::File) {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "ios")]
    {
        // Tauri's Swift reader does not cancel on EOF. Keep its pipe open
        // when redirecting stderr so an idle app cannot spin that reader.
        static PIPE_WRITER: std::sync::Mutex<Option<std::os::fd::OwnedFd>> = std::sync::Mutex::new(None);
        let retained = PIPE_WRITER
            .lock()
            .map_err(|_| std::io::Error::other("iOS logging writer lock poisoned"))
            .and_then(|mut writer| retain_pipe_writer(&mut writer, libc::STDERR_FILENO));
        if let Err(error) = retained {
            eprintln!("mycel-host: cannot retain iOS logging pipe: {error}");
            return;
        }
    }
    // SAFETY: dup2 onto stderr; `file` stays open until dup2 has copied it.
    unsafe { libc::dup2(file.as_raw_fd(), 2) };
}

#[cfg(windows)]
fn redirect_stderr(file: std::fs::File) {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, SetStdHandle};
    // Rust's stderr looks the handle up on every write. The handle is leaked
    // on purpose: it stays stderr until the app exits.
    // SAFETY: SetStdHandle with a valid, open file handle.
    unsafe { SetStdHandle(STD_ERROR_HANDLE, file.into_raw_handle()) };
}

/// The name a new profile starts with on iOS and iPadOS ("iPhone", or the
/// name the user gave the device where iOS shares it). UIKit only answers on
/// the main thread, where Tauri runs `setup`; elsewhere the runtime picks.
#[cfg(target_os = "ios")]
fn device_name() -> Option<String> {
    let mtm = objc2::MainThreadMarker::new()?;
    let name = objc2_ui_kit::UIDevice::currentDevice(mtm).name().to_string();
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(not(target_os = "ios"))]
fn device_name() -> Option<String> {
    None
}

/// iPhone and iPad: let the page run under the status bar and home indicator
/// and pad itself (viewport-fit=cover and env(safe-area-inset-*) in the
/// CSS); by default WKWebView insets it and paints the bars white. And no
/// rubber-band bounce of the whole app.
#[cfg(target_os = "ios")]
fn edge_to_edge(window: &tauri::WebviewWindow) {
    use objc2::msg_send;
    use objc2::runtime::{AnyObject, Bool};
    let _ = window.with_webview(|webview| {
        // SAFETY: Tauri hands out the live WKWebView; -scrollView returns its
        // UIScrollView, and both setters take plain values
        // (UIScrollViewContentInsetAdjustmentNever = 2).
        unsafe {
            let Some(wk) = (webview.inner() as *mut AnyObject).as_ref() else { return };
            let scroll: *mut AnyObject = msg_send![wk, scrollView];
            let Some(scroll) = scroll.as_ref() else { return };
            let _: () = msg_send![scroll, setContentInsetAdjustmentBehavior: 2isize];
            let _: () = msg_send![scroll, setBounces: Bool::NO];
        }
    });
}

/// Flush as soon as the app is suspended and before releasing its remaining
/// background time. The expiration handler ends the UIKit task exactly once.
#[cfg(target_os = "ios")]
fn finish_in_background(handle: &AppHandle) {
    use objc2::MainThreadMarker;
    use objc2_ui_kit::{UIApplication, UIBackgroundTaskInvalid};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn end_task(task: &AtomicUsize) {
        let Some(mtm) = MainThreadMarker::new() else { return };
        // SAFETY: UIKit's immutable exported invalid-task sentinel.
        let invalid = unsafe { UIBackgroundTaskInvalid };
        let id = task.swap(invalid, Ordering::AcqRel);
        if id != invalid {
            UIApplication::sharedApplication(mtm).endBackgroundTask(id);
        }
    }

    let Some(mtm) = MainThreadMarker::new() else { return };
    let Some(runtime) = handle.try_state::<Rt>().map(|rt| rt.inner().clone()) else { return };
    // SAFETY: UIKit's immutable exported invalid-task sentinel.
    let invalid = unsafe { UIBackgroundTaskInvalid };
    let task = Arc::new(AtomicUsize::new(invalid));
    let expiration_task = task.clone();
    let expiration = block2::RcBlock::new(move || end_task(&expiration_task));
    let id = UIApplication::sharedApplication(mtm).beginBackgroundTaskWithExpirationHandler(Some(&expiration));
    task.store(id, Ordering::Release);
    let handle = handle.clone();
    std::thread::spawn(move || {
        if let Err(error) = runtime.flush() {
            eprintln!("mycel-host: background persistence failed: {error}");
        }
        if id == invalid {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(25));
        if let Err(error) = runtime.flush() {
            eprintln!("mycel-host: background persistence failed: {error}");
        }
        let _ = handle.run_on_main_thread(move || end_task(&task));
    });
}

/// The main window, from tauri.conf.json (`"create": false` there: see `run`).
fn open_main_window(app: &AppHandle) -> tauri::Result<()> {
    let Some(config) = app.config().app.windows.iter().find(|w| w.label == "main").cloned() else {
        return Ok(());
    };
    let builder = tauri::WebviewWindowBuilder::from_config(app, &config)?;
    // Windows and Linux: the page captures the camera itself for calls
    // (the SDK's webcam.ts), and only once someone turns their camera on.
    // The system's own camera setting still applies.
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    let builder = builder.on_permission_request(|_, kind| match kind {
        tauri::webview::PermissionKind::Camera => tauri::webview::PermissionResponse::Allow,
        _ => tauri::webview::PermissionResponse::Default,
    });
    let window = builder.build()?;
    #[cfg(target_os = "ios")]
    edge_to_edge(&window);
    #[cfg(target_os = "linux")]
    enable_camera_capture(&window);
    #[cfg(not(any(target_os = "ios", target_os = "linux")))]
    let _ = window;
    if let Some(rt) = app.try_state::<Rt>() {
        set_window_title(app, &rt.profile().name);
    }
    Ok(())
}

/// WebKitGTK leaves `getUserMedia` out unless its media-stream setting is on.
#[cfg(target_os = "linux")]
fn enable_camera_capture(window: &tauri::WebviewWindow) {
    let _ = window.with_webview(|wv| {
        use webkit2gtk::{SettingsExt, WebViewExt};
        if let Some(settings) = WebViewExt::settings(&wv.inner()) {
            settings.set_enable_media_stream(true);
        }
    });
}

/// Android: swiping Mycel away from recents destroys its activity, not the
/// app. MycelService keeps the process, so the runtime keeps receiving; when
/// the app is opened again, MainActivity.onCreate calls this to give the new
/// activity a window (tao binds it to the activity that has none).
#[cfg(target_os = "android")]
static APP: std::sync::OnceLock<AppHandle> = std::sync::OnceLock::new();

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_mycel_host_MainActivity_onActivityReady(
    _env: jni::JNIEnv,
    _activity: jni::objects::JObject,
) {
    let Some(app) = APP.get() else { return }; // the first activity: setup opens it
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if handle.get_webview_window("main").is_none()
            && let Err(e) = open_main_window(&handle)
        {
            eprintln!("mycel-host: can't reopen the window: {e}");
        }
    });
}

/// Android apps get no environment. For testing, `debug.mycel.<name>`
/// system properties (`adb shell setprop debug.mycel.audio test`) stand in
/// for the `MYCEL_<NAME>` variables documented at the top of this file and
/// in the crates (`MYCEL_AUDIO`, `MYCEL_VIDEO_DEBUG`, `MYCEL_NET`, ...).
#[cfg(target_os = "android")]
fn env_from_properties() {
    for name in ["AUDIO", "VIDEO_DEBUG", "NET", "LINKS", "MESH", "BLE_LOG"] {
        let var = format!("MYCEL_{name}");
        if std::env::var_os(&var).is_some() {
            continue;
        }
        let Ok(key) = std::ffi::CString::new(format!("debug.mycel.{}", name.to_ascii_lowercase())) else { continue };
        let mut value = [0 as std::ffi::c_char; 92]; // PROP_VALUE_MAX
        // SAFETY: a NUL-terminated key and a PROP_VALUE_MAX buffer.
        if unsafe { libc::__system_property_get(key.as_ptr(), value.as_mut_ptr()) } > 0 {
            // SAFETY: NUL-terminated by __system_property_get.
            let v = unsafe { std::ffi::CStr::from_ptr(value.as_ptr()) }.to_string_lossy().into_owned();
            // SAFETY: during startup, before the runtime's threads read the environment.
            unsafe { std::env::set_var(&var, v) };
        }
    }
}

/// What runs with or without a window: the runtime, the alert bridge and
/// the event forwarder. One per process.
pub(crate) struct Core {
    pub(crate) runtime: Rt,
    pub(crate) notifier: Arc<notify::Notifier>,
    app: AppSlot,
}

static CORE: OnceLock<Core> = OnceLock::new();
/// Held while opening, so a background start and a window opening at the
/// same moment never both open the profile: the second adopts the first's.
static OPENING: Mutex<()> = Mutex::new(());

/// The open core, if any (background catch-ups use it).
#[cfg_attr(not(any(target_os = "android", target_os = "ios")), allow(dead_code))]
pub(crate) fn core() -> Option<&'static Core> {
    CORE.get()
}

/// Open the core for `data_dir`, once per process. `app`: the window's app;
/// `None` is a start with nobody watching (no window), which opens only an
/// existing profile (`Ok(None)` otherwise): a new profile is named and
/// created in the app, never behind the user's back. A core opened in the
/// background is adopted by the window that opens later.
fn open_core(data_dir: &Path, app: Option<AppHandle>) -> Result<Option<&'static Core>, String> {
    let _opening = OPENING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(core) = CORE.get() {
        // One profile per process: say so if a caller wanted another folder
        // (both entry points read MYCEL_DATA_DIR, so they shouldn't).
        if core.runtime.data_dir() != data_dir {
            eprintln!(
                "mycel-host: asked to open {} but {} is open; using it",
                data_dir.display(),
                core.runtime.data_dir().display()
            );
        }
        if let Some(app) = app {
            let _ = core.app.set(app);
        }
        return Ok(Some(core));
    }
    let watched = app.is_some();
    if !watched && !Runtime::profile_exists(data_dir).unwrap_or(false) {
        return Ok(None);
    }
    let mode = network_mode(data_dir)?;
    let name = std::env::var("MYCEL_NAME").ok().filter(|n| !n.trim().is_empty());
    let runtime: Rt = tauri::async_runtime::block_on(Runtime::open_with(RuntimeOptions {
        data_dir: data_dir.to_path_buf(),
        mode,
        name,
        default_name: if watched { device_name() } else { None },
        keeper: false,
        port: 0,
    }))
        .map_err(|e| {
            let hint = if e.to_string().contains("already open") {
                "\n\nAnother copy of Mycel is already using this data folder. Quit it first, or give this copy its own folder with MYCEL_DATA_DIR."
            } else {
                ""
            };
            format!("cannot open Mycel data in {}: {e:#}{hint}", data_dir.display())
        })?;
    let slot: AppSlot = Arc::new(OnceLock::new());
    if let Some(app) = app {
        let _ = slot.set(app);
    }
    let notifier = notify::Notifier::start(slot.clone(), data_dir);
    // Nobody is looking until a window says so, nor when iOS launched the
    // app straight into the background (a catch-up, a Bluetooth event): an
    // incoming call must ring as a notification then.
    let away = notify::starts_away(watched, watched && launched_in_background());
    notifier.set_away(away);
    if away && cfg!(mobile) {
        runtime.set_background(true);
    }
    forward_events(slot.clone(), runtime.clone(), notifier.clone());
    eprintln!(
        "mycel-host: data dir {}, network {:?}{}",
        data_dir.display(),
        mode,
        if watched { "" } else { ", started in the background" }
    );
    Ok(Some(CORE.get_or_init(|| Core { runtime, notifier, app: slot })))
}

/// iOS launched the app straight into the background (`BGTaskScheduler`, or
/// a relaunch for a Bluetooth event): it has a window, but nobody is
/// looking, and no `Suspended` event will say so.
#[cfg(target_os = "ios")]
fn launched_in_background() -> bool {
    use objc2::MainThreadMarker;
    use objc2_ui_kit::{UIApplication, UIApplicationState};
    // Setup runs on the main thread, during launch.
    let Some(mtm) = MainThreadMarker::new() else { return false };
    UIApplication::sharedApplication(mtm).applicationState() == UIApplicationState::Background
}

#[cfg(not(target_os = "ios"))]
fn launched_in_background() -> bool {
    false
}

/// On a phone, whether `event` sends the app to the background (`true`) or
/// brings it back (`false`): radios link only with known devices while
/// it's away ([`Runtime::set_background`]). Focus alone doesn't count (a
/// pulled-down notification centre would drop links to strangers).
#[cfg(mobile)]
fn background_change(event: &WindowEvent) -> Option<bool> {
    match event {
        WindowEvent::Suspended | WindowEvent::Destroyed => Some(true),
        WindowEvent::Resumed => Some(false),
        _ => None,
    }
}

/// `MYCEL_DATA_DIR`, if set: the data folder instead of the app's own.
fn data_dir_override() -> Option<PathBuf> {
    std::env::var_os("MYCEL_DATA_DIR").filter(|dir| !dir.is_empty()).map(PathBuf::from)
}

/// Open the runtime with no window (Android after a reboot or an update, a
/// restarted service, a background catch-up), for an existing profile only.
/// True once a runtime is running in this process.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn start_in_background(data_dir: PathBuf) -> bool {
    if CORE.get().is_some() {
        return true;
    }
    #[cfg(target_os = "android")]
    env_from_properties();
    // The same folder a window would open (`start`).
    let data_dir = data_dir_override().unwrap_or(data_dir);
    if std::fs::create_dir_all(&data_dir).is_err() {
        return false;
    }
    log_to_file(&data_dir);
    match open_core(&data_dir, None) {
        Ok(core) => core.is_some(),
        Err(msg) => {
            eprintln!("mycel-host: background start failed: {msg}");
            false
        }
    }
}

/// Open the runtime (or adopt the one a background start opened) and wire
/// it to the app.
fn start(app: &mut tauri::App) -> Result<(), String> {
    #[cfg(target_os = "android")]
    if CORE.get().is_none() {
        env_from_properties();
    }
    let data_dir = match data_dir_override() {
        Some(dir) => dir,
        None => app.path().app_data_dir().map_err(|e| format!("cannot find the app data folder: {e}"))?,
    };
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("cannot create data dir {}: {e}", data_dir.display()))?;
    // Also after a background start: tao points stderr at logcat when the
    // first activity is created, so this takes it back (the background
    // start's log becomes mycel.log.1).
    log_to_file(&data_dir);
    let core = open_core(&data_dir, Some(app.handle().clone()))?.ok_or("Mycel couldn't open its data")?;
    // The folder actually open (a background start was told it by Android).
    allow_attachment_files(app, core.runtime.data_dir())?;
    app.manage(core.notifier.clone());
    app.manage(core.runtime.clone());
    Ok(())
}

/// Startup failed: hide the (unusable) window, show the reason, then quit.
fn fail_to_start(app: &AppHandle, msg: String) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
    eprintln!("mycel-host: {msg}");
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    let handle = app.clone();
    app.dialog().message(msg).title("Mycel can't start").kind(MessageDialogKind::Error).show(move |_| handle.exit(1));
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let started = start(app);
            // The window (`"create": false` in tauri.conf.json) opens only
            // now, once the runtime is managed: a page that loads faster than
            // the runtime opens (as on phones) would otherwise get "state not
            // managed" from its first commands. It opens on failure too, so
            // phones have a window to show the error on.
            open_main_window(app.handle())?;
            #[cfg(target_os = "android")]
            let _ = APP.set(app.handle().clone());
            match started {
                Ok(()) => {
                    let name = app.state::<Rt>().profile().name;
                    set_window_title(app.handle(), &name);
                }
                // Returning an error from setup makes Tauri panic (a native
                // app then just "quits unexpectedly"). Say what went wrong.
                Err(msg) => fail_to_start(app.handle(), msg),
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            background::background_status,
            background::request_background_exemption,
            notify::prepare_notifications,
            notify::set_notification_context,
            notify::notification_target,
            notify::take_notification_action,
            commands::get_profile,
            commands::set_name,
            commands::add_contact,
            commands::add_nearby_contact,
            commands::remove_contact,
            commands::list_contacts,
            commands::list_nearby,
            commands::list_notices,
            commands::dismiss_notice,
            commands::network_status,
            commands::set_network_mode,
            commands::restart_app,
            commands::open_file,
            commands::list_conversations,
            commands::get_conversation,
            commands::create_conversation,
            commands::list_messages,
            commands::messages_around,
            commands::send_message,
            commands::edit_message,
            commands::delete_message,
            commands::delete_message_local,
            commands::restore_message_local,
            commands::search_messages,
            commands::toggle_reaction,
            commands::mark_read,
            commands::set_typing,
            commands::add_members,
            commands::remove_member,
            commands::add_keeper,
            commands::rename_conversation,
            commands::fetch_attachment,
            commands::accept_request,
            commands::decline_request,
            commands::stage_file,
            commands::start_call,
            commands::accept_call,
            commands::decline_call,
            commands::end_call,
            commands::set_muted,
            commands::call_status,
            commands::set_camera,
            commands::video_keyframe,
            commands::video_subscribe,
            commands::video_targets,
            commands::video_push,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the Mycel host");

    app.run(|app, event| {
        // Whether anyone is looking, for notifications.
        // Android: the window goes when the activity does (swiped away from
        // recents); keep the app and its runtime (see `onActivityReady`).
        #[cfg(target_os = "android")]
        if let RunEvent::ExitRequested { api, code: None, .. } = &event {
            api.prevent_exit();
        }
        let away = match &event {
            RunEvent::WindowEvent { label, event, .. } if label == "main" => match event {
                WindowEvent::Focused(focused) => Some(!focused),
                WindowEvent::Destroyed => Some(true),
                #[cfg(mobile)]
                WindowEvent::Suspended => Some(true),
                #[cfg(mobile)]
                WindowEvent::Resumed => Some(false),
                _ => None,
            },
            _ => None,
        };
        if let Some(away) = away
            && let Some(notifier) = app.try_state::<Arc<notify::Notifier>>()
        {
            notifier.set_away(away);
        }
        #[cfg(mobile)]
        if let RunEvent::WindowEvent { label, event, .. } = &event
            && label == "main"
            && let Some(background) = background_change(event)
            && let Some(runtime) = app.try_state::<Rt>()
        {
            runtime.set_background(background);
        }
        #[cfg(target_os = "ios")]
        if let RunEvent::WindowEvent { event: WindowEvent::Suspended, .. } = &event {
            finish_in_background(app);
        }
        if let RunEvent::Exit = event
            && let Some(runtime) = app.try_state::<Rt>()
        {
            let runtime = runtime.inner().clone();
            if let Err(e) = tauri::async_runtime::block_on(runtime.shutdown()) {
                eprintln!("mycel-host: runtime shutdown failed: {e}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Tests that touch the process-wide core, the one-catch-up-at-a-time
    /// flag or the catch-up tickets take this, so they never overlap.
    pub(crate) fn serial() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: Mutex<()> = Mutex::new(());
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn eventually(what: &str, mut check: impl FnMut() -> bool) {
        for _ in 0..200 {
            if check() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for: {what}");
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("mycel-host-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Regression: the `bluetooth-peripheral` background mode kept a locked
    /// iPhone advertising and serving its node key to anyone in Bluetooth
    /// range, all day. Background modes in both copies of the iOS
    /// Info.plist (Tauri's source and the Xcode project's).
    #[test]
    fn ios_never_advertises_over_bluetooth_in_the_background() {
        for plist in [include_str!("../Info.ios.plist"), include_str!("../gen/apple/mycel-host_iOS/Info.plist")] {
            let modes = plist.split("<key>UIBackgroundModes</key>").nth(1).expect("background modes declared");
            let modes = &modes[..modes.find("</array>").expect("an array")];
            assert!(!modes.contains("bluetooth-peripheral"), "{modes}");
            for mode in ["fetch", "processing", "bluetooth-central"] {
                assert!(modes.contains(&format!("<string>{mode}</string>")), "{mode} missing: {modes}");
            }
        }
    }

    /// The whole windowless lifecycle in one test: the core is one per
    /// process, so its steps can't run as separate tests.
    #[test]
    fn a_windowless_start_opens_only_an_existing_profile_and_catches_up() {
        let _serial = serial();
        assert!(CORE.get().is_none(), "nothing else in this binary opens the core");

        // With no runtime there is nothing to catch up with.
        assert!(!background::catch_up_now(background::begin_catch_up(), Duration::from_secs(5)));

        // No profile: nothing opens, nothing is created behind the user's back.
        let empty = temp_dir("empty");
        assert!(open_core(&empty, None).unwrap().is_none());
        assert!(CORE.get().is_none());
        assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0, "the folder stays empty");

        // A profile made in the app (here directly): Bob, who shares a
        // conversation with Alice. Then his phone sleeps (closed).
        let dir = temp_dir("profile");
        let alice_dir = temp_dir("alice");
        let open = |dir: &Path, name: &str| {
            tauri::async_runtime::block_on(Runtime::open_with(RuntimeOptions {
                data_dir: dir.to_path_buf(),
                mode: NetworkMode::Local,
                name: Some(name.into()),
                default_name: None,
                keeper: false,
                port: 0,
            }))
            .unwrap()
        };
        let made = open(&dir, "bob");
        let alice = open(&alice_dir, "alice");
        let bob_contact = alice.add_contact(made.profile().contact_code).unwrap();
        made.add_contact(alice.profile().contact_code).unwrap();
        alice.node().add_peer_addr(made.node().addr());
        made.node().add_peer_addr(alice.node().addr());
        let conversation = alice.create_conversation(None, vec![bob_contact.id]).unwrap().id;
        eventually("Bob has the conversation", || made.conversation(conversation.clone()).is_ok());
        let id = made.profile().id;
        tauri::async_runtime::block_on(made.shutdown()).unwrap();
        drop(made);
        // Alice writes while Bob's phone is asleep.
        tauri::async_runtime::block_on(alice.send_message(
            conversation.clone(),
            "while you slept".into(),
            None,
            vec![],
        ))
        .unwrap();
        let bodies = |rt: &Rt| -> Vec<String> {
            rt.messages(conversation.clone(), None, None).unwrap().into_iter().map(|m| m.body).collect()
        };

        // Opened with no window, as that profile.
        let core = open_core(&dir, None).unwrap().expect("an existing profile opens");
        assert_eq!(core.runtime.profile().id, id);
        assert_eq!(core.runtime.data_dir(), dir.as_path());
        assert!(core.app.get().is_none(), "no window yet");
        assert!(core.notifier.is_away_for_test(), "nobody is looking");

        // Later opens (the window's, a second background start) adopt it
        // rather than opening the profile twice. A different folder gets
        // the open core too (logged), never a second runtime.
        assert!(std::ptr::eq(open_core(&dir, None).unwrap().unwrap(), core));
        assert!(std::ptr::eq(open_core(&empty, None).unwrap().unwrap(), core));
        assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);
        assert!(std::ptr::eq(super::core().unwrap(), core));

        // A catch-up against the real runtime delivers what Alice wrote:
        // sync, linger, flush; only a completed one is recorded. (Alice has
        // Bob's old address only, so nothing reaches him before it.)
        core.runtime.node().add_peer_addr(alice.node().addr());
        assert!(!bodies(&core.runtime).contains(&"while you slept".to_string()));
        let ticket = background::begin_catch_up();
        let start = std::time::Instant::now();
        assert!(background::catch_up_for_test(ticket, Duration::from_secs(15), Duration::from_millis(200)));
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(bodies(&core.runtime).contains(&"while you slept".to_string()), "the catch-up delivered it");
        let recorded = background::last_catch_up_for_test();
        assert!(recorded.is_some());

        // A message Alice pushes while the catch-up lingers arrives too.
        alice.node().add_peer_addr(core.runtime.node().addr());
        let pusher = {
            let (alice, conversation) = (alice.clone(), conversation.clone());
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(500));
                tauri::async_runtime::block_on(alice.send_message(
                    conversation,
                    "during the linger".into(),
                    None,
                    vec![],
                ))
                .unwrap();
            })
        };
        let ticket = background::begin_catch_up();
        assert!(background::catch_up_for_test(ticket, Duration::from_secs(15), Duration::from_secs(4)));
        pusher.join().unwrap();
        assert!(bodies(&core.runtime).contains(&"during the linger".to_string()), "pushed during the linger");

        // A sync the budget cuts short (a peer that stalls) isn't a check.
        std::thread::sleep(Duration::from_millis(5));
        let recorded = background::last_catch_up_for_test();
        let ticket = background::begin_catch_up();
        assert!(!background::stalled_catch_up_for_test(ticket, Duration::from_secs(4)));
        assert_eq!(background::last_catch_up_for_test(), recorded, "an incomplete catch-up isn't recorded");

        tauri::async_runtime::block_on(alice.shutdown()).unwrap();
        let _ = std::fs::remove_dir_all(&alice_dir);
        tauri::async_runtime::block_on(core.runtime.shutdown()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty);
    }
}
