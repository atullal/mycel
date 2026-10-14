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

mod commands;
mod notify;
mod open_file;

use std::path::PathBuf;
use std::sync::Arc;

use mycel_node::{Runtime, RuntimeOptions};
use mycel_node::api::{Event, NetworkMode};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tokio::sync::broadcast::error::RecvError;

/// Tauri event carrying one runtime `Event` to the webview.
pub const EVENT: &str = "mycel://event";

/// Runtime handle kept in Tauri managed state.
pub type Rt = Arc<Runtime>;

fn network_mode(data_dir: &std::path::Path) -> Result<NetworkMode, String> {
    match std::env::var("MYCEL_NET").ok().as_deref().map(str::trim) {
        // An unreadable saved mode means local paths only, never wider.
        None | Some("") => Ok(Runtime::launch_network_mode(data_dir, NetworkMode::Internet)),
        Some("lan") => Ok(NetworkMode::Lan),
        Some("internet") => Ok(NetworkMode::Internet),
        Some("local") => Ok(NetworkMode::Local),
        Some(other) => Err(format!(
            "MYCEL_NET={other:?} is not a network mode; use lan, internet or local"
        )),
    }
}

/// Window title carries the profile name so several instances can be told apart.
pub(crate) fn set_window_title(app: &AppHandle, name: &str) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_title(&format!("{name} — Mycel"));
    }
}

/// Forward runtime events to the webview until the runtime shuts down. The
/// chat layer's alerts go to the notification bridge instead (never blocks).
fn forward_events(app: AppHandle, runtime: Rt, notifier: Arc<notify::Notifier>) {
    // Subscribe before spawning so nothing emitted after startup is missed.
    let mut rx = runtime.subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) if event.is_for_shell() => notifier.on_event(&event),
                Ok(event) => {
                    if let Err(e) = app.emit(EVENT, &event) {
                        eprintln!("mycel-host: failed to emit event: {e}");
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    // We dropped events: tell the UI to refresh everything it shows.
                    eprintln!("mycel-host: event stream lagged by {skipped}; asking UI to refresh");
                    let mut refresh = vec![
                        Event::ContactsChanged,
                        Event::NearbyChanged,
                        Event::NetworkChanged,
                        Event::NoticesChanged,
                    ];
                    refresh.extend(
                        runtime
                            .conversations()
                            .into_iter()
                            .map(|c| Event::ConversationUpdated { conversation: c.id }),
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
    std::fs::create_dir_all(&files)
        .map_err(|e| format!("cannot create {}: {e}", files.display()))?;

    // Show downloaded attachments (convertFileSrc).
    app.asset_protocol_scope()
        .allow_directory(&files, true)
        .map_err(|e| e.to_string())?;

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
    app.add_capability(
        tauri::ipc::CapabilityBuilder::new("attachment-files")
            .window("main")
            .permission_scoped("opener:allow-open-path", allowed, Vec::new()),
    )
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
        if let Ok(previous) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
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
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
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
    if std::env::var_os("MYCEL_BLE_LOG").is_some() {
        return;
    }
    let level = diagnostics_level(&data_dir.join("link-diagnostics"))
        .or(cfg!(debug_assertions).then_some(1));
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
fn retain_pipe_writer(
    retained: &mut Option<std::os::fd::OwnedFd>,
    writer: std::os::fd::RawFd,
) -> std::io::Result<()> {
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
        assert_eq!(
            unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );

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
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(retained);
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            0
        );

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
        for (text, level) in [("", Some(1)), ("1", Some(1)), ("2\n", Some(2)), (" 2 ", Some(2)), ("0", None), ("7", None), ("yes", None)] {
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
        static PIPE_WRITER: std::sync::Mutex<Option<std::os::fd::OwnedFd>> =
            std::sync::Mutex::new(None);
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use objc2::MainThreadMarker;
    use objc2_ui_kit::{UIApplication, UIBackgroundTaskInvalid};

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
    let id = UIApplication::sharedApplication(mtm)
        .beginBackgroundTaskWithExpirationHandler(Some(&expiration));
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

/// Open the runtime and wire it to the app.
fn start(app: &mut tauri::App) -> Result<(), String> {
    #[cfg(target_os = "android")]
    env_from_properties();
    let data_dir = match std::env::var_os("MYCEL_DATA_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => app
            .path()
            .app_data_dir()
            .map_err(|e| format!("cannot find the app data folder: {e}"))?,
    };
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("cannot create data dir {}: {e}", data_dir.display()))?;
    log_to_file(&data_dir);
    let mode = network_mode(&data_dir)?;
    let name = std::env::var("MYCEL_NAME")
        .ok()
        .filter(|n| !n.trim().is_empty());

    let runtime: Rt = tauri::async_runtime::block_on(Runtime::open_with(RuntimeOptions {
        data_dir: data_dir.clone(),
        mode,
        name,
        default_name: device_name(),
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

    allow_attachment_files(app, &data_dir)?;

    let notifier = notify::Notifier::start(app.handle().clone(), &data_dir);
    forward_events(app.handle().clone(), runtime.clone(), notifier.clone());
    app.manage(notifier);
    app.manage(runtime);

    eprintln!(
        "mycel-host: data dir {}, network {:?}",
        data_dir.display(),
        mode
    );
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
    app.dialog()
        .message(msg)
        .title("Mycel can't start")
        .kind(MessageDialogKind::Error)
        .show(move |_| handle.exit(1));
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
