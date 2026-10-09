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

mod commands;
mod open_file;

use std::path::PathBuf;
use std::sync::Arc;

use mycel_node::{Runtime, RuntimeOptions};
use mycel_node::api::{Event, NetworkMode};
use tauri::{AppHandle, Emitter, Manager, RunEvent};
use tokio::sync::broadcast::error::RecvError;

/// Tauri event carrying one runtime `Event` to the webview.
pub const EVENT: &str = "mycel://event";

/// Runtime handle kept in Tauri managed state.
pub type Rt = Arc<Runtime>;

fn network_mode(data_dir: &std::path::Path) -> Result<NetworkMode, String> {
    match std::env::var("MYCEL_NET").ok().as_deref().map(str::trim) {
        None | Some("") => Ok(Runtime::saved_network_mode(data_dir).unwrap_or(NetworkMode::Internet)),
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

/// Forward runtime events to the webview until the runtime shuts down.
fn forward_events(app: AppHandle, runtime: Rt) {
    // Subscribe before spawning so nothing emitted after startup is missed.
    let mut rx = runtime.subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
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
/// run is kept as `mycel.log.1`).
fn log_to_file(data_dir: &std::path::Path) {
    use std::io::IsTerminal;
    if std::io::stderr().is_terminal() {
        return;
    }
    let path = data_dir.join("mycel.log");
    let _ = std::fs::rename(&path, data_dir.join("mycel.log.1"));
    if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        redirect_stderr(file);
    }
    if std::env::var_os("MYCEL_BLE_LOG").is_none() {
        // SAFETY: called during startup, before other threads read the environment.
        unsafe { std::env::set_var("MYCEL_BLE_LOG", "1") };
    }
}

#[cfg(unix)]
fn redirect_stderr(file: std::fs::File) {
    use std::os::fd::AsRawFd;
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

/// Open the runtime and wire it to the app.
fn start(app: &mut tauri::App) -> Result<(), String> {
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

    forward_events(app.handle().clone(), runtime.clone());
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
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let started = start(app);
            // The window (`"create": false` in tauri.conf.json) opens only
            // now, once the runtime is managed: a page that loads faster than
            // the runtime opens (as on phones) would otherwise get "state not
            // managed" from its first commands. It opens on failure too, so
            // phones have a window to show the error on.
            let config = app.config().app.windows.iter().find(|w| w.label == "main").cloned();
            if let Some(config) = config {
                let window = tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?.build()?;
                #[cfg(target_os = "ios")]
                edge_to_edge(&window);
                #[cfg(not(target_os = "ios"))]
                let _ = window;
            }
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
            commands::get_profile,
            commands::set_name,
            commands::add_contact,
            commands::add_nearby_contact,
            commands::remove_contact,
            commands::list_contacts,
            commands::list_nearby,
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
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the Mycel host");

    app.run(|app, event| {
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
