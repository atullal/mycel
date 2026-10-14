//! The OS side of private local alerts.
//!
//! The chat layer decides what is news (`mycel_kit_chat::alerts`) and emits
//! `Event::Alert` / `Event::AlertWithdrawn`; this bridge holds no messaging
//! rules. It only:
//! - shows each alert kind as one fixed, generic sentence: no names, text,
//!   conversation IDs or payload reach the OS;
//! - routes taps through opaque OS ids that are never reused;
//! - suppresses alerts about what's on screen while the app is focused;
//! - asks for permission in the foreground.
//!
//! OS calls run on one worker thread, never on the async runtime that
//! forwards events (Tauri's mobile bridge blocks on the main thread).
//! iOS can only post these while its process is running: this is not a
//! remote push service.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use mycel_node::api::{Alert, AlertKind, Event};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
#[cfg(not(target_os = "android"))]
use tauri_plugin_notification::NotificationExt;

use crate::Rt;

/// All the OS ever shows: one fixed sentence per kind.
fn content(kind: AlertKind) -> (&'static str, &'static str) {
    (
        "Mycel",
        match kind {
            AlertKind::Message => "New message",
            AlertKind::MessageRequest => "New message request",
            AlertKind::GroupInvitation => "New group invitation",
            AlertKind::IncomingCall => "Incoming call",
            AlertKind::MissedCall => "Missed call",
        },
    )
}

/// Delivered alerts that stay routable.
const MAX_ROUTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Route {
    /// What a tap opens (resolved again by the runtime when tapped).
    target: String,
    thread: String,
    key: String,
}

/// Opaque OS notification ids and what they open. Kept only in Mycel's
/// sandbox, across restarts. Ids are never reused: `last_id` only grows, and
/// a table that can't be read starts over at a random point after clearing
/// delivered alerts, so an old retained alert can never open another chat.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Routes {
    last_id: i32,
    entries: BTreeMap<i32, Route>,
}

/// Delivered alerts to take off the screen.
#[derive(Debug, Default, PartialEq, Eq)]
struct Removal {
    ids: Vec<i32>,
    /// Every delivered alert (the ids started over).
    all: bool,
}

impl Removal {
    #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
    fn is_empty(&self) -> bool {
        self.ids.is_empty() && !self.all
    }
}

impl Routes {
    /// A new table whose ids can't meet those of a lost one (well clear of
    /// `i32::MAX`, so it won't wrap in practice either).
    fn fresh() -> Routes {
        let start = 1 + (mycel_node::crypto::random_u64() % (1 << 30)) as i32;
        Routes { last_id: start, entries: BTreeMap::new() }
    }

    /// The table on disk, or a fresh one (`true`) if missing or unreadable:
    /// delivered alerts can then no longer be routed and must be cleared.
    fn load(path: &Path) -> (Routes, bool) {
        let stored = std::fs::read(path)
            .ok()
            .and_then(|data| serde_json::from_slice::<Routes>(&data).ok())
            .filter(|routes| routes.last_id > 0 && routes.entries.keys().all(|id| *id > 0 && *id <= routes.last_id));
        match stored {
            Some(routes) => (routes, false),
            None => (Routes::fresh(), true),
        }
    }

    fn add(&mut self, route: Route) -> (i32, Removal) {
        let mut removal = Removal::default();
        let id = match self.last_id.checked_add(1) {
            Some(id) => id,
            None => {
                // Two billion alerts later: start over with a clean screen.
                self.entries.clear();
                removal.all = true;
                1
            }
        };
        self.last_id = id;
        self.entries.insert(id, route);
        while self.entries.len() > MAX_ROUTES {
            if let Some((old, _)) = self.entries.pop_first() {
                removal.ids.push(old);
            }
        }
        (id, removal)
    }

    fn take(&mut self, matches: impl Fn(&Route) -> bool) -> Vec<i32> {
        let ids: Vec<i32> = self.entries.iter().filter(|(_, r)| matches(r)).map(|(id, _)| *id).collect();
        for id in &ids {
            self.entries.remove(id);
        }
        ids
    }
}

/// Write a whole file so a crash leaves the old or the new contents, both
/// on disk (file and directory synced).
fn write_durably(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let temp = path.with_extension("json.tmp");
    let mut file = std::fs::File::create(&temp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

enum Job {
    /// Clear delivered alerts the table can't route.
    Startup { fresh: bool },
    Show(Alert),
    Withdraw { thread: String, key: Option<String> },
}

pub struct Notifier {
    away: AtomicBool,
    /// The alert thread on screen (`set_notification_context`).
    visible: Mutex<Option<String>>,
    routes: Mutex<Routes>,
    path: Option<PathBuf>,
    jobs: Mutex<Option<mpsc::Sender<Job>>>,
    #[cfg_attr(target_os = "android", allow(dead_code))]
    asked: AtomicBool,
}

impl Notifier {
    fn with_routes(routes: Routes, path: Option<PathBuf>) -> Notifier {
        Notifier {
            away: AtomicBool::new(false),
            visible: Mutex::new(None),
            routes: Mutex::new(routes),
            path,
            jobs: Mutex::new(None),
            asked: AtomicBool::new(false),
        }
    }

    /// Start the OS bridge: its worker thread performs every OS call.
    pub fn start(app: AppHandle, data_dir: &Path) -> Arc<Notifier> {
        let path = data_dir.join("notification-targets.json");
        let (routes, fresh) = Routes::load(&path);
        let notifier = Arc::new(Notifier::with_routes(routes, Some(path)));
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(Job::Startup { fresh });
        *notifier.jobs.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let worker = Arc::downgrade(&notifier);
        std::thread::Builder::new()
            .name("mycel-notify".into())
            .spawn(move || {
                for job in rx {
                    let Some(notifier) = worker.upgrade() else { return };
                    // A failing OS call must not stop later alerts.
                    let run = std::panic::AssertUnwindSafe(|| notifier.run(&app, job));
                    if std::panic::catch_unwind(run).is_err() {
                        eprintln!("mycel-host: a notification task failed");
                    }
                }
            })
            .expect("notification thread");
        notifier
    }

    pub fn set_away(&self, away: bool) {
        self.away.store(away, Ordering::Relaxed);
    }

    /// Hand a shell event to the worker. Never blocks.
    pub fn on_event(&self, event: &Event) {
        match event {
            Event::Alert { alert } => self.send(Job::Show(alert.clone())),
            Event::AlertWithdrawn { thread, key } => {
                self.send(Job::Withdraw { thread: thread.clone(), key: key.clone() })
            }
            _ => {}
        }
    }

    fn send(&self, job: Job) {
        if let Some(jobs) = &*self.jobs.lock().unwrap_or_else(|e| e.into_inner()) {
            let _ = jobs.send(job);
        }
    }

    fn viewing(&self, thread: &str) -> bool {
        !self.away.load(Ordering::Relaxed)
            && self.visible.lock().unwrap_or_else(|e| e.into_inner()).as_deref() == Some(thread)
    }

    /// While the app is in front, alerts about what's on screen, and those
    /// the app shows itself (an incoming call), stay quiet.
    fn suppressed(&self, alert: &Alert) -> bool {
        !self.away.load(Ordering::Relaxed) && (!alert.foreground || self.viewing(&alert.thread))
    }

    /// Route a new alert: drop the one it replaces and allocate a fresh id.
    #[cfg_attr(target_os = "android", allow(dead_code))]
    fn route(&self, alert: &Alert) -> (i32, Removal) {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let replaced = routes.take(|r| r.key == alert.key);
        let (id, mut removal) = routes.add(Route {
            target: alert.target.clone(),
            thread: alert.thread.clone(),
            key: alert.key.clone(),
        });
        removal.ids.extend(replaced);
        self.persist(&routes);
        (id, removal)
    }

    /// Forget withdrawn alerts; their ids to take off the screen.
    fn withdraw(&self, thread: &str, key: Option<&str>) -> Vec<i32> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        let ids = match key {
            Some(key) => routes.take(|r| r.key == key),
            None => routes.take(|r| r.thread == thread),
        };
        if !ids.is_empty() {
            self.persist(&routes);
        }
        ids
    }

    fn persist(&self, routes: &Routes) {
        let Some(path) = &self.path else { return };
        let saved = serde_json::to_vec(routes)
            .map_err(std::io::Error::other)
            .and_then(|data| write_durably(path, &data));
        if saved.is_err() {
            eprintln!("mycel-host: cannot persist notification routing");
        }
    }

    fn run(&self, app: &AppHandle, job: Job) {
        match job {
            Job::Startup { fresh } => self.clear_unroutable(app, fresh),
            Job::Show(alert) => {
                if self.suppressed(&alert) {
                    if self.viewing(&alert.thread) {
                        let ids = self.withdraw(&alert.thread, None);
                        self.remove(app, Removal { ids, all: false });
                    }
                    return;
                }
                self.show(app, &alert);
            }
            Job::Withdraw { thread, key } => {
                let ids = self.withdraw(&thread, key.as_deref());
                self.remove(app, Removal { ids, all: false });
            }
        }
    }

    #[cfg(target_os = "ios")]
    fn clear_unroutable(&self, app: &AppHandle, fresh: bool) {
        let n = app.notification();
        if fresh {
            if let Err(e) = n.remove_all_active() {
                eprintln!("mycel-host: clearing old notifications failed: {e}");
            }
            return;
        }
        let Ok(active) = n.active() else { return };
        let stale: Vec<i32> = {
            let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
            active.iter().map(|a| a.id()).filter(|id| !routes.entries.contains_key(id)).collect()
        };
        self.remove(app, Removal { ids: stale, all: false });
    }

    #[cfg(not(target_os = "ios"))]
    fn clear_unroutable(&self, _app: &AppHandle, _fresh: bool) {}

    #[cfg(target_os = "ios")]
    fn remove(&self, app: &AppHandle, removal: Removal) {
        if removal.is_empty() {
            return;
        }
        let n = app.notification();
        let removed = if removal.all { n.remove_all_active() } else { n.remove_active(removal.ids) };
        if let Err(e) = removed {
            eprintln!("mycel-host: notification removal failed: {e}");
        }
    }

    /// Desktop notification centers can't be cleared from here.
    #[cfg(not(target_os = "ios"))]
    fn remove(&self, _app: &AppHandle, _removal: Removal) {}

    #[cfg(target_os = "android")]
    fn show(&self, _app: &AppHandle, alert: &Alert) {
        let (title, body) = content(alert.kind);
        if let Err(e) = android_notify(title, body) {
            eprintln!("mycel-host: notification failed: {e}");
        }
    }

    #[cfg(not(target_os = "android"))]
    fn show(&self, app: &AppHandle, alert: &Alert) {
        let n = app.notification();
        // Permission is asked in the foreground (prepare_notifications),
        // never while an event arrives behind a locked screen.
        if !matches!(n.permission_state(), Ok(tauri_plugin_notification::PermissionState::Granted)) {
            return;
        }
        let (title, body) = content(alert.kind);
        // A fresh opaque id even in the same thread, so tap handling can
        // tell two separate alerts apart.
        let (id, replaced) = self.route(alert);
        self.remove(app, replaced);
        if let Err(e) = n.builder().id(id).title(title).body(body).sound("default").show() {
            eprintln!("mycel-host: notification failed: {e}");
        }
    }

    #[cfg(not(target_os = "android"))]
    fn prepare(&self, app: &AppHandle) -> String {
        let n = app.notification();
        let Ok(state) = n.permission_state() else {
            return "unavailable".into();
        };
        if self.should_request_permission(state) {
            return n
                .request_permission()
                .map(|state| state.to_string())
                .unwrap_or_else(|_| "unavailable".into());
        }
        state.to_string()
    }

    #[cfg(not(target_os = "android"))]
    fn should_request_permission(&self, state: tauri_plugin_notification::PermissionState) -> bool {
        use tauri_plugin_notification::PermissionState;
        matches!(state, PermissionState::Prompt | PermissionState::PromptWithRationale)
            && !self.away.load(Ordering::Relaxed)
            && !self.asked.swap(true, Ordering::Relaxed)
    }

    /// Android posts alerts through MycelService; there's no permission
    /// state to check from here.
    #[cfg(target_os = "android")]
    fn prepare(&self, _app: &AppHandle) -> String {
        "unavailable".into()
    }
}

/// UI calls this after loading, while the permission prompt can be seen.
/// Returns the plugin's state (`granted`, `denied`, `prompt`,
/// `prompt-with-rationale`) or `unavailable`: no permission state to check
/// here (Android, or a desktop without a notification service).
#[tauri::command]
pub async fn prepare_notifications(
    app: AppHandle,
    notifier: State<'_, Arc<Notifier>>,
) -> Result<String, String> {
    let notifier = notifier.inner().clone();
    tauri::async_runtime::spawn_blocking(move || notifier.prepare(&app))
        .await
        .map_err(|_| "Notification permission check failed".into())
}

/// A mounted chat hidden by a panel or an app switch must report None.
#[tauri::command]
pub async fn set_notification_context(
    notifier: State<'_, Arc<Notifier>>,
    rt: State<'_, Rt>,
    conversation: Option<String>,
) -> Result<(), String> {
    let thread = conversation.and_then(|id| rt.alert_thread(&id));
    *notifier.visible.lock().unwrap_or_else(|e| e.into_inner()) = thread.clone();
    if let Some(thread) = thread.filter(|t| notifier.viewing(t)) {
        notifier.send(Job::Withdraw { thread, key: None });
    }
    Ok(())
}

/// Never trust an OS notification's payload: only its opaque id, through
/// our own table, then the runtime's current view of the target.
#[tauri::command]
pub async fn notification_target(
    notifier: State<'_, Arc<Notifier>>,
    rt: State<'_, Rt>,
    id: i32,
) -> Result<Option<String>, String> {
    let target = notifier
        .routes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entries
        .get(&id)
        .map(|route| route.target.clone());
    Ok(target.and_then(|target| rt.alert_route(&target)))
}

/// Consume a tap even when iOS delivered it before the webview was ready.
#[tauri::command]
pub async fn take_notification_action(app: AppHandle) -> Result<Option<i32>, String> {
    #[cfg(target_os = "ios")]
    return tauri::async_runtime::spawn_blocking(move || {
        app.notification()
            .take_pending_action()
            .map_err(|_| "Notification action unavailable".into())
    })
    .await
    .map_err(|_| "Notification action unavailable".to_string())?;
    #[cfg(not(target_os = "ios"))]
    {
        let _ = app;
        Ok(None)
    }
}

/// `MycelService.notify(context, title, body)` (gen/android/.../MycelService.kt),
/// through the app's class loader (a native thread's FindClass only sees
/// system classes).
#[cfg(target_os = "android")]
fn android_notify(title: &str, body: &str) -> jni::errors::Result<()> {
    use jni::objects::{JObject, JValue};
    let ctx = ndk_context::android_context();
    // SAFETY: tao keeps the process's JavaVM and application Context alive.
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }?;
    let mut env = vm.attach_current_thread()?;
    // SAFETY: a global reference to the application Context, borrowed.
    let context = unsafe { JObject::from_raw(ctx.context().cast()) };
    let loader = env
        .call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
        .l()?;
    let name = env.new_string("dev.mycel.host.MycelService")?;
    let class = env
        .call_method(
            &loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&name)],
        )?
        .l()?;
    let (title, body) = (env.new_string(title)?, env.new_string(body)?);
    let res = env.call_static_method(
        jni::objects::JClass::from(class),
        "notify",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V",
        &[
            JValue::Object(&context),
            JValue::Object(&title),
            JValue::Object(&body),
        ],
    );
    if res.is_err() {
        let _ = env.exception_clear();
    }
    res.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [AlertKind; 5] = [
        AlertKind::Message,
        AlertKind::MessageRequest,
        AlertKind::GroupInvitation,
        AlertKind::IncomingCall,
        AlertKind::MissedCall,
    ];

    fn alert(kind: AlertKind, thread: &str, key: &str) -> Alert {
        Alert {
            kind,
            thread: thread.into(),
            key: key.into(),
            target: format!("target-of-{thread}"),
            foreground: kind != AlertKind::IncomingCall,
        }
    }

    fn notifier() -> Notifier {
        Notifier::with_routes(Routes::fresh(), None)
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mycel-notify-{tag}-{}", mycel_node::crypto::random_u64()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_os_only_ever_sees_one_fixed_sentence_per_kind() {
        let sentences: Vec<_> = KINDS.iter().map(|kind| content(*kind)).collect();
        assert_eq!(sentences, [
            ("Mycel", "New message"),
            ("Mycel", "New message request"),
            ("Mycel", "New group invitation"),
            ("Mycel", "Incoming call"),
            ("Mycel", "Missed call"),
        ]);
        // Alerts carry no names or text to leak: only opaque local keys.
        let json = serde_json::to_value(alert(AlertKind::Message, "t", "k")).unwrap();
        let mut fields: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(fields, ["foreground", "key", "kind", "target", "thread"]);
    }

    #[test]
    fn alerts_about_what_is_on_screen_or_rung_in_app_stay_quiet_while_focused() {
        let notifier = notifier();
        let message = alert(AlertKind::Message, "thread", "message:thread");
        let call = alert(AlertKind::IncomingCall, "thread", "call:c");
        *notifier.visible.lock().unwrap() = Some("another".into());
        assert!(!notifier.suppressed(&message));
        assert!(notifier.suppressed(&call), "the app rings calls itself");
        *notifier.visible.lock().unwrap() = Some("thread".into());
        assert!(notifier.suppressed(&message));
        // A chat can stay mounted behind a locked screen: that isn't reading.
        notifier.set_away(true);
        assert!(!notifier.suppressed(&message) && !notifier.suppressed(&call));
        assert!(!notifier.viewing("thread"));
    }

    #[test]
    fn routes_replace_by_key_and_are_pruned_when_withdrawn() {
        let notifier = notifier();
        let (first, _) = notifier.route(&alert(AlertKind::Message, "a", "message:a"));
        let (second, replaced) = notifier.route(&alert(AlertKind::Message, "a", "message:a"));
        assert!(second > first);
        assert_eq!(replaced, Removal { ids: vec![first], all: false });
        let (call, _) = notifier.route(&alert(AlertKind::MissedCall, "a", "missed:c"));
        let (other, _) = notifier.route(&alert(AlertKind::Message, "b", "message:b"));
        assert_eq!(notifier.withdraw("a", Some("missed:c")), vec![call]);
        assert_eq!(notifier.withdraw("a", None), vec![second]);
        // Nothing left for that thread: no OS call, however often it's read.
        assert!(notifier.withdraw("a", None).is_empty());
        assert_eq!(notifier.routes.lock().unwrap().entries.keys().copied().collect::<Vec<_>>(), [other]);
    }

    #[test]
    fn ids_are_never_reused_across_restarts_corruption_and_overflow() {
        let dir = temp_dir("routes");
        let path = dir.join("notification-targets.json");
        let (mut routes, fresh) = Routes::load(&path);
        assert!(fresh, "nothing on disk: clear what might be delivered");
        let (id, _) = routes.add(Route { target: "x".into(), thread: "t".into(), key: "k".into() });
        assert!(id > 0);
        write_durably(&path, &serde_json::to_vec(&routes).unwrap()).unwrap();
        assert!(!dir.join("notification-targets.json.tmp").exists());
        let (mut restarted, fresh) = Routes::load(&path);
        assert!(!fresh);
        assert_eq!(restarted.entries[&id].target, "x");
        // Bounded, oldest first; evicted alerts are taken off the screen.
        let mut evicted = vec![];
        for n in 0..300 {
            evicted.extend(restarted.add(Route { target: format!("{n}"), thread: "t".into(), key: format!("{n}") }).1.ids);
        }
        assert_eq!(restarted.entries.len(), MAX_ROUTES);
        assert!(evicted.contains(&id) && !restarted.entries.contains_key(&id));
        assert!(restarted.add(Route { target: "y".into(), thread: "t".into(), key: "y".into() }).0 > id);
        // A corrupt table (or one from an older version) starts over: every
        // delivered alert is cleared and ids start at a random point.
        std::fs::write(&path, b"{\"last_id\":0,\"entries\":{\"1\":\"old-chat\"}}").unwrap();
        let (reset, fresh) = Routes::load(&path);
        assert!(fresh && reset.entries.is_empty());
        assert!(reset.last_id > 0 && reset.last_id <= 1 << 30);
        // Overflow also clears everything before ids start again.
        let mut full = Routes { last_id: i32::MAX, entries: BTreeMap::new() };
        full.entries.insert(i32::MAX, Route { target: "z".into(), thread: "t".into(), key: "z".into() });
        let (id, removal) = full.add(Route { target: "w".into(), thread: "t".into(), key: "w".into() });
        assert_eq!((id, removal.all, full.entries.len()), (1, true, 1));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shell_events_are_queued_without_blocking() {
        let notifier = notifier();
        let (tx, rx) = mpsc::channel();
        *notifier.jobs.lock().unwrap() = Some(tx);
        notifier.on_event(&Event::Alert { alert: alert(AlertKind::Message, "t", "message:t") });
        notifier.on_event(&Event::AlertWithdrawn { thread: "t".into(), key: None });
        notifier.on_event(&Event::ContactsChanged);
        let jobs: Vec<Job> = rx.try_iter().collect();
        assert!(matches!(jobs.as_slice(), [Job::Show(_), Job::Withdraw { key: None, .. }]));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn permission_prompt_requires_foreground_and_never_reprompts_denied() {
        use tauri_plugin_notification::PermissionState;
        let notifier = notifier();
        notifier.set_away(true);
        assert!(!notifier.should_request_permission(PermissionState::Prompt));
        notifier.set_away(false);
        assert!(!notifier.should_request_permission(PermissionState::Granted));
        assert!(!notifier.should_request_permission(PermissionState::Denied));
        assert!(notifier.should_request_permission(PermissionState::Prompt));
        assert!(!notifier.should_request_permission(PermissionState::Prompt));
    }
}
