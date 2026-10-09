//! System notifications for new messages and incoming calls while nobody is
//! looking at Mycel: the window is in the background on a computer, or the
//! app is in the background on a phone (Android keeps it running with
//! MainActivity's foreground service; iOS only while it allows).
//!
//! Whether someone is looking comes from the main window's focus and
//! suspend / resume events (`lib.rs`). New messages are found from
//! `ConversationUpdated`: the conversation's newest message, if it isn't
//! ours and hasn't been notified yet.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use mycel_node::api::{ConversationSummary, Event, MessageId};
use tauri::AppHandle;
#[cfg(not(target_os = "android"))]
use tauri_plugin_notification::NotificationExt;

use crate::Rt;

#[derive(Default)]
pub struct Notifier {
    away: AtomicBool,
    /// Newest message per conversation already shown or seen.
    seen: Mutex<HashMap<String, MessageId>>,
    /// Asked for permission (Android asks in MainActivity instead).
    #[cfg_attr(target_os = "android", allow(dead_code))]
    asked: AtomicBool,
}

impl Notifier {
    /// Everything already there at startup counts as seen.
    pub fn new(rt: &Rt) -> Notifier {
        let seen = rt
            .conversations()
            .into_iter()
            .filter_map(|c| c.last_message.map(|m| (c.id, m.id)))
            .collect();
        Notifier { seen: Mutex::new(seen), ..Notifier::default() }
    }

    /// The window gained or lost focus, or the app was suspended / resumed.
    pub fn set_away(&self, away: bool) {
        self.away.store(away, Ordering::Relaxed);
    }

    pub fn on_event(&self, app: &AppHandle, rt: &Rt, event: &Event) {
        match event {
            Event::ConversationUpdated { conversation } | Event::ConversationAdded { conversation } => {
                let Ok(summary) = rt.conversation(conversation.clone()) else { return };
                self.on_conversation(app, &summary);
            }
            Event::CallIncoming { call } if self.away.load(Ordering::Relaxed) => {
                let title = match (&call.title, call.group) {
                    (Some(t), true) => format!("{} is calling {t}", call.peer_name),
                    _ => format!("{} is calling", call.peer_name),
                };
                self.show(app, &title, "Open Mycel to answer");
            }
            _ => {}
        }
    }

    fn on_conversation(&self, app: &AppHandle, c: &ConversationSummary) {
        let Some(m) = &c.last_message else { return };
        let fresh = {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            seen.insert(c.id.clone(), m.id.clone()).as_ref() != Some(&m.id)
        };
        if !fresh || m.is_mine || m.deleted || c.unread == 0 || !self.away.load(Ordering::Relaxed) {
            return;
        }
        let title = if c.request {
            format!("Message request from {}", m.author_name)
        } else if c.direct {
            m.author_name.clone()
        } else {
            format!("{} in {}", m.author_name, c.title)
        };
        let body = if !m.body.trim().is_empty() {
            preview(&m.body)
        } else {
            match m.attachments.len() {
                0 => "New message".into(),
                1 => format!("Sent {}", m.attachments[0].name),
                n => format!("Sent {n} files"),
            }
        };
        self.show(app, &title, &body);
    }

    #[cfg(target_os = "android")]
    fn show(&self, _app: &AppHandle, title: &str, body: &str) {
        // Natively: the plugin needs an activity, and there may be none
        // (swiped away from recents while MycelService keeps us running).
        if let Err(e) = android_notify(title, body) {
            eprintln!("mycel-host: notification failed: {e}");
        }
    }

    #[cfg(not(target_os = "android"))]
    fn show(&self, app: &AppHandle, title: &str, body: &str) {
        let n = app.notification();
        // Ask once (Android 13+, macOS, iOS show the system prompt).
        if !self.asked.swap(true, Ordering::Relaxed)
            && let Ok(state) = n.permission_state()
            && state != tauri_plugin_notification::PermissionState::Granted
        {
            let _ = n.request_permission();
        }
        if let Err(e) = n.builder().title(title).body(body).show() {
            eprintln!("mycel-host: notification failed: {e}");
        }
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
    let loader = env.call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?.l()?;
    let name = env.new_string("dev.mycel.host.MycelService")?;
    let class = env
        .call_method(&loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", &[JValue::Object(&name)])?
        .l()?;
    let (title, body) = (env.new_string(title)?, env.new_string(body)?);
    let res = env.call_static_method(
        jni::objects::JClass::from(class),
        "notify",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V",
        &[JValue::Object(&context), JValue::Object(&title), JValue::Object(&body)],
    );
    if res.is_err() {
        let _ = env.exception_clear();
    }
    res.map(|_| ())
}

/// The first lines of a message, at most 140 characters.
fn preview(body: &str) -> String {
    let flat: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= 140 { flat } else { format!("{}…", flat.chars().take(139).collect::<String>()) }
}
