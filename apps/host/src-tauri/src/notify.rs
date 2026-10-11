//! System notifications for new messages and incoming calls while nobody is
//! looking at Mycel: the window is in the background on a computer, or the
//! app is in the background on a phone (Android keeps it running with
//! MainActivity's foreground service; iOS only while it allows).
//!
//! Whether someone is looking comes from the main window's focus and
//! suspend / resume events (`lib.rs`). New messages are found from
//! `ConversationUpdated`: the conversation's newest message, if it isn't
//! ours and hasn't been notified yet.
//!
//! Notifications may appear on a locked screen or be retained by the OS.
//! Only generic text crosses that boundary; conversation and call details
//! stay inside Mycel.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use mycel_node::api::{ConversationSummary, Event, MessageId};
use tauri::AppHandle;
#[cfg(not(target_os = "android"))]
use tauri_plugin_notification::NotificationExt;

use crate::Rt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Notification {
    Message,
    MessageRequest,
    IncomingCall,
}

impl Notification {
    /// Static output prevents names, messages, or attachment metadata from
    /// being passed to either platform's notification service.
    fn content(self) -> (&'static str, &'static str) {
        let body = match self {
            Self::Message => "New message",
            Self::MessageRequest => "New message request",
            Self::IncomingCall => "Incoming call",
        };
        ("Mycel", body)
    }
}

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
        Notifier {
            seen: Mutex::new(seen),
            ..Notifier::default()
        }
    }

    /// The window gained or lost focus, or the app was suspended / resumed.
    pub fn set_away(&self, away: bool) {
        self.away.store(away, Ordering::Relaxed);
    }

    pub fn on_event(&self, app: &AppHandle, rt: &Rt, event: &Event) {
        match event {
            Event::ConversationUpdated { conversation }
            | Event::ConversationAdded { conversation } => {
                let Ok(summary) = rt.conversation(conversation.clone()) else {
                    return;
                };
                if let Some(notification) = self.for_conversation(&summary) {
                    self.show(app, notification);
                }
            }
            Event::CallIncoming { .. } if self.away.load(Ordering::Relaxed) => {
                self.show(app, Notification::IncomingCall);
            }
            _ => {}
        }
    }

    fn for_conversation(&self, c: &ConversationSummary) -> Option<Notification> {
        let m = c.last_message.as_ref()?;
        let fresh = {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            seen.insert(c.id.clone(), m.id.clone()).as_ref() != Some(&m.id)
        };
        if !fresh || m.is_mine || m.deleted || c.unread == 0 || !self.away.load(Ordering::Relaxed) {
            return None;
        }
        Some(if c.request {
            Notification::MessageRequest
        } else {
            Notification::Message
        })
    }

    #[cfg(target_os = "android")]
    fn show(&self, _app: &AppHandle, notification: Notification) {
        let (title, body) = notification.content();
        // Natively: the plugin needs an activity, and there may be none
        // (swiped away from recents while MycelService keeps us running).
        if let Err(e) = android_notify(title, body) {
            eprintln!("mycel-host: notification failed: {e}");
        }
    }

    #[cfg(not(target_os = "android"))]
    fn show(&self, app: &AppHandle, notification: Notification) {
        let (title, body) = notification.content();
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
    use mycel_node::api::{Attachment, Delivery, MessageView};

    fn private_conversation() -> ConversationSummary {
        ConversationSummary {
            id: "private-conversation-id".into(),
            title: "Sensitive group name".into(),
            direct: false,
            members: vec![],
            last_message: Some(MessageView {
                id: "private-message-id".into(),
                conversation: "private-conversation-id".into(),
                author: "private-author-id".into(),
                author_name: "Sensitive sender name".into(),
                sent_at: 0,
                body: "Sensitive message text".into(),
                reply_to: None,
                edited: false,
                deleted: false,
                attachments: vec![Attachment {
                    blob: "private-blob-id".into(),
                    name: "Sensitive attachment filename.txt".into(),
                    mime: "text/plain".into(),
                    size: 17,
                    local_path: Some("/private/attachment-path".into()),
                }],
                reactions: vec![],
                is_mine: false,
                delivery: Delivery::Delivered,
            }),
            unread: 1,
            active: true,
            my_role: None,
            request: false,
            invited_by: Some("private-inviter-id".into()),
        }
    }

    #[test]
    fn notification_output_contains_no_conversation_details() {
        for direct in [false, true] {
            for request in [false, true] {
                for attachment_only in [false, true] {
                    let notifier = Notifier::default();
                    notifier.set_away(true);
                    let mut conversation = private_conversation();
                    conversation.direct = direct;
                    conversation.request = request;
                    if attachment_only {
                        conversation.last_message.as_mut().unwrap().body.clear();
                    }
                    let (title, body) = notifier.for_conversation(&conversation).unwrap().content();
                    assert_eq!(title, "Mycel");
                    assert_eq!(
                        body,
                        if request {
                            "New message request"
                        } else {
                            "New message"
                        }
                    );
                    let output = format!("{title} {body}");
                    let message = conversation.last_message.as_ref().unwrap();
                    for private in [
                        conversation.id.as_str(),
                        conversation.title.as_str(),
                        message.id.as_str(),
                        message.author.as_str(),
                        message.author_name.as_str(),
                        "Sensitive message text",
                        message.attachments[0].name.as_str(),
                        message.attachments[0].blob.as_str(),
                        message.attachments[0].local_path.as_deref().unwrap(),
                        conversation.invited_by.as_deref().unwrap(),
                    ] {
                        assert!(
                            !output.contains(private),
                            "notification exposed private data"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn incoming_call_notification_is_generic() {
        assert_eq!(
            Notification::IncomingCall.content(),
            ("Mycel", "Incoming call")
        );
    }

    #[test]
    fn conversation_notification_filters_and_seen_state_are_preserved() {
        let notifier = Notifier::default();
        let mut conversation = private_conversation();

        // Reading while focused also marks this message as seen.
        assert_eq!(notifier.for_conversation(&conversation), None);
        notifier.set_away(true);
        assert_eq!(notifier.for_conversation(&conversation), None);

        conversation.last_message.as_mut().unwrap().id = "fresh-message".into();
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
        assert_eq!(notifier.for_conversation(&conversation), None);

        for excluded in ["mine", "deleted", "read"] {
            let mut conversation = private_conversation();
            let message = conversation.last_message.as_mut().unwrap();
            message.id = excluded.into();
            message.is_mine = excluded == "mine";
            message.deleted = excluded == "deleted";
            conversation.unread = if excluded == "read" { 0 } else { 1 };
            assert_eq!(notifier.for_conversation(&conversation), None);
            // Even excluded events retain the original seen-state update.
            conversation.last_message.as_mut().unwrap().is_mine = false;
            conversation.last_message.as_mut().unwrap().deleted = false;
            conversation.unread = 1;
            assert_eq!(notifier.for_conversation(&conversation), None);
        }

        conversation.last_message = None;
        assert_eq!(notifier.for_conversation(&conversation), None);
    }
}
