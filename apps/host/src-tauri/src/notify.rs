//! Private local alerts for incoming unread messages, requests and calls.
//! iOS can only generate these while its process is running; this is not a
//! remote push service. No names, message text or private IDs reach the OS.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use mycel_node::api::{
    CallDirection, CallEndReason, CallInfo, CallPhase, ConversationSummary, Event, MessageId,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
#[cfg(not(target_os = "android"))]
use tauri_plugin_notification::NotificationExt;

use crate::Rt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Notification {
    Message,
    MessageRequest,
    GroupInvitation,
    IncomingCall,
    MissedCall,
}

impl Notification {
    fn content(self) -> (&'static str, &'static str) {
        (
            "Mycel",
            match self {
                Self::Message => "New message",
                Self::MessageRequest => "New message request",
                Self::GroupInvitation => "New group invitation",
                Self::IncomingCall => "Incoming call",
                Self::MissedCall => "Missed call",
            },
        )
    }
}

/// IDs supplied to the OS have no relationship to conversation or peer IDs.
/// The routing table lives only in Mycel's sandbox and survives a restart.
#[derive(Default, Serialize, Deserialize)]
struct Targets {
    next_id: i32,
    entries: BTreeMap<i32, String>,
}

impl Targets {
    fn insert(&mut self, conversation: &str) -> i32 {
        // Never reuse an old ID for another chat, including IDs evicted below.
        self.next_id = self
            .next_id
            .checked_add(1)
            .filter(|id| *id > 0)
            .unwrap_or(1);
        while self.entries.contains_key(&self.next_id) {
            self.next_id = self.next_id.checked_add(1).unwrap_or(1);
        }
        let id = self.next_id;
        self.entries.insert(id, conversation.into());
        while self.entries.len() > 256 {
            if let Some(old) = self.entries.keys().next().copied() {
                self.entries.remove(&old);
            }
        }
        id
    }
}

#[derive(Default)]
pub struct Notifier {
    away: AtomicBool,
    visible_conversation: Mutex<Option<String>>,
    // Keep a short history so deleting the newest message does not alert
    // again about the older message that becomes the conversation preview.
    seen: Mutex<HashMap<String, VecDeque<MessageId>>>,
    requests_seen: Mutex<HashSet<String>>,
    calls_seen: Mutex<HashSet<(String, bool)>>,
    active: Mutex<HashMap<String, i32>>,
    targets: Mutex<Targets>,
    targets_path: Option<PathBuf>,
    #[cfg_attr(target_os = "android", allow(dead_code))]
    asked: AtomicBool,
}

impl Notifier {
    pub fn new(rt: &Rt) -> Notifier {
        let conversations = rt.conversations();
        let requests_seen = conversations
            .iter()
            .filter(|c| c.request)
            .map(|c| c.thread_key.clone())
            .collect();
        let seen = conversations
            .into_iter()
            .filter_map(|c| {
                c.last_message
                    .map(|m| (c.thread_key, VecDeque::from([m.id])))
            })
            .collect();
        let path = rt.data_dir().join("notification-targets.json");
        let targets = std::fs::read(&path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default();
        Notifier {
            seen: Mutex::new(seen),
            requests_seen: Mutex::new(requests_seen),
            targets: Mutex::new(targets),
            targets_path: Some(path),
            ..Notifier::default()
        }
    }

    pub fn set_away(&self, away: bool) {
        self.away.store(away, Ordering::Relaxed);
    }

    fn viewing(&self, conversation: &str) -> bool {
        !self.away.load(Ordering::Relaxed)
            && self
                .visible_conversation
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_deref()
                == Some(conversation)
    }

    fn viewing_summary(&self, conversation: &ConversationSummary) -> bool {
        if self.away.load(Ordering::Relaxed) {
            return false;
        }
        let visible = self
            .visible_conversation
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        visible.as_ref().is_some_and(|key| {
            key == &conversation.thread_key || conversation.aliases.contains(key)
        })
    }

    pub fn on_event(&self, app: &AppHandle, rt: &Rt, event: &Event) {
        match event {
            Event::ConversationUpdated { conversation }
            | Event::ConversationAdded { conversation } => {
                let Ok(summary) = rt.conversation(conversation.clone()) else {
                    return;
                };
                if summary.unread == 0 || self.viewing_summary(&summary) {
                    self.clear_conversation(app, &summary);
                }
                if let Some(notification) = self.for_conversation(&summary) {
                    self.show(
                        app,
                        notification,
                        &summary.id,
                        &format!("message:{}", summary.thread_key),
                    );
                }
            }
            Event::CallIncoming { call } => {
                if let Some(notification) = self.for_call(call, true) {
                    self.show(
                        app,
                        notification,
                        &call.conversation,
                        &format!("call:{}", call.id),
                    );
                }
            }
            Event::CallUpdated { call } => {
                // An answered/declined/ended call must not remain an incoming
                // call in Notification Center. A missed alert replaces it.
                if call.state != CallPhase::Ringing {
                    self.clear_key(app, &format!("call:{}", call.id));
                }
                if let Some(notification) = self.for_call(call, false) {
                    self.show(
                        app,
                        notification,
                        &call.conversation,
                        &format!("missed:{}", call.id),
                    );
                }
            }
            _ => {}
        }
    }

    fn for_conversation(&self, c: &ConversationSummary) -> Option<Notification> {
        if c.request && !c.direct && c.last_message.is_none() {
            let fresh = self
                .requests_seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(c.thread_key.clone());
            return (fresh && c.active && !self.viewing_summary(c))
                .then_some(Notification::GroupInvitation);
        }
        let m = c.last_message.as_ref()?;
        let fresh = {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            // Requests and pre-aggregation snapshots can have been observed
            // under their wire ID before this thread became eligible. Carry
            // their seen state forward instead of alerting again on acceptance.
            let legacy: Vec<_> = c
                .aliases
                .iter()
                .filter(|alias| *alias != &c.thread_key)
                .filter_map(|alias| seen.remove(alias))
                .flatten()
                .collect();
            let history = seen.entry(c.thread_key.clone()).or_default();
            for id in legacy {
                if !history.contains(&id) {
                    history.push_back(id);
                }
            }
            let fresh = !history.contains(&m.id);
            if fresh {
                history.push_back(m.id.clone());
            }
            while history.len() > 32 {
                history.pop_front();
            }
            fresh
        };
        if !fresh || m.is_mine || m.deleted || !c.active || c.unread == 0 || self.viewing_summary(c)
        {
            return None;
        }
        Some(if c.request {
            Notification::MessageRequest
        } else {
            Notification::Message
        })
    }

    fn for_call(&self, call: &CallInfo, incoming: bool) -> Option<Notification> {
        if call.direction != CallDirection::Incoming {
            return None;
        }
        let notification = if incoming && call.state == CallPhase::Ringing {
            // The foreground call UI already rings and provides Accept/Decline.
            if !self.away.load(Ordering::Relaxed) {
                return None;
            }
            Notification::IncomingCall
        } else if !incoming
            && call.end_reason == Some(CallEndReason::Missed)
            && matches!(call.state, CallPhase::Ended | CallPhase::Joinable)
        {
            Notification::MissedCall
        } else {
            return None;
        };
        let key = (call.id.clone(), notification == Notification::MissedCall);
        let mut seen = self.calls_seen.lock().unwrap_or_else(|e| e.into_inner());
        if !seen.insert(key) {
            return None;
        }
        // Runtime retains only recent call state. Bound our companion cache.
        if seen.len() > 512 {
            seen.retain(|(id, _)| id == &call.id);
        }
        Some(notification)
    }

    fn id_for(&self, conversation: &str, key: &str) -> i32 {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        let mut targets = self.targets.lock().unwrap_or_else(|e| e.into_inner());
        let id = targets.insert(conversation);
        // Atomic replacement prevents a partial routing table after a crash.
        if let Some(path) = &self.targets_path {
            let temp = path.with_extension("json.tmp");
            if let Ok(data) = serde_json::to_vec(&*targets) {
                if std::fs::write(&temp, data)
                    .and_then(|()| std::fs::rename(&temp, path))
                    .is_err()
                {
                    eprintln!("mycel-host: cannot persist notification routing");
                }
            }
        }
        active.insert(key.into(), id);
        id
    }

    fn clear_key(&self, app: &AppHandle, key: &str) {
        let id = self
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
        if let Some(id) = id {
            self.remove(app, vec![id]);
        }
    }

    fn take_conversation_alerts(&self, conversation: &ConversationSummary) -> Vec<i32> {
        // Retained alerts can refer to an older canonical wire ID, including
        // records written before stable direct-message thread keys existed.
        let mut ids: Vec<i32> = self
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .iter()
            .filter_map(|(id, target)| {
                (target == &conversation.id || conversation.aliases.contains(target)).then_some(*id)
            })
            .collect();
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = active.remove(&format!("message:{}", conversation.thread_key)) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        active.retain(|_, id| !ids.contains(id));
        ids
    }

    fn clear_conversation(&self, app: &AppHandle, conversation: &ConversationSummary) {
        let ids = self.take_conversation_alerts(conversation);
        if !ids.is_empty() {
            self.remove(app, ids);
        }
    }

    #[cfg(target_os = "ios")]
    fn remove(&self, app: &AppHandle, ids: Vec<i32>) {
        // Tauri's mobile bridge waits for the main thread; never call it from
        // the main thread or retain our state locks during the call.
        if let Err(e) = app.notification().remove_active(ids) {
            eprintln!("mycel-host: notification removal failed: {e}");
        }
    }

    #[cfg(not(target_os = "ios"))]
    fn remove(&self, _app: &AppHandle, _ids: Vec<i32>) {}

    #[cfg(target_os = "android")]
    fn show(&self, _app: &AppHandle, notification: Notification, _conversation: &str, _key: &str) {
        let (title, body) = notification.content();
        if let Err(e) = android_notify(title, body) {
            eprintln!("mycel-host: notification failed: {e}");
        }
    }

    #[cfg(not(target_os = "android"))]
    fn show(&self, app: &AppHandle, notification: Notification, conversation: &str, key: &str) {
        let n = app.notification();
        // Request permission in the foreground through prepare_notifications,
        // never while an incoming event arrives behind a locked screen.
        if !matches!(
            n.permission_state(),
            Ok(tauri_plugin_notification::PermissionState::Granted)
        ) {
            return;
        }
        let (title, body) = notification.content();
        // A new alert gets a fresh opaque ID, even in the same conversation.
        // This lets tap dedup distinguish two separate incoming messages.
        self.clear_key(app, key);
        let id = self.id_for(conversation, key);
        if let Err(e) = n
            .builder()
            .id(id)
            .title(title)
            .body(body)
            .sound("default")
            .show()
        {
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
        matches!(
            state,
            PermissionState::Prompt | PermissionState::PromptWithRationale
        ) && !self.away.load(Ordering::Relaxed)
            && !self.asked.swap(true, Ordering::Relaxed)
    }

    #[cfg(target_os = "android")]
    fn prepare(&self, _app: &AppHandle) -> String {
        "unavailable".into()
    }
}

/// UI calls this after loading, while the permission prompt can be seen.
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
    app: AppHandle,
    notifier: State<'_, Arc<Notifier>>,
    rt: State<'_, Rt>,
    conversation: Option<String>,
) -> Result<(), String> {
    let notifier = notifier.inner().clone();
    let conversation = conversation.and_then(|id| rt.conversation(id).ok());
    *notifier
        .visible_conversation
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = conversation.as_ref().map(|c| c.thread_key.clone());
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(conversation) = conversation.filter(|c| notifier.viewing(&c.thread_key)) {
            notifier.clear_conversation(&app, &conversation);
        }
    })
    .await
    .map_err(|_| "Notification context update failed".into())
}

/// Never trust an OS notification's payload as a conversation identifier.
#[tauri::command]
pub async fn notification_target(
    notifier: State<'_, Arc<Notifier>>,
    rt: State<'_, Rt>,
    id: i32,
) -> Result<Option<String>, String> {
    let target = notifier
        .targets
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entries
        .get(&id)
        .cloned();
    let Some(target) = target else {
        return Ok(None);
    };
    Ok(rt
        .conversation(target)
        .ok()
        .filter(|c| c.active)
        .map(|c| c.id))
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
    use mycel_node::api::{Attachment, Delivery, MessageView};

    fn private_conversation() -> ConversationSummary {
        ConversationSummary {
            id: "private-conversation-id".into(),
            thread_key: "private-thread-key".into(),
            aliases: vec!["private-conversation-id".into()],
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
        assert_eq!(Notification::MissedCall.content(), ("Mycel", "Missed call"));
        assert_eq!(
            Notification::GroupInvitation.content(),
            ("Mycel", "New group invitation")
        );
    }

    #[test]
    fn message_alerts_follow_visible_chat_and_native_focus() {
        let notifier = Notifier::default();
        let mut conversation = private_conversation();
        *notifier.visible_conversation.lock().unwrap() = Some("another-chat".into());
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
        *notifier.visible_conversation.lock().unwrap() = Some(conversation.thread_key.clone());
        conversation.last_message.as_mut().unwrap().id = "currently-read".into();
        assert_eq!(notifier.for_conversation(&conversation), None);
        // The chat can remain mounted behind a locked screen; it is not read.
        notifier.set_away(true);
        conversation.last_message.as_mut().unwrap().id = "background-message".into();
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
    }

    #[test]
    fn deleted_preview_rollback_does_not_repeat_an_old_alert() {
        let notifier = Notifier::default();
        let mut conversation = private_conversation();
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
        let old = conversation.last_message.as_ref().unwrap().id.clone();
        conversation.last_message.as_mut().unwrap().id = "newer-message".into();
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
        conversation.last_message.as_mut().unwrap().id = old;
        assert_eq!(notifier.for_conversation(&conversation), None);
    }

    #[test]
    fn late_canonical_alias_does_not_realert_and_clears_old_delivered_ids() {
        let notifier = Notifier::default();
        let mut conversation = private_conversation();
        let key = format!("message:{}", conversation.thread_key);
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
        let first = notifier.id_for(&conversation.id, &key);
        // A late competing direct chat changes the wire representative, while
        // the two-peer logical thread and already observed message stay fixed.
        conversation.aliases.push("earlier-canonical-id".into());
        conversation.id = "earlier-canonical-id".into();
        assert_eq!(notifier.for_conversation(&conversation), None);
        assert!(
            notifier
                .take_conversation_alerts(&conversation)
                .contains(&first)
        );
        assert!(!notifier.active.lock().unwrap().contains_key(&key));
        // Legacy persisted targets refer to the former wire alias and clear too.
        assert_eq!(
            notifier
                .targets
                .lock()
                .unwrap()
                .entries
                .get(&first)
                .map(String::as_str),
            Some("private-conversation-id")
        );
        conversation.last_message.as_mut().unwrap().id = "genuinely-new-message".into();
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
        let second = notifier.id_for(&conversation.id, &key);
        assert_ne!(first, second);
        let cleared = notifier.take_conversation_alerts(&conversation);
        assert!(cleared.contains(&first) && cleared.contains(&second));
    }

    #[test]
    fn visible_thread_stays_visible_when_its_wire_id_changes() {
        let notifier = Notifier::default();
        let mut conversation = private_conversation();
        *notifier.visible_conversation.lock().unwrap() = Some(conversation.thread_key.clone());
        conversation.id = "new-canonical-wire-id".into();
        assert_eq!(notifier.for_conversation(&conversation), None);
        notifier.set_away(true);
        conversation.last_message.as_mut().unwrap().id = "new-background-message".into();
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
    }

    #[test]
    fn accepting_a_wire_keyed_request_preserves_seen_and_visible_state() {
        let notifier = Notifier::default();
        let mut conversation = private_conversation();
        conversation.direct = true;
        conversation.request = true;
        conversation.thread_key = conversation.id.clone();
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::MessageRequest)
        );
        conversation.request = false;
        conversation.thread_key = "accepted-two-peer-thread".into();
        assert_eq!(notifier.for_conversation(&conversation), None);
        *notifier.visible_conversation.lock().unwrap() = Some(conversation.id.clone());
        conversation.last_message.as_mut().unwrap().id = "visible-post-accept-message".into();
        assert_eq!(notifier.for_conversation(&conversation), None);
        notifier.set_away(true);
        conversation.last_message.as_mut().unwrap().id = "background-post-accept-message".into();
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::Message)
        );
    }

    #[test]
    fn group_invitation_without_a_message_alerts_once() {
        let notifier = Notifier::default();
        let mut conversation = private_conversation();
        conversation.request = true;
        conversation.last_message = None;
        conversation.unread = 0;
        assert_eq!(
            notifier.for_conversation(&conversation),
            Some(Notification::GroupInvitation)
        );
        assert_eq!(notifier.for_conversation(&conversation), None);
    }

    #[test]
    fn opaque_routing_survives_restart_and_is_bounded() {
        let mut targets = Targets::default();
        let id = targets.insert("private-conversation-id");
        assert!(id > 0);
        let saved = serde_json::to_vec(&targets).unwrap();
        let mut restarted: Targets = serde_json::from_slice(&saved).unwrap();
        assert_eq!(
            restarted.entries.get(&id).map(String::as_str),
            Some("private-conversation-id")
        );
        for n in 0..300 {
            restarted.insert(&format!("conversation-{n}"));
        }
        assert_eq!(restarted.entries.len(), 256);
        assert!(!restarted.entries.contains_key(&id));
        // Old retained notifications become unrouteable, never another chat.
        assert!(restarted.insert("last-chat") > id);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn permission_prompt_requires_foreground_and_never_reprompts_denied() {
        use tauri_plugin_notification::PermissionState;
        let notifier = Notifier::default();
        notifier.set_away(true);
        assert!(!notifier.should_request_permission(PermissionState::Prompt));
        notifier.set_away(false);
        assert!(!notifier.should_request_permission(PermissionState::Granted));
        assert!(!notifier.should_request_permission(PermissionState::Denied));
        assert!(notifier.should_request_permission(PermissionState::Prompt));
        assert!(!notifier.should_request_permission(PermissionState::Prompt));
    }

    fn incoming_call() -> CallInfo {
        CallInfo {
            id: "private-call-id".into(),
            conversation: "private-conversation-id".into(),
            group: false,
            title: None,
            peer: "private-peer-id".into(),
            peer_name: "Sensitive name".into(),
            direction: CallDirection::Incoming,
            state: CallPhase::Ringing,
            end_reason: None,
            error: None,
            started_at: 0,
            connected_at: None,
            duration_ms: 0,
            participants: vec![],
            joined_count: 0,
            active_speaker: None,
            path: None,
            bitrate: 0,
            muted: false,
            remote_muted: false,
            level: 0.0,
            remote_level: 0.0,
            echo_cancellation: false,
            stats: Default::default(),
            video: Default::default(),
        }
    }

    #[test]
    fn call_alerts_cover_unanswered_calls_without_duplicates_or_declined_alerts() {
        let notifier = Notifier::default();
        let mut call = incoming_call();
        assert_eq!(notifier.for_call(&call, true), None); // foreground call UI
        notifier.set_away(true);
        assert_eq!(
            notifier.for_call(&call, true),
            Some(Notification::IncomingCall)
        );
        assert_eq!(notifier.for_call(&call, true), None);
        call.state = CallPhase::Ended;
        call.end_reason = Some(CallEndReason::Missed);
        assert_eq!(
            notifier.for_call(&call, false),
            Some(Notification::MissedCall)
        );
        assert_eq!(notifier.for_call(&call, false), None);
        call.id = "group-missed".into();
        call.group = true;
        call.state = CallPhase::Joinable;
        assert_eq!(
            notifier.for_call(&call, false),
            Some(Notification::MissedCall)
        );
        for reason in [
            CallEndReason::Declined,
            CallEndReason::HungUp,
            CallEndReason::RemoteHungUp,
        ] {
            call.id = format!("not-missed-{reason:?}");
            call.state = CallPhase::Ended;
            call.end_reason = Some(reason);
            assert_eq!(notifier.for_call(&call, false), None);
        }
        call.direction = CallDirection::Outgoing;
        call.state = CallPhase::Ringing;
        assert_eq!(notifier.for_call(&call, true), None);
    }

    #[test]
    fn conversation_notification_filters_and_seen_state_are_preserved() {
        let notifier = Notifier::default();
        let mut conversation = private_conversation();

        // Reading while focused also marks this message as seen.
        *notifier.visible_conversation.lock().unwrap() = Some(conversation.thread_key.clone());
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
