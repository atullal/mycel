//! One `#[tauri::command]` per row of the command table in docs/RUNTIME_API.md.
//!
//! Command names are snake_case; Tauri maps the webview's camelCase argument
//! names (`replyTo`) onto these snake_case parameters (`reply_to`). Every
//! error becomes its human-readable string with the full cause chain (e.g.
//! "can't read /x: Operation not permitted (os error 1)"), which the SDK
//! surfaces as an `Error` message.
//!
//! All commands are `async` so they run on the async runtime instead of the
//! main (UI) thread.

use mycel_node::api::{
    CallInfo, Contact, ConversationId, ConversationSummary, MessageId, MessageView, NearbyPeer,
    NetworkMode, NetworkStatus, PeerId, Profile,
};
use tauri::{AppHandle, State};

use crate::{Rt, set_window_title};

type Res<T> = Result<T, String>;

/// `{:#}` prints an anyhow error with its causes; `to_string()` would drop
/// them and hide the real OS error.
fn err(e: impl std::fmt::Display) -> String {
    format!("{e:#}")
}

// ---------------------------------------------------------------- identity & contacts

#[tauri::command]
pub async fn get_profile(rt: State<'_, Rt>) -> Res<Profile> {
    Ok(rt.profile())
}

#[tauri::command]
pub async fn set_name(app: AppHandle, rt: State<'_, Rt>, name: String) -> Res<Profile> {
    let profile = rt.set_name(name).map_err(err)?;
    set_window_title(&app, &profile.name);
    Ok(profile)
}

#[tauri::command]
pub async fn add_contact(rt: State<'_, Rt>, code: String) -> Res<Contact> {
    rt.add_contact(code).map_err(err)
}

#[tauri::command]
pub async fn add_nearby_contact(rt: State<'_, Rt>, id: PeerId) -> Res<Contact> {
    rt.add_nearby_contact(id).await.map_err(err)
}

#[tauri::command]
pub async fn remove_contact(rt: State<'_, Rt>, id: PeerId) -> Res<()> {
    rt.remove_contact(id).map_err(err)
}

#[tauri::command]
pub async fn list_contacts(rt: State<'_, Rt>) -> Res<Vec<Contact>> {
    Ok(rt.contacts())
}

#[tauri::command]
pub async fn list_nearby(rt: State<'_, Rt>) -> Res<Vec<NearbyPeer>> {
    Ok(rt.nearby())
}

#[tauri::command]
pub async fn network_status(rt: State<'_, Rt>) -> Res<NetworkStatus> {
    Ok(rt.network_status())
}

#[tauri::command]
pub async fn set_network_mode(rt: State<'_, Rt>, mode: NetworkMode) -> Res<NetworkStatus> {
    rt.set_network_mode(mode).map_err(err)
}

/// Relaunch the app (the network mode is fixed while running).
#[tauri::command]
pub fn restart_app(app: tauri::AppHandle) {
    app.restart();
}

/// Open a downloaded attachment: the share sheet on iPhone and iPad, an
/// "Open with" chooser on Android, the default app on a computer.
#[tauri::command]
pub async fn open_file(app: AppHandle, rt: State<'_, Rt>, path: String) -> Res<()> {
    crate::open_file::open(&app, rt.data_dir(), &path)
}

// ---------------------------------------------------------------- messaging

#[tauri::command]
pub async fn list_conversations(rt: State<'_, Rt>) -> Res<Vec<ConversationSummary>> {
    Ok(rt.conversations())
}

#[tauri::command]
pub async fn get_conversation(rt: State<'_, Rt>, id: ConversationId) -> Res<ConversationSummary> {
    rt.conversation(id).map_err(err)
}

#[tauri::command]
pub async fn create_conversation(
    rt: State<'_, Rt>,
    title: Option<String>,
    members: Vec<PeerId>,
) -> Res<ConversationSummary> {
    rt.create_conversation(title, members).map_err(err)
}

#[tauri::command]
pub async fn list_messages(
    rt: State<'_, Rt>,
    id: ConversationId,
    limit: Option<u32>,
    before: Option<MessageId>,
) -> Res<Vec<MessageView>> {
    rt.messages(id, limit, before).map_err(err)
}

#[tauri::command]
pub async fn send_message(
    rt: State<'_, Rt>,
    id: ConversationId,
    body: String,
    reply_to: Option<MessageId>,
    attachments: Option<Vec<String>>,
) -> Res<MessageView> {
    rt.send_message(id, body, reply_to, attachments.unwrap_or_default())
        .await
        .map_err(err)
}

#[tauri::command]
pub async fn edit_message(
    rt: State<'_, Rt>,
    id: ConversationId,
    message: MessageId,
    body: String,
) -> Res<()> {
    rt.edit_message(id, message, body).map_err(err)
}

#[tauri::command]
pub async fn delete_message(rt: State<'_, Rt>, id: ConversationId, message: MessageId) -> Res<()> {
    rt.delete_message(id, message).map_err(err)
}

#[tauri::command]
pub async fn toggle_reaction(
    rt: State<'_, Rt>,
    id: ConversationId,
    message: MessageId,
    emoji: String,
) -> Res<()> {
    rt.toggle_reaction(id, message, emoji).map_err(err)
}

#[tauri::command]
pub async fn mark_read(rt: State<'_, Rt>, id: ConversationId) -> Res<()> {
    rt.mark_read(id).map_err(err)
}

#[tauri::command]
pub async fn set_typing(rt: State<'_, Rt>, id: ConversationId) -> Res<()> {
    rt.set_typing(id).map_err(err)
}

#[tauri::command]
pub async fn add_members(rt: State<'_, Rt>, id: ConversationId, members: Vec<PeerId>) -> Res<()> {
    rt.add_members(id, members).map_err(err)
}

#[tauri::command]
pub async fn remove_member(rt: State<'_, Rt>, id: ConversationId, member: PeerId) -> Res<()> {
    rt.remove_member(id, member).map_err(err)
}

#[tauri::command]
pub async fn add_keeper(rt: State<'_, Rt>, id: ConversationId, keeper: PeerId) -> Res<()> {
    rt.add_keeper(id, keeper).map_err(err)
}

#[tauri::command]
pub async fn rename_conversation(rt: State<'_, Rt>, id: ConversationId, title: String) -> Res<()> {
    rt.rename_conversation(id, title).map_err(err)
}

// ---------------------------------------------------------------- message requests

#[tauri::command]
pub async fn accept_request(rt: State<'_, Rt>, id: ConversationId) -> Res<ConversationSummary> {
    rt.accept_request(id).map_err(err)
}

#[tauri::command]
pub async fn decline_request(
    rt: State<'_, Rt>,
    id: ConversationId,
    block: Option<bool>,
) -> Res<()> {
    rt.decline_request(id, block.unwrap_or(false)).map_err(err)
}

#[tauri::command]
pub async fn fetch_attachment(rt: State<'_, Rt>, blob: String) -> Res<String> {
    rt.fetch_attachment(blob).await.map_err(err)
}

/// Save raw bytes (a pasted image, a dropped file without a path) as an
/// attachable file. The body is the file's bytes; the `x-mycel-name` header
/// carries its URI-encoded name. Returns the path to pass in `attachments`.
#[tauri::command]
pub async fn stage_file(rt: State<'_, Rt>, request: tauri::ipc::Request<'_>) -> Res<String> {
    let tauri::ipc::InvokeBody::Raw(data) = request.body() else {
        return Err("stage_file expects the file's bytes as the request body".into());
    };
    let name = request
        .headers()
        .get("x-mycel-name")
        .and_then(|v| v.to_str().ok())
        .map(percent_decode)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "pasted".into());
    rt.stage_upload(&name, data).await.map_err(err)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------- calls

#[tauri::command]
pub async fn start_call(rt: State<'_, Rt>, conversation: ConversationId, video: Option<bool>) -> Res<CallInfo> {
    rt.start_call_with(conversation, video.unwrap_or(false)).await.map_err(err)
}

#[tauri::command]
pub async fn accept_call(rt: State<'_, Rt>, call: String, video: Option<bool>) -> Res<CallInfo> {
    rt.accept_call_with(call, video.unwrap_or(false)).await.map_err(err)
}

#[tauri::command]
pub async fn set_camera(rt: State<'_, Rt>, call: String, on: bool) -> Res<CallInfo> {
    rt.set_camera(call, on).await.map_err(err)
}

#[tauri::command]
pub async fn video_keyframe(rt: State<'_, Rt>, call: String) -> Res<()> {
    rt.video_keyframe(call).map_err(err)
}

/// Bumped by every `video_subscribe`: older subscriptions stop.
static VIDEO_SUBSCRIPTION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Stream encoded video frames (remote video and self-view) to the webview
/// as raw bytes (layout: `mycel_video::UiFrame`); it decodes them with
/// WebCodecs. One subscription at a time: a new one (a reload) replaces it.
#[tauri::command]
pub async fn video_subscribe(rt: State<'_, Rt>, channel: tauri::ipc::Channel<tauri::ipc::InvokeResponseBody>) -> Res<()> {
    use std::sync::atomic::Ordering;
    let me = VIDEO_SUBSCRIPTION.fetch_add(1, Ordering::SeqCst) + 1;
    let mut frames = rt.video_frames();
    tauri::async_runtime::spawn(async move {
        loop {
            let f = match frames.recv().await {
                Ok(f) => f,
                // the webview fell behind: skip ahead (it asks for a keyframe)
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            if VIDEO_SUBSCRIPTION.load(Ordering::SeqCst) != me {
                return;
            }
            if channel.send(tauri::ipc::InvokeResponseBody::Raw(f.encode())).is_err() {
                return;
            }
        }
    });
    Ok(())
}

#[tauri::command]
pub async fn decline_call(rt: State<'_, Rt>, call: String) -> Res<()> {
    rt.decline_call(call).map_err(err)
}

#[tauri::command]
pub async fn end_call(rt: State<'_, Rt>, call: String) -> Res<()> {
    rt.end_call(call).map_err(err)
}

#[tauri::command]
pub async fn set_muted(rt: State<'_, Rt>, call: String, muted: bool) -> Res<CallInfo> {
    rt.set_muted(call, muted).map_err(err)
}

#[tauri::command]
pub async fn call_status(rt: State<'_, Rt>) -> Res<Vec<CallInfo>> {
    Ok(rt.call_status())
}
