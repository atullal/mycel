//! One `#[tauri::command]` per row of the command table in docs/RUNTIME_API.md.
//!
//! Command names are snake_case; Tauri maps the webview's camelCase argument
//! names (`replyTo`) onto these snake_case parameters (`reply_to`). Every
//! error becomes its human-readable string, which the SDK surfaces as an
//! `Error` message.
//!
//! All commands are `async` so they run on the async runtime instead of the
//! main (UI) thread.

use mycel_node::api::{
    Contact, ConversationId, ConversationSummary, MessageId, MessageView, NearbyPeer,
    NetworkStatus, PeerId, Profile,
};
use tauri::{AppHandle, State};

use crate::{Rt, set_window_title};

type Res<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
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

#[tauri::command]
pub async fn fetch_attachment(rt: State<'_, Rt>, blob: String) -> Res<String> {
    rt.fetch_attachment(blob).await.map_err(err)
}
