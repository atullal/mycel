//! JSON command dispatcher: the RUNTIME_API.md command table over any
//! transport (local HTTP for browsers/CLI). The Tauri host has typed
//! commands of its own; both call the same `Runtime` methods.

use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::Runtime;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Id {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Name {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Code {
    code: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Create {
    title: Option<String>,
    members: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListMessages {
    id: String,
    limit: Option<u32>,
    before: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessagesAround {
    id: String,
    message: String,
    before: Option<u32>,
    after: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchMessages {
    id: String,
    query: String,
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Send {
    id: String,
    body: String,
    reply_to: Option<String>,
    attachments: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Edit {
    id: String,
    message: String,
    body: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Msg {
    id: String,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct React {
    id: String,
    message: String,
    emoji: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Members {
    id: String,
    members: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberArg {
    id: String,
    member: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keeper {
    id: String,
    keeper: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Title {
    id: String,
    title: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Decline {
    id: String,
    #[serde(default)]
    block: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mode {
    mode: crate::api::NetworkMode,
}

#[derive(Deserialize)]
struct OnOff {
    on: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Blob {
    blob: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallArg {
    call: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyframeArg {
    call: String,
    /// "local" (our self-view), "remote" (from the others), or both.
    #[serde(default)]
    source: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartCall {
    conversation: String,
    #[serde(default)]
    video: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptCall {
    call: String,
    #[serde(default)]
    video: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Camera {
    call: String,
    on: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mute {
    call: String,
    muted: bool,
}

#[derive(Deserialize)]
struct DismissNotice {
    notice: crate::api::Notice,
}

fn args<T: DeserializeOwned>(v: Value) -> Result<T> {
    let v = if v.is_null() { json!({}) } else { v };
    serde_json::from_value(v).map_err(|e| anyhow!("bad arguments: {e}"))
}

fn ok<T: serde::Serialize>(v: T) -> Result<Value> {
    Ok(serde_json::to_value(v)?)
}

/// Run one command by name with JSON args (camelCase), returning JSON.
pub async fn dispatch(rt: &Runtime, cmd: &str, a: Value) -> Result<Value> {
    match cmd {
        "get_profile" => ok(rt.profile()),
        "set_name" => ok(rt.set_name(args::<Name>(a)?.name)?),
        "add_contact" => ok(rt.add_contact(args::<Code>(a)?.code)?),
        "add_nearby_contact" => ok(rt.add_nearby_contact(args::<Id>(a)?.id).await?),
        "remove_contact" => ok(rt.remove_contact(args::<Id>(a)?.id)?),
        "list_contacts" => ok(rt.contacts()),
        "list_nearby" => ok(rt.nearby()),
        "network_status" => ok(rt.network_status()),
        "list_notices" => ok(rt.notices()),
        "dismiss_notice" => ok(rt.dismiss_notice(args::<DismissNotice>(a)?.notice)?),
        "set_network_mode" => ok(rt.set_network_mode(args::<Mode>(a)?.mode)?),
        "set_custodian" => ok(rt.set_custodian(args::<OnOff>(a)?.on)?),
        "list_conversations" => ok(rt.conversations()),
        "get_conversation" => ok(rt.conversation(args::<Id>(a)?.id)?),
        "create_conversation" => {
            let c: Create = args(a)?;
            ok(rt.create_conversation(c.title, c.members)?)
        }
        "list_messages" => {
            let l: ListMessages = args(a)?;
            ok(rt.messages(l.id, l.limit, l.before)?)
        }
        "messages_around" => {
            let m: MessagesAround = args(a)?;
            ok(rt.messages_around(m.id, m.message, m.before, m.after)?)
        }
        "search_messages" => {
            let s: SearchMessages = args(a)?;
            ok(rt.search_messages(s.id, s.query, s.limit)?)
        }
        "send_message" => {
            let s: Send = args(a)?;
            ok(rt.send_message(s.id, s.body, s.reply_to, s.attachments.unwrap_or_default()).await?)
        }
        "edit_message" => {
            let e: Edit = args(a)?;
            ok(rt.edit_message(e.id, e.message, e.body)?)
        }
        "delete_message" => {
            let m: Msg = args(a)?;
            ok(rt.delete_message(m.id, m.message)?)
        }
        "delete_message_local" => {
            let m: Msg = args(a)?;
            ok(rt.delete_message_local(m.id, m.message)?)
        }
        "restore_message_local" => {
            let m: Msg = args(a)?;
            ok(rt.restore_message_local(m.id, m.message)?)
        }
        "toggle_reaction" => {
            let r: React = args(a)?;
            ok(rt.toggle_reaction(r.id, r.message, r.emoji)?)
        }
        "mark_read" => ok(rt.mark_read(args::<Id>(a)?.id)?),
        "set_typing" => ok(rt.set_typing(args::<Id>(a)?.id)?),
        "add_members" => {
            let m: Members = args(a)?;
            ok(rt.add_members(m.id, m.members)?)
        }
        "remove_member" => {
            let m: MemberArg = args(a)?;
            ok(rt.remove_member(m.id, m.member)?)
        }
        "add_keeper" => {
            let k: Keeper = args(a)?;
            ok(rt.add_keeper(k.id, k.keeper)?)
        }
        "rename_conversation" => {
            let t: Title = args(a)?;
            ok(rt.rename_conversation(t.id, t.title)?)
        }
        "fetch_attachment" => ok(rt.fetch_attachment(args::<Blob>(a)?.blob).await?),
        "accept_request" => ok(rt.accept_request(args::<Id>(a)?.id)?),
        "decline_request" => {
            let d: Decline = args(a)?;
            ok(rt.decline_request(d.id, d.block)?)
        }
        "start_call" => {
            let s: StartCall = args(a)?;
            ok(rt.start_call_with(s.conversation, s.video).await?)
        }
        "accept_call" => {
            let s: AcceptCall = args(a)?;
            ok(rt.accept_call_with(s.call, s.video).await?)
        }
        "set_camera" => {
            let c: Camera = args(a)?;
            ok(rt.set_camera(c.call, c.on).await?)
        }
        "video_keyframe" => {
            let k: KeyframeArg = args(a)?;
            ok(rt.video_keyframe(k.call, k.source)?)
        }
        "decline_call" => ok(rt.decline_call(args::<CallArg>(a)?.call)?),
        "end_call" => ok(rt.end_call(args::<CallArg>(a)?.call)?),
        "set_muted" => {
            let m: Mute = args(a)?;
            ok(rt.set_muted(m.call, m.muted)?)
        }
        "call_status" => ok(rt.call_status()),
        "sync_now" => {
            rt.sync_now().await;
            ok(())
        }
        other => Err(anyhow!("unknown command: {other}")),
    }
}
