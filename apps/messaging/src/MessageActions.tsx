import { useState } from "react";
import { useConversations, useMycel } from "@mycel/sdk/react";
import type { MessageView } from "@mycel/sdk";
import { ChatModal } from "./ChatModal.tsx";
import { Icon, errorText, previewText } from "./ui.tsx";
import { SearchField } from "./SearchField.tsx";
import { matchesSearch } from "./search.ts";

export const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

export function MessageActions({ message, onClose, onReply, onEdit, canInteract = true, onDeleted }: {
  message: MessageView; onClose: () => void;
  onReply?: (m: MessageView) => void; onEdit?: (m: MessageView) => void;
  canInteract?: boolean; onDeleted: (m: MessageView, local: boolean) => void;
}) {
  const mycel = useMycel();
  const { conversations } = useConversations();
  const [forwarding, setForwarding] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [query, setQuery] = useState("");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (action: () => Promise<unknown>) => {
    if (busy) return;
    setBusy(true); setError(null);
    try { await action(); onClose(); }
    catch (e) { setError(errorText(e)); setBusy(false); }
  };
  const forward = () => run(async () => {
    if (!conversations.some((c) => c.id === target && c.active && !c.request && c.myRole !== "readOnly")) {
      throw new Error("Choose an active conversation.");
    }
    const attachments = await Promise.all(message.attachments.map((a) => a.localPath ?? mycel.chat.fetchAttachment(a.blob)));
    await mycel.chat.send(target, message.body, { attachments });
  });
  const destinations = conversations.filter((c) => c.active && !c.request && c.myRole !== "readOnly");
  const shown = destinations.filter((c) => matchesSearch(query, c.title, ...c.members.map((m) => m.name)));
  const remove = (local: boolean) => run(async () => {
    if (local) await mycel.chat.deleteLocal(message.conversation, message.id);
    else await mycel.chat.delete(message.conversation, message.id);
    onDeleted(message, local);
  });
  return <ChatModal title={deleting ? "Delete message?" : forwarding ? "Forward message" : "Message actions"} onClose={() => { if (!busy) onClose(); }}>
    <p className="mx-action-preview">{previewText(message)}</p>
    {deleting ? <>
      <p className="mx-modal-note">Delete for me removes this message from this device's chat history.</p>
      <button className="mx-menu-item mx-delete-action" disabled={busy} onClick={() => void remove(true)}><span>Delete for me</span><Icon.Trash /></button>
      {canInteract && message.isMine && !message.deleted && <>
        <p className="mx-modal-note">Delete for everyone removes it from the conversation when other devices sync. Copies people saved elsewhere remain.</p>
        <button className="mx-menu-item mx-delete-action" disabled={busy} onClick={() => void remove(false)}><span>Delete for everyone</span><Icon.Trash /></button>
      </>}
      <button className="mx-menu-item" disabled={busy} onClick={onClose}><span>Cancel</span><Icon.X /></button>
    </> : forwarding ? <>
      <p className="mx-modal-note">Choose where to send this message.</p>
      <SearchField value={query} onChange={setQuery} label="Search forwarding destinations" placeholder="Search names or chats" />
      <div className="mx-forward-list">
        {shown.map((c) =>
          <button key={c.id} className="mx-menu-item" aria-pressed={target === c.id} disabled={busy} onClick={() => setTarget(c.id)}>
            <span>{c.title}</span>{target === c.id && <Icon.Check />}
          </button>)}
        {!shown.length && <p className="mx-modal-note" role="status">{query.trim() ? "No matching conversations." : "No conversations available."}</p>}
      </div>
      {target && !shown.some((c) => c.id === target) && <p className="mx-modal-note">Selected: {destinations.find((c) => c.id === target)?.title}</p>}
      <button className="mx-btn mx-btn-primary mx-forward-send" disabled={!target || busy} onClick={() => void forward()}>{busy ? "Sending…" : "Forward"}</button>
    </> : <>
      {canInteract && !message.deleted && <div className="mx-context-reactions" aria-label="Reactions">
        {QUICK_REACTIONS.map((emoji) => <button key={emoji} disabled={busy} aria-label={`React with ${emoji}`} onClick={() => void run(() => mycel.chat.react(message.conversation, message.id, emoji))}>{emoji}</button>)}
      </div>}
      {onReply && !message.deleted && <button className="mx-menu-item" disabled={busy} onClick={() => { onClose(); onReply(message); }}><span>Reply</span><Icon.Reply /></button>}
      {!!message.body && <button className="mx-menu-item" disabled={busy} onClick={() => void run(() => navigator.clipboard.writeText(message.body))}><span>Copy</span><Icon.Copy /></button>}
      {canInteract && !message.deleted && <button className="mx-menu-item" disabled={busy} onClick={() => setForwarding(true)}><span>Forward</span><Icon.Forward /></button>}
      {message.isMine && onEdit && !!message.body && !message.deleted && <button className="mx-menu-item" disabled={busy} onClick={() => { onClose(); onEdit(message); }}><span>Edit</span><Icon.Edit /></button>}
      <button className="mx-menu-item mx-delete-action" disabled={busy} onClick={() => setDeleting(true)}><span>Delete</span><Icon.Trash /></button>
    </>}
    {error && <p className="mx-error" role="alert">{error}</p>}
  </ChatModal>;
}
