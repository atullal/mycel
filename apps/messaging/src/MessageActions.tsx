import { useState } from "react";
import { useConversations, useMycel } from "@mycel/sdk/react";
import type { MessageView } from "@mycel/sdk";
import { ChatModal } from "./ChatModal.tsx";
import { Icon, errorText, previewText } from "./ui.tsx";

export const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

export function MessageActions({ message, onClose, onReply, onEdit }: {
  message: MessageView; onClose: () => void;
  onReply?: (m: MessageView) => void; onEdit?: (m: MessageView) => void;
}) {
  const mycel = useMycel();
  const { conversations } = useConversations();
  const [forwarding, setForwarding] = useState(false);
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
  return <ChatModal title={forwarding ? "Forward message" : "Message actions"} onClose={() => { if (!busy) onClose(); }}>
    <p className="mx-action-preview">{previewText(message)}</p>
    {forwarding ? <>
      <p className="mx-modal-note">Choose where to send this message.</p>
      <div className="mx-forward-list">
        {conversations.filter((c) => c.active && !c.request && c.myRole !== "readOnly").map((c) =>
          <button key={c.id} className="mx-menu-item" aria-pressed={target === c.id} disabled={busy} onClick={() => setTarget(c.id)}>
            <span>{c.title}</span>{target === c.id && <Icon.Check />}
          </button>)}
      </div>
      <button className="mx-btn mx-btn-primary mx-forward-send" disabled={!target || busy} onClick={() => void forward()}>{busy ? "Sending…" : "Forward"}</button>
    </> : <>
      <div className="mx-context-reactions" aria-label="Reactions">
        {QUICK_REACTIONS.map((emoji) => <button key={emoji} disabled={busy} aria-label={`React with ${emoji}`} onClick={() => void run(() => mycel.chat.react(message.conversation, message.id, emoji))}>{emoji}</button>)}
      </div>
      {onReply && <button className="mx-menu-item" disabled={busy} onClick={() => { onClose(); onReply(message); }}><span>Reply</span><Icon.Reply /></button>}
      {!!message.body && <button className="mx-menu-item" disabled={busy} onClick={() => void run(() => navigator.clipboard.writeText(message.body))}><span>Copy</span><Icon.Copy /></button>}
      <button className="mx-menu-item" disabled={busy} onClick={() => setForwarding(true)}><span>Forward</span><Icon.Forward /></button>
      {message.isMine && onEdit && !!message.body && <button className="mx-menu-item" disabled={busy} onClick={() => { onClose(); onEdit(message); }}><span>Edit</span><Icon.Edit /></button>}
    </>}
    {error && <p className="mx-error" role="alert">{error}</p>}
  </ChatModal>;
}
