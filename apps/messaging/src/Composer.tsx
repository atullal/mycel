import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { useMycel } from "@mycel/sdk/react";
import type { ConversationSummary, MessageView } from "@mycel/sdk";
import { Icon, errorText, fileNameFromPath, previewText } from "./ui.tsx";

const TYPING_EVERY_MS = 2500;
const MAX_ROWS_PX = 180;

export function Composer({
  conversation,
  messages,
  replyTo,
  editing,
  onCancelReply,
  onCancelEdit,
  onStartEdit,
}: {
  conversation: ConversationSummary;
  messages: MessageView[];
  replyTo: MessageView | null;
  editing: MessageView | null;
  onCancelReply: () => void;
  onCancelEdit: () => void;
  onStartEdit: (m: MessageView) => void;
}) {
  const mycel = useMycel();
  const [text, setText] = useState("");
  const [files, setFiles] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const draftBeforeEdit = useRef("");
  const lastTyping = useRef(0);
  const input = useRef<HTMLTextAreaElement>(null);

  // Grow the textarea with its content, up to a limit.
  useLayoutEffect(() => {
    const el = input.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, MAX_ROWS_PX)}px`;
  }, [text]);

  // Entering edit mode loads the message; leaving restores the draft.
  const editingId = editing?.id;
  useEffect(() => {
    if (editing) {
      draftBeforeEdit.current = text;
      setText(editing.body);
      requestAnimationFrame(() => {
        const el = input.current;
        if (el) {
          el.focus();
          el.setSelectionRange(el.value.length, el.value.length);
        }
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editingId]);

  useEffect(() => {
    if (replyTo) input.current?.focus();
  }, [replyTo]);

  useEffect(() => {
    input.current?.focus();
  }, [conversation.id]);

  const cancelEdit = () => {
    setText(draftBeforeEdit.current);
    onCancelEdit();
  };

  const submit = async () => {
    if (busy) return;
    const body = text.trim();
    setError(null);
    if (editing) {
      if (!body) return;
      if (body === editing.body) return cancelEdit();
      setBusy(true);
      try {
        await mycel.chat.edit(conversation.id, editing.id, body);
        setText(draftBeforeEdit.current);
        draftBeforeEdit.current = "";
        onCancelEdit();
      } catch (e) {
        setError(errorText(e));
      } finally {
        setBusy(false);
      }
      return;
    }
    if (!body && files.length === 0) return;
    setBusy(true);
    try {
      await mycel.chat.send(conversation.id, body, {
        replyTo: replyTo?.id,
        attachments: files,
      });
      setText("");
      setFiles([]);
      onCancelReply();
      lastTyping.current = 0;
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
      input.current?.focus();
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.nativeEvent.isComposing) return;
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void submit();
    } else if (e.key === "Escape") {
      if (editing) {
        e.preventDefault();
        cancelEdit();
      } else if (replyTo) {
        e.preventDefault();
        onCancelReply();
      }
    } else if (e.key === "ArrowUp" && !editing && text === "" && files.length === 0) {
      const mine = [...messages].reverse().find((m) => m.isMine && !m.deleted && m.body);
      if (mine) {
        e.preventDefault();
        onStartEdit(mine);
      }
    }
  };

  const onChange = (value: string) => {
    setText(value);
    const now = Date.now();
    if (!editing && value.trim() && now - lastTyping.current > TYPING_EVERY_MS) {
      lastTyping.current = now;
      void mycel.chat.typing(conversation.id).catch(() => {});
    }
  };

  const attach = async () => {
    try {
      const picked = await mycel.files.pick();
      if (picked.length) setFiles((f) => [...f, ...picked.filter((p) => !f.includes(p))]);
    } catch (e) {
      setError(errorText(e));
    }
    input.current?.focus();
  };

  const canSend = editing ? !!text.trim() : !!text.trim() || files.length > 0;
  const placeholder = editing
    ? "Edit message"
    : conversation.direct
      ? `Message ${conversation.title.split(" ")[0]}`
      : `Message ${conversation.title}`;

  return (
    <div className="mx-composer">
      {(replyTo || editing) && (
        <div className={`mx-context${editing ? " is-edit" : ""}`}>
          {editing ? <Icon.Edit size={16} /> : <Icon.Reply size={16} />}
          <div className="mx-context-text">
            <span className="mx-context-title">
              {editing ? "Editing message" : `Replying to ${replyTo!.isMine ? "yourself" : replyTo!.authorName}`}
            </span>
            <span className="mx-context-body">{previewText((editing ?? replyTo)!)}</span>
          </div>
          <button
            className="mx-icon-btn"
            onClick={editing ? cancelEdit : onCancelReply}
            aria-label={editing ? "Cancel editing" : "Cancel reply"}
            title="Cancel (Esc)"
          >
            <Icon.X size={16} />
          </button>
        </div>
      )}

      {files.length > 0 && !editing && (
        <ul className="mx-pending" aria-label="Attachments">
          {files.map((f) => (
            <li key={f}>
              <Icon.File size={15} />
              <span>{fileNameFromPath(f)}</span>
              <button onClick={() => setFiles((all) => all.filter((x) => x !== f))} aria-label={`Remove ${fileNameFromPath(f)}`}>
                <Icon.X size={13} />
              </button>
            </li>
          ))}
        </ul>
      )}

      {error && (
        <p className="mx-composer-error" role="alert">
          {error}
        </p>
      )}

      <div className="mx-composer-box">
        {!editing && (
          <button className="mx-icon-btn" onClick={attach} aria-label="Attach files" title="Attach files">
            <Icon.Clip />
          </button>
        )}
        <textarea
          ref={input}
          rows={1}
          value={text}
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          aria-label={placeholder}
        />
        <button
          className="mx-send"
          onClick={() => void submit()}
          disabled={!canSend || busy}
          aria-label={editing ? "Save edit" : "Send"}
          title={editing ? "Save (Enter)" : "Send (Enter)"}
        >
          {editing ? <Icon.Check size={18} /> : <Icon.Send size={18} />}
        </button>
      </div>
      <p className="mx-hint">
        <kbd>Enter</kbd> to send, <kbd>Shift</kbd>+<kbd>Enter</kbd> for a new line, <kbd>↑</kbd> to edit your last message
      </p>
    </div>
  );
}
