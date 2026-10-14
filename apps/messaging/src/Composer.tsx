import {
  useEffect,
  useImperativeHandle,
  useLayoutEffect,
  useRef,
  useState,
  type ClipboardEvent,
  type KeyboardEvent,
  type Ref,
} from "react";
import { useMycel, useTransfer } from "@mycel/sdk/react";
import { isMobile } from "@mycel/sdk";
import type { ConversationSummary, MessageView } from "@mycel/sdk";
import { Icon, errorText, fileNameFromPath, formatRate, formatSize, previewText } from "./ui.tsx";
import { VoiceRecorder } from "./VoiceRecorder.tsx";

/** Lets the conversation view hand the composer dropped files. */
export interface ComposerHandle {
  /** Local paths (native drag-and-drop). */
  attachPaths(paths: string[]): void;
  /** Browser `File`s (HTML drag-and-drop): staged with the runtime first. */
  attachFiles(files: File[]): void;
}

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
  ref,
}: {
  ref?: Ref<ComposerHandle>;
  conversation: ConversationSummary;
  messages: MessageView[];
  replyTo: MessageView | null;
  editing: MessageView | null;
  onCancelReply: () => void;
  onCancelEdit: () => void;
  onStartEdit: (m: MessageView) => void;
}) {
  const mycel = useMycel();
  // Phones and tablets pick through the system's chooser (photos, camera,
  // files): it hands over copies, which are staged with the runtime. A
  // computer's file dialog gives real paths, which the runtime reads itself,
  // so even very large files never pass through the web view.
  const systemChooser = isMobile();
  const [recording, setRecording] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const cameraInput = useRef<HTMLInputElement>(null);
  const [text, setText] = useState("");
  const [files, setFiles] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [staging, setStaging] = useState(0);
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
    if (matchMedia("(pointer: fine)").matches) input.current?.focus();
  }, [conversation.id]);

  const cancelEdit = () => {
    setText(draftBeforeEdit.current);
    onCancelEdit();
  };

  const submit = async () => {
    if (busy || staging > 0 || recording) return;
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
    if (e.key === "Enter" && !e.shiftKey && (matchMedia("(pointer: fine)").matches || e.metaKey || e.ctrlKey)) {
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

  const attachPaths = (picked: string[]) => {
    if (picked.length) setFiles((f) => [...f, ...picked.filter((p) => !f.includes(p))]);
  };

  const attach = async () => {
    try {
      attachPaths(await mycel.files.pick());
    } catch (e) {
      setError(errorText(e));
    }
    if (matchMedia("(pointer: fine)").matches) input.current?.focus();
  };

  // Pasted images and HTML-dropped files have no path: copy them to the runtime first.
  const attachFiles = async (list: File[], propagateError = false) => {
    if (!list.length) return;
    if (!mycel.files.stage) {
      const unavailable = new Error("Use Attach files to add files here.");
      setError(unavailable.message);
      if (propagateError) throw unavailable;
      return;
    }
    setError(null);
    setStaging((n) => n + 1);
    try {
      attachPaths(await mycel.files.stage(list));
    } catch (e) {
      setError(errorText(e));
      if (propagateError) throw e;
    } finally {
      setStaging((n) => n - 1);
      if (matchMedia("(pointer: fine)").matches) input.current?.focus();
    }
  };

  useImperativeHandle(ref, () => ({ attachPaths, attachFiles }));

  const onPaste = (e: ClipboardEvent<HTMLTextAreaElement>) => {
    if (editing) return;
    const list = Array.from(e.clipboardData.files);
    if (list.length) {
      e.preventDefault();
      void attachFiles(list);
    }
  };

  const canSend = (editing ? !!text.trim() : !!text.trim() || files.length > 0) && staging === 0;
  const placeholder = editing
    ? "Edit message"
    : conversation.direct
      ? `Message ${conversation.title.split(" ")[0]}`
      : `Message ${conversation.title}`;

  return (
    <div className="mx-composer">
      {systemChooser && (
        <>
          {/* The system chooser already offers Photos, Camera and Files. */}
          <input ref={fileInput} type="file" multiple hidden onChange={(e) => { void attachFiles(Array.from(e.currentTarget.files ?? [])); e.currentTarget.value = ""; }} />
          <input ref={cameraInput} type="file" accept="image/*" capture="environment" hidden onChange={(e) => { void attachFiles(Array.from(e.currentTarget.files ?? [])); e.currentTarget.value = ""; }} />
        </>
      )}
      {recording && <VoiceRecorder onCancel={() => setRecording(false)} onAttach={(file) => attachFiles([file], true)} />}
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

      {((files.length > 0 && !editing) || staging > 0) && (
        <ul className="mx-pending" aria-label="Attachments">
          {!editing &&
            files.map((f) => (
              <PendingFile key={f} path={f} sending={busy} onRemove={() => setFiles((all) => all.filter((x) => x !== f))} />
            ))}
          {staging > 0 && (
            <li className="is-staging">
              <span className="mx-spinner" aria-hidden="true" />
              <span>Adding…</span>
            </li>
          )}
        </ul>
      )}

      {error && (
        <p className="mx-composer-error" role="alert">
          {error}
        </p>
      )}

      {!recording && <div className="mx-composer-box">
        {!editing && (
          <button
            className="mx-icon-btn mx-attach"
            disabled={busy || staging > 0}
            onClick={() => (systemChooser ? fileInput.current?.click() : void attach())}
            aria-label="Attach files"
            title="Attach files"
          >
            {systemChooser ? <Icon.Plus /> : <Icon.Clip />}
          </button>
        )}
        <textarea
          ref={input}
          rows={1}
          value={text}
          placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          onPaste={onPaste}
          aria-label={placeholder}
        />
        {!canSend && !editing && staging === 0 && !busy ? <>
          {systemChooser && <button className="mx-icon-btn mx-camera" onClick={() => cameraInput.current?.click()} aria-label="Camera"><Icon.Camera /></button>}
          <button className="mx-icon-btn mx-record" onClick={() => setRecording(true)} aria-label="Record voice note" title="Record voice note"><Icon.Mic /></button>
        </> : <button
          className="mx-send"
          onClick={() => void submit()}
          disabled={!canSend || busy}
          aria-label={editing ? "Save edit" : "Send"}
          title={editing ? "Save (Enter)" : "Send (Enter)"}
        >
          {editing ? <Icon.Check size={18} /> : <Icon.Send size={18} />}
        </button>}
      </div>}
      <p className="mx-hint">
        <kbd>Enter</kbd> to send, <kbd>Shift</kbd>+<kbd>Enter</kbd> for a new line, <kbd>↑</kbd> to edit your last message.
        Drop or paste files to attach.
      </p>
    </div>
  );
}

/** A file waiting to be sent; shows encryption progress while sending. */
function PendingFile({ path, sending, onRemove }: { path: string; sending: boolean; onRemove: () => void }) {
  const progress = useTransfer(path);
  const name = fileNameFromPath(path);
  const pct = sending && progress && progress.total > 0 ? Math.min(100, Math.round((progress.done / progress.total) * 100)) : null;
  const rate = pct != null ? formatRate(progress?.rate) : "";
  return (
    <li
      className={pct != null ? "is-sending" : undefined}
      title={pct != null ? `Encrypting ${name}: ${pct}% of ${formatSize(progress!.total)}${rate ? ` at ${rate}` : ""}` : name}
    >
      <Icon.File size={15} />
      <span>{name}</span>
      {pct != null ? (
        <>
          <span className="mx-pending-pct">
            {pct}%{rate ? ` · ${rate}` : ""}
          </span>
          <span className="mx-pending-bar" style={{ width: `${pct}%` }} aria-hidden="true" />
        </>
      ) : (
        <button onClick={onRemove} disabled={sending} aria-label={`Remove ${name}`}>
          <Icon.X size={13} />
        </button>
      )}
    </li>
  );
}
