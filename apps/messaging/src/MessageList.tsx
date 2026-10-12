import { Fragment, memo, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useMycel, useTransfer } from "@mycel/sdk/react";
import type { Attachment, ConversationSummary, MessageView } from "@mycel/sdk";
import {
  Avatar,
  DeliveryMark,
  Icon,
  errorText,
  formatClock,
  formatDay,
  formatRate,
  formatSize,
  previewText,
  sameDay,
} from "./ui.tsx";
import { MessageActions } from "./MessageActions.tsx";
import { ChatModal } from "./ChatModal.tsx";
import { completesReply, replyDistance } from "./messageGesture.ts";
import { HyphaeMark } from "./MessagingApp.tsx";

const GROUP_GAP_MS = 6 * 60_000;
export { QUICK_REACTIONS } from "./MessageActions.tsx";

interface Props {
  me: string | undefined;
  summary: ConversationSummary;
  messages: MessageView[];
  loading: boolean;
  error: Error | null;
  hasMore: boolean;
  onLoadOlder: () => void;
  onReply?: (m: MessageView) => void;
  onEdit?: (m: MessageView) => void;
  editingId: string | null;
  onDeleted?: (m: MessageView) => void;
  jumpToId?: string | null;
  onJumped?: () => void;
}

export function MessageList({ me, summary, messages, loading, error, hasMore, onLoadOlder, onReply, onEdit, editingId, onDeleted, jumpToId, onJumped }: Props) {
  const mycel = useMycel();
  const [undo, setUndo] = useState<MessageView | null>(null);
  const [undoError, setUndoError] = useState<string | null>(null);
  useEffect(() => { if (!undo) return; const timer = setTimeout(() => setUndo(null), 5000); return () => clearTimeout(timer); }, [undo]);
  const scroller = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);
  const restoreFrom = useRef<{ height: number; top: number } | null>(null);
  const previousLast = useRef<string | undefined>(undefined);
  const [away, setAway] = useState(false);
  const [selected, setSelected] = useState<MessageView | null>(null);
  const [flash, setFlash] = useState<string | null>(null);

  const byId = useMemo(() => new Map(messages.map((m) => [m.id, m])), [messages]);
  const lastId = messages[messages.length - 1]?.id;
  const lastIsMine = messages[messages.length - 1]?.isMine;

  // Keep the view pinned to the bottom when new messages arrive (or when I send),
  // and keep the reading position when older messages are prepended.
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const newMessage = previousLast.current !== lastId;
    previousLast.current = lastId;
    if (restoreFrom.current) {
      const { height, top } = restoreFrom.current;
      el.scrollTop = el.scrollHeight - height + top;
      restoreFrom.current = null;
      return;
    }
    if (stickToBottom.current || (newMessage && lastIsMine)) {
      el.scrollTop = el.scrollHeight; stickToBottom.current = true; setAway(false);
    }
  }, [messages, lastId, lastIsMine]);

  // Images load after layout; stay pinned while they do.
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const onLoad = () => {
      if (stickToBottom.current) el.scrollTop = el.scrollHeight;
    };
    el.addEventListener("load", onLoad, true);
    const observer = new ResizeObserver(onLoad);
    observer.observe(el);
    return () => { el.removeEventListener("load", onLoad, true); observer.disconnect(); };
  }, []);

  const loadOlder = () => {
    const el = scroller.current;
    if (el) restoreFrom.current = { height: el.scrollHeight, top: el.scrollTop };
    onLoadOlder();
  };

  const jumpTo = (id: string) => {
    const node = scroller.current?.querySelector(`[data-mid="${id}"]`);
    if (!node) return;
    node.scrollIntoView({ block: "center", behavior: "smooth" });
    setFlash(id);
    setTimeout(() => setFlash((f) => (f === id ? null : f)), 1400);
  };

  useEffect(() => {
    if (!jumpToId || loading || error) return;
    if (byId.has(jumpToId)) {
      stickToBottom.current = false;
      jumpTo(jumpToId);
      onJumped?.();
    } else if (hasMore) onLoadOlder();
    else onJumped?.();
  }, [jumpToId, byId, loading, error, hasMore, onLoadOlder, onJumped]);

  return (
    <div className="mx-messages-area">
    <div
      className="mx-scroll"
      ref={scroller}
      onScroll={(e) => {
        const el = e.currentTarget;
        stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
        setAway(!stickToBottom.current);
      }}
    >
      <div className={`mx-thread${summary.direct ? " is-direct" : " is-group"}`} role="log" aria-label="Messages">
        {hasMore ? (
          <div className="mx-older">
            <button className="mx-btn mx-btn-quiet" onClick={loadOlder}>
              Show earlier messages
            </button>
          </div>
        ) : (
          !loading && (
            <div className="mx-origin">
              <Icon.Lock size={14} />
              <p>
                {summary.direct
                  ? `Messages with ${summary.title} are end-to-end encrypted and kept only on your devices.`
                  : "Messages in this group are end-to-end encrypted and kept only on its members' devices."}
              </p>
            </div>
          )
        )}

        {error && <p className="mx-error">Couldn't load messages: {errorText(error)}</p>}

        {!loading && messages.length === 0 && !error && (
          <div className="mx-thread-empty">
            <HyphaeMark />
            <p>{summary.active ? "Say hello. Your first message starts the thread." : "No messages."}</p>
          </div>
        )}

        {messages.map((m, i) => {
          const prev = messages[i - 1];
          const next = messages[i + 1];
          const newDay = !prev || !sameDay(prev.sentAt, m.sentAt);
          const joinsPrev =
            !newDay && !!prev && prev.author === m.author && m.sentAt - prev.sentAt < GROUP_GAP_MS;
          const joinsNext =
            !!next && next.author === m.author && sameDay(m.sentAt, next.sentAt) && next.sentAt - m.sentAt < GROUP_GAP_MS;
          return (
            <Fragment key={m.id}>
              {newDay && (
                <div className="mx-day" role="separator">
                  <span>{formatDay(m.sentAt)}</span>
                </div>
              )}
              <MessageRow
                m={m}
                showAuthor={!summary.direct && !m.isMine && !joinsPrev}
                showAvatar={!summary.direct && !m.isMine && !joinsNext}
                first={!joinsPrev}
                last={!joinsNext}
                quoted={m.replyTo ? byId.get(m.replyTo) ?? null : undefined}
                onJump={jumpTo}
                onReply={onReply}
                onActions={setSelected}
                canAct={summary.active && !summary.request}
                inert={summary.request}
                flashing={flash === m.id}
                editing={editingId === m.id}
                me={me}
              />
            </Fragment>
          );
        })}
      </div>
    </div>
    {away && <button className="mx-latest" aria-label="Jump to latest message" onClick={() => { const el = scroller.current; if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" }); }}><Icon.Down /></button>}
    {undo && <div className="mx-delete-undo" role="status"><span>Message deleted for you</span><button className="mx-btn mx-btn-quiet" onClick={() => {
      const message = undo; setUndo(null); setUndoError(null);
      void mycel.chat.restoreLocal(message.conversation, message.id).catch((e) => setUndoError(errorText(e)));
    }}>Undo</button></div>}
    {undoError && <p className="mx-msg-error" role="alert">{undoError}</p>}
    {selected && <MessageActions message={byId.get(selected.id) ?? selected} canInteract={summary.active && !summary.request && summary.myRole !== "readOnly"} onClose={() => setSelected(null)} onReply={onReply} onEdit={onEdit} onDeleted={(m, local) => { onDeleted?.(m); if (local) { setUndoError(null); setUndo(m); } }} />}
    </div>
  );
}

const MessageRow = memo(function MessageRow({
  m,
  showAuthor,
  showAvatar,
  first,
  last,
  quoted,
  onJump,
  onReply,
  onActions,
  canAct,
  flashing,
  editing,
  me,
  inert,
}: {
  me: string | undefined;
  /** Message request: attachments and links stay closed until accepted. */
  inert: boolean;
  m: MessageView;
  showAuthor: boolean;
  showAvatar: boolean;
  first: boolean;
  last: boolean;
  /** undefined: not a reply; null: reply to a message that isn't loaded. */
  quoted: MessageView | null | undefined;
  onJump: (id: string) => void;
  onReply?: (m: MessageView) => void;
  onActions: (m: MessageView) => void;
  canAct: boolean;
  flashing: boolean;
  editing: boolean;
}) {
  const mycel = useMycel();
  const gesture = useRef<{ x: number; y: number; dx: number; dy: number; timer: ReturnType<typeof setTimeout> | null } | null>(null);
  const suppressClick = useRef(false);
  const [offset, setOffset] = useState(0);
  const cancelGesture = () => { if (gesture.current?.timer) clearTimeout(gesture.current.timer); gesture.current = null; setOffset(0); };
  useEffect(() => () => { if (gesture.current?.timer) clearTimeout(gesture.current.timer); }, []);
  const [failure, setFailure] = useState<string | null>(null);

  const act = (p: Promise<unknown>) => p.catch((e) => setFailure(errorText(e)));
  const react = (emoji: string) => {
    void act(mycel.chat.react(m.conversation, m.id, emoji));
  };

  const cls = [
    "mx-msg",
    m.isMine ? "is-mine" : "is-theirs",
    first ? "is-first" : "",
    last ? "is-last" : "",
    m.deleted ? "is-deleted" : "",
    flashing ? "is-flash" : "",
    editing ? "is-editing" : "",
  ]
    .filter(Boolean)
    .join(" ");

  const images = m.attachments.filter((a) => a.mime.startsWith("image/"));
  const files = m.attachments.filter((a) => !a.mime.startsWith("image/"));
  const bodyOnlyEmoji = /^\p{Extended_Pictographic}{1,3}$/u.test(m.body.replace(/\s/g, "")) && !m.attachments.length;

  return (
    <div className={cls} data-mid={m.id}>
      <div className="mx-msg-gutter">{showAvatar && <Avatar id={m.author} name={m.authorName} size={28} />}</div>
      <div className="mx-msg-col">
        {showAuthor && <div className="mx-msg-author">{m.authorName}</div>}
        <div className="mx-msg-line"
          onContextMenu={(e) => { { e.preventDefault(); onActions(m); } }}>
          {offset > 0 && <span className="mx-swipe-hint" aria-hidden="true"><Icon.Reply /></span>}
          <div className={`mx-bubble${bodyOnlyEmoji ? " is-emoji" : ""}${images.length && !m.body ? " is-media" : ""}`}
            tabIndex={0}
            aria-label={`${m.isMine ? "You" : m.authorName}: ${previewText(m)}. Message actions`}
            style={offset ? { transform: `translateX(${offset}px)` } : undefined}
            onKeyDown={(e) => { if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); onActions(m); } }}
            onPointerDownCapture={(e) => {
              suppressClick.current = false;
              if (!e.isPrimary || e.pointerType === "mouse" || (e.target as Element).closest("button:not(.mx-image),a,audio,video")) return;
              cancelGesture();
              const g = { x: e.clientX, y: e.clientY, dx: 0, dy: 0, timer: null as ReturnType<typeof setTimeout> | null };
              g.timer = setTimeout(() => { suppressClick.current = true; cancelGesture(); onActions(m); }, 480);
              gesture.current = g;
            }}
            onPointerMove={(e) => {
              const g = gesture.current; if (!g) return;
              g.dx = e.clientX - g.x; g.dy = e.clientY - g.y;
              if (Math.hypot(g.dx, g.dy) > 10 && g.timer) { clearTimeout(g.timer); g.timer = null; }
              if (onReply && !m.deleted) {
                const distance = replyDistance(g.dx, g.dy);
                if (distance && !e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.setPointerCapture(e.pointerId);
                setOffset(distance);
              }
            }}
            onPointerUp={(e) => {
              const g = gesture.current;
              if (g && onReply && !m.deleted && completesReply(e.clientX - g.x, e.clientY - g.y)) { suppressClick.current = true; onReply(m); }
              cancelGesture();
            }}
            onPointerCancel={cancelGesture}
            onClickCapture={(e) => { if (suppressClick.current) { e.preventDefault(); e.stopPropagation(); suppressClick.current = false; } }}>
            {m.deleted ? (
              <span className="mx-deleted">{m.isMine ? "You deleted this message" : "This message was deleted"}</span>
            ) : (
              <>
                {quoted !== undefined && (
                  <button
                    className="mx-quote"
                    onClick={() => m.replyTo && onJump(m.replyTo)}
                    disabled={!quoted}
                    title={quoted ? "Go to message" : undefined}
                  >
                    <span className="mx-quote-author">{quoted ? (quoted.isMine ? "You" : quoted.authorName) : "Reply"}</span>
                    <span className="mx-quote-text">{quoted ? previewText(quoted) : "Earlier message"}</span>
                  </button>
                )}
                {inert ? (
                  m.attachments.map((a) => <InertAttachment key={a.blob} a={a} />)
                ) : (
                  <>
                    {images.map((a) => (
                      <ImageAttachment key={a.blob} a={a} />
                    ))}
                    {files.map((a) => (
                      <FileAttachment key={a.blob} a={a} />
                    ))}
                  </>
                )}
                {m.body && <p className="mx-text">{inert ? m.body : linkify(m.body)}</p>}
              </>
            )}
            <span className="mx-meta">
              {m.edited && !m.deleted && <span className="mx-edited">edited</span>}
              <time dateTime={new Date(m.sentAt).toISOString()} title={new Date(m.sentAt).toLocaleString()}>
                {formatClock(m.sentAt)}
              </time>
              {m.isMine && !m.deleted && <DeliveryMark delivery={m.delivery} />}
            </span>
          </div>

          {<button className="mx-message-more mx-icon-btn" onClick={() => onActions(m)} aria-label="Message actions" title="Message actions"><Icon.More size={16} /></button>}
        </div>

        {m.reactions.length > 0 && (
          <div className="mx-reactions">
            {m.reactions.map((r) => (
              <ReactionChip key={r.emoji} emoji={r.emoji} by={r.by} me={me} onToggle={() => react(r.emoji)} disabled={!canAct} />
            ))}
          </div>
        )}
        {failure && (
          <p className="mx-msg-error" role="alert" onClick={() => setFailure(null)}>
            {failure}
          </p>
        )}
      </div>
    </div>
  );
});

function ReactionChip({
  emoji,
  by,
  me,
  onToggle,
  disabled,
}: {
  emoji: string;
  by: string[];
  me: string | undefined;
  onToggle: () => void;
  disabled: boolean;
}) {
  const mine = !!me && by.includes(me);
  const others = by.length - (mine ? 1 : 0);
  const label = mine
    ? others > 0
      ? `You and ${others} other${others > 1 ? "s" : ""} reacted ${emoji}`
      : `You reacted ${emoji}`
    : `${by.length} reacted ${emoji}`;
  return (
    <button
      className={`mx-reaction${mine ? " is-mine" : ""}`}
      onClick={onToggle}
      disabled={disabled}
      aria-pressed={mine}
      title={label}
      aria-label={label}
    >
      <span>{emoji}</span>
      <span className="mx-reaction-n">{by.length}</span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Attachments

function useAttachment(a: Attachment) {
  const mycel = useMycel();
  const [state, setState] = useState<"idle" | "fetching" | "error">("idle");
  const [err, setErr] = useState<string | null>(null);
  const fetch = () => {
    setState("fetching");
    setErr(null);
    mycel.chat.fetchAttachment(a.blob).then(
      () => setState("idle"),
      (e) => {
        setState("error");
        setErr(errorText(e));
      },
    );
  };
  const url = a.localPath ? mycel.files.url(a.localPath) : null;
  const open = () => a.localPath && void mycel.files.open(a.localPath).catch((e) => setErr(errorText(e)));
  const transfer = useTransfer(a.blob);
  const pct =
    state === "fetching" && transfer && transfer.total > 0
      ? Math.min(100, Math.floor((transfer.done / transfer.total) * 100))
      : null;
  const rate = pct != null ? formatRate(transfer?.rate) : "";
  return { state, err, fetch, url, open, pct, rate };
}

/** Thin download progress bar under an attachment. */
function ProgressBar({ pct }: { pct: number }) {
  return (
    <span className="mx-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
      <span style={{ width: `${pct}%` }} />
    </span>
  );
}

function ImageAttachment({ a }: { a: Attachment }) {
  const { state, err, fetch, url, open, pct, rate } = useAttachment(a);
  const [viewing, setViewing] = useState(false);
  if (url) {
    return (
      <><button className="mx-image" onDragStart={(e) => e.preventDefault()} onClick={() => setViewing(true)} title={`Open ${a.name}`}>
        <img src={url} alt={a.name} loading="lazy" draggable={false} />
      </button>
      {viewing && <ChatModal title={a.name} className="mx-media-viewer" onClose={() => setViewing(false)}><img src={url} alt={a.name} /><button className="mx-menu-item" onClick={open}>Share or save<Icon.Open /></button>{err && <p role="alert">{err}</p>}</ChatModal>}</>
    );
  }
  return (
    <div className="mx-image is-pending">
      <Icon.File size={22} />
      <span className="mx-file-name">{a.name}</span>
      <span className="mx-file-size">{formatSize(a.size)}</span>
      <button className="mx-btn mx-btn-small" onClick={fetch} disabled={state === "fetching"}>
        {state === "fetching" ? <span className="mx-spinner" aria-label="Downloading" /> : <Icon.Download size={15} />}
        {state === "fetching" ? (pct != null ? `Downloading ${pct}%${rate ? ` · ${rate}` : ""}` : "Downloading") : "Download photo"}
      </button>
      {pct != null && <ProgressBar pct={pct} />}
      {err && <span className="mx-file-err">{err}</span>}
    </div>
  );
}

/** An attachment in a message request: name and size only. Nothing is fetched, previewed or opened. */
function InertAttachment({ a }: { a: Attachment }) {
  return (
    <div className="mx-file is-inert" title="Accept the request to download attachments">
      <span className="mx-file-icon">
        <Icon.File size={20} />
      </span>
      <span className="mx-file-text">
        <span className="mx-file-name">{a.name}</span>
        <span className="mx-file-size">{formatSize(a.size)}, opens after you accept</span>
      </span>
    </div>
  );
}

function FileAttachment({ a }: { a: Attachment }) {
  const { state, err, fetch, url, open, pct, rate } = useAttachment(a);
  if (url && (a.mime.startsWith("audio/") || a.mime.startsWith("video/"))) {
    return <div className="mx-inline-media">{a.mime.startsWith("audio/")
      ? <audio controls preload="metadata" src={url} aria-label={a.name} />
      : <video controls playsInline preload="metadata" src={url} aria-label={a.name} />}
      <span className="mx-file-size">{a.name}</span>
    </div>;
  }
  return (
    <div className="mx-file">
      <span className="mx-file-icon">
        <Icon.File size={20} />
      </span>
      <span className="mx-file-text">
        <span className="mx-file-name">{a.name}</span>
        <span className={`mx-file-size${err ? " is-error" : ""}`}>
          {err ?? (pct != null ? `${pct}% of ${formatSize(a.size)}${rate ? ` · ${rate}` : ""}` : formatSize(a.size))}
        </span>
        {pct != null && <ProgressBar pct={pct} />}
      </span>
      {url ? (
        <button className="mx-icon-btn mx-file-btn" onClick={open} aria-label={`Open ${a.name}`} title="Open">
          <Icon.Open size={17} />
        </button>
      ) : (
        <button
          className="mx-icon-btn mx-file-btn"
          onClick={fetch}
          disabled={state === "fetching"}
          aria-label={`Download ${a.name}`}
          title="Download"
        >
          {state === "fetching" ? <span className="mx-spinner" /> : <Icon.Download size={17} />}
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------

const URL_RE = /(https?:\/\/[^\s<]+[^\s<.,;:!?)\]'"])/g;

function linkify(text: string) {
  const parts = text.split(URL_RE);
  return parts.map((p, i) =>
    i % 2 === 1 ? (
      <a key={i} href={p} target="_blank" rel="noreferrer noopener">
        {p}
      </a>
    ) : (
      p
    ),
  );
}
