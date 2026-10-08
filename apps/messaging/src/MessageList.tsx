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
  formatSize,
  previewText,
  sameDay,
} from "./ui.tsx";
import { HyphaeMark } from "./MessagingApp.tsx";

const GROUP_GAP_MS = 6 * 60_000;
export const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

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
}

export function MessageList({ me, summary, messages, loading, error, hasMore, onLoadOlder, onReply, onEdit, editingId }: Props) {
  const scroller = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);
  const restoreFrom = useRef<{ height: number; top: number } | null>(null);
  const [flash, setFlash] = useState<string | null>(null);

  const byId = useMemo(() => new Map(messages.map((m) => [m.id, m])), [messages]);
  const lastId = messages[messages.length - 1]?.id;
  const lastIsMine = messages[messages.length - 1]?.isMine;

  // Keep the view pinned to the bottom when new messages arrive (or when I send),
  // and keep the reading position when older messages are prepended.
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    if (restoreFrom.current) {
      const { height, top } = restoreFrom.current;
      el.scrollTop = el.scrollHeight - height + top;
      restoreFrom.current = null;
      return;
    }
    if (stickToBottom.current || lastIsMine) el.scrollTop = el.scrollHeight;
  }, [messages, lastId, lastIsMine]);

  // Images load after layout; stay pinned while they do.
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const onLoad = () => {
      if (stickToBottom.current) el.scrollTop = el.scrollHeight;
    };
    el.addEventListener("load", onLoad, true);
    return () => el.removeEventListener("load", onLoad, true);
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

  return (
    <div
      className="mx-scroll"
      ref={scroller}
      onScroll={(e) => {
        const el = e.currentTarget;
        stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
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
                onEdit={onEdit}
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
  onEdit,
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
  onEdit?: (m: MessageView) => void;
  canAct: boolean;
  flashing: boolean;
  editing: boolean;
}) {
  const mycel = useMycel();
  const [picking, setPicking] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const act = (p: Promise<unknown>) => p.catch((e) => setFailure(errorText(e)));
  const react = (emoji: string) => {
    setPicking(false);
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
    <div className={cls} data-mid={m.id} onMouseLeave={() => setPicking(false)}>
      <div className="mx-msg-gutter">{showAvatar && <Avatar id={m.author} name={m.authorName} size={28} />}</div>
      <div className="mx-msg-col">
        {showAuthor && <div className="mx-msg-author">{m.authorName}</div>}
        <div className="mx-msg-line">
          <div className={`mx-bubble${bodyOnlyEmoji ? " is-emoji" : ""}${images.length && !m.body ? " is-media" : ""}`}>
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

          {canAct && !m.deleted && (
            <div className="mx-actions" role="toolbar" aria-label="Message actions">
              <button className="mx-act" onClick={() => setPicking((p) => !p)} aria-label="React" title="React" aria-expanded={picking}>
                <Icon.Smile size={17} />
              </button>
              {onReply && (
                <button className="mx-act" onClick={() => onReply(m)} aria-label="Reply" title="Reply">
                  <Icon.Reply size={17} />
                </button>
              )}
              {m.isMine && onEdit && (
                <button className="mx-act" onClick={() => onEdit(m)} aria-label="Edit" title="Edit">
                  <Icon.Edit size={17} />
                </button>
              )}
              {m.isMine &&
                (confirmDelete ? (
                  <button
                    className="mx-act mx-act-danger is-confirm"
                    onClick={() => void act(mycel.chat.delete(m.conversation, m.id))}
                    onBlur={() => setConfirmDelete(false)}
                    autoFocus
                  >
                    Delete for everyone
                  </button>
                ) : (
                  <button className="mx-act mx-act-danger" onClick={() => setConfirmDelete(true)} aria-label="Delete" title="Delete">
                    <Icon.Trash size={17} />
                  </button>
                ))}
              {picking && (
                <div className="mx-picker" role="menu" aria-label="Pick a reaction">
                  {QUICK_REACTIONS.map((e) => (
                    <button key={e} role="menuitem" onClick={() => react(e)} aria-label={`React with ${e}`}>
                      {e}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
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
  return { state, err, fetch, url, open, pct };
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
  const { state, err, fetch, url, open, pct } = useAttachment(a);
  if (url) {
    return (
      <button className="mx-image" onClick={open} title={`Open ${a.name}`}>
        <img src={url} alt={a.name} loading="lazy" />
      </button>
    );
  }
  return (
    <div className="mx-image is-pending">
      <Icon.File size={22} />
      <span className="mx-file-name">{a.name}</span>
      <span className="mx-file-size">{formatSize(a.size)}</span>
      <button className="mx-btn mx-btn-small" onClick={fetch} disabled={state === "fetching"}>
        {state === "fetching" ? <span className="mx-spinner" aria-label="Downloading" /> : <Icon.Download size={15} />}
        {state === "fetching" ? (pct != null ? `Downloading ${pct}%` : "Downloading") : "Download photo"}
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
  const { state, err, fetch, url, open, pct } = useAttachment(a);
  return (
    <div className="mx-file">
      <span className="mx-file-icon">
        <Icon.File size={20} />
      </span>
      <span className="mx-file-text">
        <span className="mx-file-name">{a.name}</span>
        <span className={`mx-file-size${err ? " is-error" : ""}`}>
          {err ?? (pct != null ? `${pct}% of ${formatSize(a.size)}` : formatSize(a.size))}
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
