import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent } from "react";
import { useMessages, useMycel, useTyping } from "@mycel/sdk/react";
import type { Contact, ConversationSummary, MessageView } from "@mycel/sdk";
import { MessageList } from "./MessageList.tsx";
import { Composer, type ComposerHandle } from "./Composer.tsx";
import { ConversationAvatar, Icon, errorText } from "./ui.tsx";

export function ChatView({
  summary,
  me,
  contactsById,
  membersOpen,
  onToggleMembers,
  onBack,
}: {
  summary: ConversationSummary;
  me: string | undefined;
  contactsById: Map<string, Contact>;
  membersOpen: boolean;
  onToggleMembers: () => void;
  onBack: () => void;
}) {
  const mycel = useMycel();
  const { messages, loading, hasMore, loadOlder, error } = useMessages(summary.id);
  const typingPeers = useTyping(summary.id);
  const [replyTo, setReplyTo] = useState<MessageView | null>(null);
  const [editing, setEditing] = useState<MessageView | null>(null);

  // Mark read while the conversation is on screen (re-checked when the window
  // regains focus or visibility). Never for a message request: a read receipt
  // would tell a stranger you've seen it.
  const unread = summary.unread;
  useEffect(() => {
    if (!unread || !summary.active || summary.request) return;
    const tryMark = () => {
      if (document.visibilityState === "visible") {
        void mycel.chat.markRead(summary.id).catch(() => {});
      }
    };
    tryMark();
    window.addEventListener("focus", tryMark);
    document.addEventListener("visibilitychange", tryMark);
    return () => {
      window.removeEventListener("focus", tryMark);
      document.removeEventListener("visibilitychange", tryMark);
    };
  }, [mycel, summary.id, unread, summary.active, summary.request, messages.length]);

  const others = summary.members.filter((m) => !m.isMe && m.role !== "keeper");
  const keepers = summary.members.filter((m) => m.role === "keeper");

  const subtitle = useMemo(() => {
    if (!summary.active) return "You're no longer a member. History stays on this device.";
    if (summary.request) return summary.direct ? "Message request" : `Message request, ${others.length + 1} people`;
    if (summary.direct) {
      const other = others[0];
      const contact = other ? contactsById.get(other.id) : undefined;
      if (!contact) return "Not in your contacts";
      if (contact.nearby) return "On your network";
      if (contact.online) return "Online";
      return "Offline. Messages will arrive when they're back.";
    }
    const people = `${others.length + 1} people`;
    return keepers.length ? `${people}, ${keepers.length} keeper${keepers.length > 1 ? "s" : ""}` : people;
  }, [summary, others, keepers, contactsById]);

  const typingNames = typingPeers
    .filter((p) => p !== me)
    .map((p) => summary.members.find((m) => m.id === p)?.name.split(" ")[0] ?? "Someone");

  const startReply = useCallback((m: MessageView) => {
    setEditing(null);
    setReplyTo(m);
  }, []);
  const startEdit = useCallback((m: MessageView) => {
    setReplyTo(null);
    setEditing(m);
  }, []);

  const canPost = summary.active && !summary.request && summary.myRole !== "readOnly";

  // Drag files onto the conversation to attach them. The native host reports
  // real paths; in a browser, HTML drop events carry File objects.
  const composer = useRef<ComposerHandle>(null);
  const [dragging, setDragging] = useState(false);
  const dragDepth = useRef(0);
  const canDrop = canPost && !editing;
  useEffect(() => {
    if (!canDrop || !mycel.files.onDragDrop) return;
    const off = mycel.files.onDragDrop((e) => {
      if (e.type === "over") setDragging(true);
      else {
        setDragging(false);
        if (e.type === "drop") composer.current?.attachPaths(e.paths);
      }
    });
    return () => {
      off();
      setDragging(false);
    };
  }, [mycel, canDrop]);
  const hasFiles = (e: DragEvent) => Array.from(e.dataTransfer.types).includes("Files");
  const html5Drop = canDrop && !!mycel.files.stage && !mycel.files.onDragDrop;
  const dropHandlers = html5Drop
    ? {
        onDragEnter: (e: DragEvent) => {
          if (!hasFiles(e)) return;
          e.preventDefault();
          dragDepth.current += 1;
          setDragging(true);
        },
        onDragOver: (e: DragEvent) => {
          if (!hasFiles(e)) return;
          e.preventDefault();
          e.dataTransfer.dropEffect = "copy";
        },
        onDragLeave: () => {
          dragDepth.current = Math.max(0, dragDepth.current - 1);
          if (dragDepth.current === 0) setDragging(false);
        },
        onDrop: (e: DragEvent) => {
          if (!hasFiles(e)) return;
          e.preventDefault();
          dragDepth.current = 0;
          setDragging(false);
          composer.current?.attachFiles(Array.from(e.dataTransfer.files));
        },
      }
    : {};

  return (
    <section className={`mx-chat${dragging ? " is-dropping" : ""}`} aria-label={summary.title} {...dropHandlers}>
      {dragging && (
        <div className="mx-dropzone" aria-hidden="true">
          <div className="mx-dropzone-card">
            <Icon.Clip />
            <span>Drop to attach</span>
            <small>Any size. Folders are sent as .zip</small>
          </div>
        </div>
      )}
      <header className="mx-chat-head">
        <button className="mx-icon-btn mx-back" onClick={onBack} aria-label="Back to conversations">
          <Icon.Back />
        </button>
        <ConversationAvatar id={summary.id} direct={summary.direct} members={summary.members} title={summary.title} size={38} />
        <div className="mx-chat-title">
          <h2>{summary.title}</h2>
          <p>{subtitle}</p>
        </div>
        <span className="mx-e2e" title="End-to-end encrypted. Only the people in this conversation can read it.">
          <Icon.Lock size={15} />
          <span>Encrypted</span>
        </span>
        <button
          className={`mx-icon-btn${membersOpen ? " is-on" : ""}`}
          onClick={onToggleMembers}
          aria-pressed={membersOpen}
          title={summary.direct ? "Details" : "Members"}
          aria-label={summary.direct ? "Conversation details" : "Members"}
        >
          <Icon.People />
        </button>
      </header>

      <MessageList
        me={me}
        summary={summary}
        messages={messages}
        loading={loading}
        error={error}
        hasMore={hasMore}
        onLoadOlder={loadOlder}
        onReply={canPost ? startReply : undefined}
        onEdit={canPost ? startEdit : undefined}
        editingId={editing?.id ?? null}
      />

      <div className="mx-typing" aria-live="polite">
        {typingNames.length > 0 && (
          <>
            <span className="mx-typing-dots" aria-hidden="true">
              <i />
              <i />
              <i />
            </span>
            {typingNames.length === 1
              ? `${typingNames[0]} is typing`
              : typingNames.length === 2
                ? `${typingNames[0]} and ${typingNames[1]} are typing`
                : "Several people are typing"}
          </>
        )}
      </div>

      {summary.request ? (
        <RequestBar summary={summary} onDeclined={onBack} />
      ) : canPost ? (
        <Composer
          ref={composer}
          conversation={summary}
          messages={messages}
          replyTo={replyTo}
          editing={editing}
          onCancelReply={() => setReplyTo(null)}
          onCancelEdit={() => setEditing(null)}
          onStartEdit={startEdit}
        />
      ) : (
        <div className="mx-composer-off">
          {summary.active
            ? "You can read this conversation, but only members can post."
            : "You were removed from this conversation, so you can't send messages here."}
        </div>
      )}
    </section>
  );
}

/**
 * Shown instead of the composer while a conversation is a message request.
 * Nothing is sent to the inviter (no receipts, no typing, no replies) until
 * the request is accepted.
 */
function RequestBar({ summary, onDeclined }: { summary: ConversationSummary; onDeclined: () => void }) {
  const mycel = useMycel();
  const [busy, setBusy] = useState<"accept" | "decline" | "block" | null>(null);
  const [confirmBlock, setConfirmBlock] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const inviter = summary.members.find((m) => m.id === summary.invitedBy);
  const name = inviter?.name || "Someone";
  const first = name.split(" ")[0];

  const run = async (kind: "accept" | "decline" | "block") => {
    setBusy(kind);
    setError(null);
    try {
      if (kind === "accept") {
        await mycel.chat.acceptRequest(summary.id);
        setBusy(null);
      } else {
        await mycel.chat.declineRequest(summary.id, { block: kind === "block" });
        onDeclined();
      }
    } catch (e) {
      setError(errorText(e));
      setBusy(null);
    }
  };

  return (
    <div className="mx-request" role="region" aria-label="Message request">
      <div className="mx-request-text">
        <Icon.Shield size={20} />
        <div>
          <p className="mx-request-lead">
            {summary.direct
              ? `${name} isn't in your contacts.`
              : `${name} added you to ${summary.title}. ${first} isn't in your contacts.`}{" "}
            They can't see anything about you until you accept.
          </p>
          <p className="mx-request-note">
            Accepting adds {first} to your contacts and lets you reply. Declining leaves quietly, and they aren't told
            whether you read anything. Attachments and links stay closed until you accept.
          </p>
        </div>
      </div>
      {error && (
        <p className="mx-request-error" role="alert">
          {error}
        </p>
      )}
      <div className="mx-request-actions">
        {confirmBlock ? (
          <>
            <span className="mx-request-confirm">Block {first}? You won't get requests from them again.</span>
            <button className="mx-btn mx-btn-quiet" onClick={() => setConfirmBlock(false)} disabled={!!busy}>
              Cancel
            </button>
            <button className="mx-btn mx-btn-danger" onClick={() => void run("block")} disabled={!!busy} autoFocus>
              {busy === "block" ? "Blocking…" : "Block and decline"}
            </button>
          </>
        ) : (
          <>
            <button className="mx-btn mx-btn-text-danger" onClick={() => setConfirmBlock(true)} disabled={!!busy}>
              Block
            </button>
            <button className="mx-btn mx-btn-quiet" onClick={() => void run("decline")} disabled={!!busy}>
              {busy === "decline" ? "Declining…" : "Decline"}
            </button>
            <button className="mx-btn mx-btn-primary" onClick={() => void run("accept")} disabled={!!busy}>
              {busy === "accept" ? "Accepting…" : "Accept"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
