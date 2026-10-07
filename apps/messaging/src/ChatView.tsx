import { useCallback, useEffect, useMemo, useState } from "react";
import { useMessages, useMycel, useTyping } from "@mycel/sdk/react";
import type { Contact, ConversationSummary, MessageView } from "@mycel/sdk";
import { MessageList } from "./MessageList.tsx";
import { Composer } from "./Composer.tsx";
import { ConversationAvatar, Icon } from "./ui.tsx";

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

  // Mark read while the conversation is on screen (re-checked when the window regains focus or visibility).
  const unread = summary.unread;
  useEffect(() => {
    if (!unread || !summary.active) return;
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
  }, [mycel, summary.id, unread, summary.active, messages.length]);

  const others = summary.members.filter((m) => !m.isMe && m.role !== "keeper");
  const keepers = summary.members.filter((m) => m.role === "keeper");

  const subtitle = useMemo(() => {
    if (!summary.active) return "You're no longer a member. History stays on this device.";
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

  const canPost = summary.active && summary.myRole !== "readOnly";

  return (
    <section className="mx-chat" aria-label={summary.title}>
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

      {canPost ? (
        <Composer
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
