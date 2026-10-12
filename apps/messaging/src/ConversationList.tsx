import { useMemo, useState } from "react";
import type { ConversationSummary } from "@mycel/sdk";
import { ConversationAvatar, Icon, formatListTime, previewText } from "./ui.tsx";
import { matchesSearch } from "./search.ts";
import { SearchField } from "./SearchField.tsx";

/** Unread count that belongs on badges: requests are counted separately. */
export function unreadOf(c: ConversationSummary): number {
  return c.active && !c.request ? c.unread : 0;
}

export function ConversationList({
  conversations,
  loading,
  selected,
  onSelect,
  onCompose,
}: {
  conversations: ConversationSummary[];
  loading: boolean;
  selected: string | null;
  onSelect: (id: string) => void;
  onCompose: () => void;
}) {
  const [query, setQuery] = useState("");
  const [requestsOpen, setRequestsOpen] = useState(true);
  const filtered = useMemo(() => {
    return conversations.filter(
      (c) => matchesSearch(query, c.title, ...c.members.map((m) => m.name)),
    );
  }, [conversations, query]);
  const requests = filtered.filter((c) => c.request);
  const chats = filtered.filter((c) => !c.request);
  const unreadTotal = conversations.reduce((n, c) => n + unreadOf(c), 0);

  return (
    <aside className="mx-list" aria-label="Conversations">
      <header className="mx-list-head">
        <h1>
          Messages
          {unreadTotal > 0 && <span className="mx-list-count">{unreadTotal} unread</span>}
        </h1>
        <button className="mx-icon-btn" onClick={onCompose} title="New conversation" aria-label="New conversation">
          <Icon.Compose />
        </button>
      </header>
      <SearchField value={query} onChange={setQuery} label="Search conversations" placeholder="Search names or groups" />
      <div className="mx-list-items">
        {requests.length > 0 && (
          <section className="mx-requests" aria-label="Message requests">
            <button
              className="mx-requests-head"
              onClick={() => setRequestsOpen((o) => !o)}
              aria-expanded={requestsOpen}
            >
              <span className="mx-requests-title">Requests</span>
              <span className="mx-requests-count">{requests.length}</span>
              <span className="mx-requests-note">From people not in your contacts</span>
              <Icon.Back size={14} className={`mx-requests-chevron${requestsOpen ? " is-open" : ""}`} />
            </button>
            {requestsOpen && (
              <ul role="listbox" aria-label="Message requests">
                {requests.map((c) => (
                  <ConversationRow key={c.id} c={c} active={c.id === selected} onSelect={onSelect} />
                ))}
              </ul>
            )}
          </section>
        )}

        <ul role="listbox" aria-label="Chats">
          {loading && conversations.length === 0 &&
            [0, 1, 2].map((i) => <li key={i} className="mx-list-skeleton" aria-hidden="true" />)}
          {!loading && chats.length === 0 && !query.trim() && (
            <li className="mx-list-empty">
              <p>Your conversations will show up here.</p>
              <button className="mx-btn mx-btn-quiet" onClick={onCompose}>
                New conversation
              </button>
            </li>
          )}
          {!loading && query.trim() && filtered.length === 0 && (
            <li className="mx-list-empty">
              <p>Nothing matches "{query}".</p>
            </li>
          )}
          {chats.map((c) => (
            <ConversationRow key={c.id} c={c} active={c.id === selected} onSelect={onSelect} />
          ))}
        </ul>
      </div>
    </aside>
  );
}

function ConversationRow({
  c,
  active,
  onSelect,
}: {
  c: ConversationSummary;
  active: boolean;
  onSelect: (id: string) => void;
}) {
  const last = c.lastMessage;
  const unread = unreadOf(c);
  let preview = last ? previewText(last) : c.active ? "No messages yet" : "";
  if (last && !last.deleted) {
    if (last.isMine) preview = `You: ${preview}`;
    else if (!c.direct) preview = `${last.authorName.split(" ")[0]}: ${preview}`;
  }
  if (!c.active) preview = "You're no longer in this group";

  return (
    <li
      role="option"
      aria-selected={active}
      tabIndex={0}
      className={`mx-row${active ? " is-active" : ""}${unread ? " is-unread" : ""}${c.active ? "" : " is-inactive"}${c.request ? " is-request" : ""}`}
      onClick={() => onSelect(c.id)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(c.id);
        }
      }}
    >
      <ConversationAvatar id={c.id} direct={c.direct} members={c.members} title={c.title} size={42} />
      <div className="mx-row-text">
        <div className="mx-row-top">
          <span className="mx-row-title">{c.title}</span>
          {last && <time className="mx-row-time">{formatListTime(last.sentAt)}</time>}
        </div>
        <div className="mx-row-bottom">
          <span className={`mx-row-preview${last?.deleted ? " is-deleted" : ""}`}>{preview}</span>
          {c.request ? (
            <span className="mx-request-tag">Request</span>
          ) : (
            unread > 0 && (
              <span className="mx-badge" aria-label={`${unread} unread`}>
                {unread > 99 ? "99+" : unread}
              </span>
            )
          )}
        </div>
      </div>
    </li>
  );
}
