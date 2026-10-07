import { useMemo, useState } from "react";
import type { ConversationSummary } from "@mycel/sdk";
import { ConversationAvatar, Icon, formatListTime, previewText } from "./ui.tsx";

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
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return conversations;
    return conversations.filter(
      (c) => c.title.toLowerCase().includes(q) || c.members.some((m) => m.name.toLowerCase().includes(q)),
    );
  }, [conversations, query]);
  const unreadTotal = conversations.reduce((n, c) => n + (c.active ? c.unread : 0), 0);

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
      {conversations.length > 3 && (
        <label className="mx-search">
          <Icon.Search size={16} />
          <input
            type="search"
            placeholder="Search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search conversations"
          />
        </label>
      )}
      <ul className="mx-list-items" role="listbox" aria-label="Conversations">
        {loading && conversations.length === 0 &&
          [0, 1, 2].map((i) => <li key={i} className="mx-list-skeleton" aria-hidden="true" />)}
        {!loading && conversations.length === 0 && (
          <li className="mx-list-empty">
            <p>Your conversations will show up here.</p>
            <button className="mx-btn mx-btn-quiet" onClick={onCompose}>
              New conversation
            </button>
          </li>
        )}
        {conversations.length > 0 && filtered.length === 0 && (
          <li className="mx-list-empty">
            <p>Nothing matches "{query}".</p>
          </li>
        )}
        {filtered.map((c) => (
          <ConversationRow key={c.id} c={c} active={c.id === selected} onSelect={onSelect} />
        ))}
      </ul>
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
  const unread = c.active ? c.unread : 0;
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
      className={`mx-row${active ? " is-active" : ""}${unread ? " is-unread" : ""}${c.active ? "" : " is-inactive"}`}
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
          {unread > 0 && (
            <span className="mx-badge" aria-label={`${unread} unread`}>
              {unread > 99 ? "99+" : unread}
            </span>
          )}
        </div>
      </div>
    </li>
  );
}
