import { useEffect, useRef, useState } from "react";
import { SearchField, useMycel } from "@mycel/sdk/react";
import type { MessageView } from "@mycel/sdk";
import { ChatModal } from "./ChatModal.tsx";
import { errorText, previewText } from "./ui.tsx";

export function ChatSearch({ conversation, onClose, onPick }: {
  conversation: string; onClose: () => void; onPick: (message: MessageView) => void;
}) {
  const mycel = useMycel();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<MessageView[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  useEffect(
    () =>
      mycel.on("conversationUpdated", (e) => {
        if (e.conversation === conversation) setRevision((r) => r + 1);
      }),
    [mycel, conversation],
  );
  // The query these results answer. A new query starts afresh ("Searching…");
  // a change in the conversation (a new message, a receipt, an edit) re-runs
  // the same query quietly and swaps the results in when they arrive.
  const searched = useRef<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    if (!query.trim()) {
      searched.current = null;
      setResults([]);
      setError(null);
      setBusy(false);
      return;
    }
    const fresh = searched.current !== query;
    if (fresh) {
      setResults([]);
      setError(null);
      setBusy(true);
    }
    const timer = setTimeout(() => {
      void mycel.chat.search(conversation, query, 101).then(
        (messages) => {
          if (cancelled) return;
          searched.current = query;
          setResults(messages);
          setError(null);
          setBusy(false);
        },
        (e) => {
          if (cancelled) return;
          setError(errorText(e));
          setBusy(false);
        },
      );
    }, fresh ? 180 : 400);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [mycel, conversation, query, revision]);
  return <ChatModal title="Search messages" onClose={onClose}>
    <SearchField value={query} onChange={setQuery} label="Search messages" placeholder="Search text or attachment names" autoFocus />
    <p className="mx-modal-note" role="status">{busy ? "Searching…" : !query.trim() ? "Search this conversation's history on this device." : results.length > 100 ? "Showing the latest 100 matches. Refine your search to see more." : `${results.length} ${results.length === 1 ? "result" : "results"}`}</p>
    {error && <p className="mx-error" role="alert">{error}</p>}
    <div className="mx-chat-search-results">
      {results.slice(0, 100).map((m) => <button key={m.id} className="mx-menu-item mx-chat-search-result" onClick={() => { onClose(); onPick(m); }}>
        <small>{m.isMine ? "You" : m.authorName} · {new Date(m.sentAt).toLocaleString()}</small>
        <span>{m.body || previewText(m)}</span>
        {!!m.body && !!m.attachments.length && <small>{m.attachments.map((a) => a.name).join(", ")}</small>}
      </button>)}
    </div>
  </ChatModal>;
}
