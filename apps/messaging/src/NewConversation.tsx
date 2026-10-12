import { useEffect, useMemo, useRef, useState } from "react";
import { useContacts, useMycel, useNearby } from "@mycel/sdk/react";
import { Avatar, Icon, errorText } from "./ui.tsx";
import { matchesSearch } from "./search.ts";
import { SearchField } from "./SearchField.tsx";
import { presenceOf, PRESENCE_LABEL } from "./presence.ts";

export function NewConversationDialog({
  onClose,
  onCreated,
  onOpenContacts,
}: {
  onClose: () => void;
  onCreated: (id: string) => void;
  onOpenContacts?: () => void;
}) {
  const mycel = useMycel();
  const { contacts, loading } = useContacts();
  const { nearby } = useNearby();
  const [chosen, setChosen] = useState<string[]>([]);
  const [title, setTitle] = useState("");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const d = dialog.current;
    if (d && !d.open) d.showModal();
  }, []);

  const strangers = nearby.filter((n) => !n.isContact);
  const shownContacts = useMemo(() => contacts.filter((c) => matchesSearch(query, c.name)), [contacts, query]);
  const shownStrangers = strangers.filter((n) => matchesSearch(query, n.name));
  const names = new Map([...contacts, ...strangers].map((p) => [p.id, p.name]));

  const toggle = (id: string) => setChosen((c) => (c.includes(id) ? c.filter((x) => x !== id) : [...c, id]));
  const group = chosen.length > 1;

  const create = async () => {
    if (!chosen.length || busy) return;
    setBusy(true);
    setError(null);
    try {
      // People on the network who aren't contacts yet: add them first.
      const contactIds = new Set(contacts.map((c) => c.id));
      for (const id of chosen) {
        if (!contactIds.has(id)) await mycel.contacts.addNearby(id);
      }
      const conv = await mycel.chat.create(group ? title.trim() || null : null, chosen);
      onCreated(conv.id);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <dialog
      ref={dialog}
      className="mx-dialog"
      aria-labelledby="mx-new-title"
      onClose={onClose}
      onClick={(e) => {
        if (e.target === dialog.current) dialog.current?.close();
      }}
    >
      <form
        method="dialog"
        className="mx-dialog-body"
        onSubmit={(e) => {
          e.preventDefault();
          void create();
        }}
      >
        <header className="mx-dialog-head">
          <h2 id="mx-new-title">New conversation</h2>
          <button type="button" className="mx-icon-btn" onClick={() => dialog.current?.close()} aria-label="Close">
            <Icon.X />
          </button>
        </header>

        <SearchField value={query} onChange={setQuery} label="Find people" autoFocus />

        {chosen.length > 0 && (
          <ul className="mx-chips" aria-label="Selected">
            {chosen.map((id) => (
              <li key={id}>
                {names.get(id) ?? "Someone"}
                <button type="button" onClick={() => toggle(id)} aria-label={`Remove ${names.get(id)}`}>
                  <Icon.X size={12} />
                </button>
              </li>
            ))}
          </ul>
        )}

        <div className="mx-people">
          <h3>Contacts</h3>
          {!loading && contacts.length === 0 && (
            <p className="mx-people-empty">
              You haven't added anyone yet.{" "}
              {onOpenContacts && (
                <button
                  type="button"
                  className="mx-link"
                  onClick={() => {
                    dialog.current?.close();
                    onOpenContacts();
                  }}
                >
                  Add a contact
                </button>
              )}
            </p>
          )}
          {contacts.length > 0 && shownContacts.length === 0 && <p className="mx-people-empty">No contacts match.</p>}
          {!loading && query.trim() && shownContacts.length === 0 && shownStrangers.length === 0 && (
            <p className="mx-people-empty" role="status">No people match "{query.trim()}".</p>
          )}
          <ul>
            {shownContacts.map((c) => (
              <PersonRow
                key={c.id}
                id={c.id}
                name={c.name}
                note={PRESENCE_LABEL[presenceOf(c)]}
                status={presenceOf(c)}
                checked={chosen.includes(c.id)}
                onToggle={() => toggle(c.id)}
              />
            ))}
          </ul>

          {shownStrangers.length > 0 && (
            <>
              <h3>Nearby, not in contacts</h3>
              <ul>
                {shownStrangers.map((n) => (
                  <PersonRow
                    key={n.id}
                    id={n.id}
                    name={n.name}
                    note="Nearby · Will be added to your contacts"
                    status="nearby"
                    checked={chosen.includes(n.id)}
                    onToggle={() => toggle(n.id)}
                  />
                ))}
              </ul>
            </>
          )}
        </div>

        {group && (
          <label className="mx-field">
            <span>Group name</span>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Optional. Members' names are used otherwise."
              maxLength={80}
            />
          </label>
        )}

        {error && (
          <p className="mx-dialog-error" role="alert">
            {error}
          </p>
        )}

        <footer className="mx-dialog-foot">
          <button type="button" className="mx-btn mx-btn-quiet" onClick={() => dialog.current?.close()}>
            Cancel
          </button>
          <button type="submit" className="mx-btn mx-btn-primary" disabled={!chosen.length || busy}>
            {busy ? "Creating…" : group ? `Create group of ${chosen.length + 1}` : "Start chat"}
          </button>
        </footer>
      </form>
    </dialog>
  );
}

function PersonRow({
  id,
  name,
  note,
  status,
  checked,
  onToggle,
}: {
  id: string;
  name: string;
  note: string;
  status: "online" | "nearby" | "offline";
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <li>
      <label className={`mx-person${checked ? " is-checked" : ""}`}>
        <input type="checkbox" checked={checked} onChange={onToggle} />
        <Avatar id={id} name={name} size={34} status={status} />
        <span className="mx-person-text">
          <span className="mx-person-name">{name}</span>
          <span className="mx-person-note">{note}</span>
        </span>
        <span className="mx-check" aria-hidden="true">
          <Icon.Check size={14} />
        </span>
      </label>
    </li>
  );
}
