import { useState } from "react";
import { useContacts, useMycel, useNearby } from "@mycel/sdk/react";
import { Avatar, STATUS_LABEL, errorText, statusOf } from "./common.tsx";

export function ContactsPanel({ onShowNearby }: { onShowNearby: () => void }) {
  const mycel = useMycel();
  const { contacts, loading } = useContacts();
  const { nearby } = useNearby();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [added, setAdded] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);

  const strangers = nearby.filter((n) => !n.isContact);

  const add = async () => {
    const c = code.trim();
    if (!c || busy) return;
    setBusy(true);
    setError(null);
    setAdded(null);
    try {
      const contact = await mycel.contacts.add(c);
      setCode("");
      setAdded(contact.name);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="p-contacts">
      <form
        className="p-add"
        onSubmit={(e) => {
          e.preventDefault();
          void add();
        }}
      >
        <label htmlFor="add-code">Add by contact code</label>
        <div className="p-add-row">
          <input
            id="add-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste a code"
            autoComplete="off"
            spellCheck={false}
          />
          <button className="h-btn h-btn-primary" disabled={!code.trim() || busy}>
            {busy ? "Adding…" : "Add"}
          </button>
        </div>
        {error && <p className="p-error">{error}</p>}
        {added && <p className="p-ok">Added {added} to your contacts.</p>}
      </form>

      {strangers.length > 0 && (
        <button className="p-nearby-hint" onClick={onShowNearby}>
          <span className="p-nearby-dot" />
          {strangers.length === 1
            ? `${strangers[0]!.name} is on your network. Add them?`
            : `${strangers.length} people on your network aren't in your contacts.`}
        </button>
      )}

      <h4 className="p-sub">
        {contacts.length ? `${contacts.length} contact${contacts.length === 1 ? "" : "s"}` : "Contacts"}
      </h4>
      {!loading && contacts.length === 0 && (
        <p className="p-empty">No contacts yet. Ask someone for their code, or add a person who's on your network.</p>
      )}
      <ul className="p-people">
        {contacts.map((c) => {
          const s = statusOf(c);
          return (
            <li key={c.id} className="p-person">
              <Avatar id={c.id} name={c.name} size={36} status={s} />
              <span className="p-person-text">
                <span className="p-person-name">{c.name}</span>
                <span className={`p-person-note is-${s}`}>{STATUS_LABEL[s]}</span>
              </span>
              {confirm === c.id ? (
                <span className="p-confirm">
                  <button className="h-link" onClick={() => setConfirm(null)}>
                    Keep
                  </button>
                  <button
                    className="h-link is-danger"
                    onClick={() => {
                      setConfirm(null);
                      void mycel.contacts.remove(c.id).catch((e) => setError(errorText(e)));
                    }}
                  >
                    Remove
                  </button>
                </span>
              ) : (
                <button className="h-link p-remove" onClick={() => setConfirm(c.id)} aria-label={`Remove ${c.name}`}>
                  Remove
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
