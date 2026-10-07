import { useState } from "react";
import { useConversation, useMycel } from "@mycel/sdk/react";
import type { Contact, Member } from "@mycel/sdk";
import { Avatar, Icon, ROLE_LABEL, errorText } from "./ui.tsx";

type Mode = "idle" | "add" | "keeper";

export function MembersPanel({
  conversationId,
  contacts,
  onClose,
  onLeft,
}: {
  conversationId: string;
  contacts: Contact[];
  onClose: () => void;
  onLeft: () => void;
}) {
  const mycel = useMycel();
  const { conversation: c, error: loadError } = useConversation(conversationId);
  const [mode, setMode] = useState<Mode>("idle");
  const [picked, setPicked] = useState<string[]>([]);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!c) {
    return (
      <aside className="mx-panel" aria-label="Members">
        <PanelHead title="Details" onClose={onClose} />
        {loadError && <p className="mx-panel-error">{errorText(loadError)}</p>}
      </aside>
    );
  }

  // Nothing can be changed (or posted) until a message request is accepted.
  const isAdmin = c.active && !c.request && c.myRole === "admin";
  const memberIds = new Set(c.members.map((m) => m.id));
  const candidates = contacts.filter((x) => !memberIds.has(x.id));
  const people = c.members.filter((m) => m.role !== "keeper");
  const keepers = c.members.filter((m) => m.role === "keeper");

  const run = async (p: Promise<unknown>, after?: () => void) => {
    setBusy(true);
    setError(null);
    try {
      await p;
      after?.();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const startMode = (m: Mode) => {
    setMode((cur) => (cur === m ? "idle" : m));
    setPicked([]);
    setError(null);
  };

  const submitPicked = () => {
    if (!picked.length) return;
    if (mode === "add") void run(mycel.chat.addMembers(c.id, picked), () => startMode("idle"));
    else if (mode === "keeper") void run(mycel.chat.addKeeper(c.id, picked[0]!), () => startMode("idle"));
  };

  const saveTitle = () => {
    const t = renaming?.trim();
    if (!t || t === c.title) return setRenaming(null);
    void run(mycel.chat.rename(c.id, t), () => setRenaming(null));
  };

  return (
    <aside className="mx-panel" aria-label={c.direct ? "Conversation details" : "Members"}>
      <PanelHead title={c.direct ? "Details" : "Members"} onClose={onClose} />

      <div className="mx-panel-scroll">
        {!c.direct && (
          <section className="mx-panel-section">
            {renaming !== null ? (
              <form
                className="mx-rename"
                onSubmit={(e) => {
                  e.preventDefault();
                  saveTitle();
                }}
              >
                <input
                  autoFocus
                  value={renaming}
                  onChange={(e) => setRenaming(e.target.value)}
                  onKeyDown={(e) => e.key === "Escape" && setRenaming(null)}
                  aria-label="Group name"
                  maxLength={80}
                />
                <button className="mx-btn mx-btn-small mx-btn-primary" disabled={busy}>
                  Save
                </button>
              </form>
            ) : (
              <div className="mx-panel-title">
                <h3>{c.title}</h3>
                {isAdmin && (
                  <button className="mx-link" onClick={() => setRenaming(c.title)}>
                    Rename
                  </button>
                )}
              </div>
            )}
          </section>
        )}

        <section className="mx-panel-section">
          <h4>{c.direct ? "Between" : `${people.length} people`}</h4>
          <ul className="mx-members">
            {people.map((m) => (
              <MemberRow
                key={m.id}
                m={m}
                canRemove={isAdmin && !m.isMe && !c.direct}
                confirming={confirm === m.id}
                onAsk={() => setConfirm(m.id)}
                onCancel={() => setConfirm(null)}
                onRemove={() => void run(mycel.chat.removeMember(c.id, m.id), () => setConfirm(null))}
              />
            ))}
          </ul>
          {isAdmin && !c.direct && (
            <button className="mx-panel-action" onClick={() => startMode("add")} aria-expanded={mode === "add"}>
              <Icon.Plus size={16} /> Add people
            </button>
          )}
          {mode === "add" && (
            <Picker
              options={candidates}
              picked={picked}
              multi
              onChange={setPicked}
              empty="Everyone in your contacts is already here."
              submitLabel={picked.length > 1 ? `Add ${picked.length} people` : "Add"}
              onSubmit={submitPicked}
              busy={busy}
            />
          )}
        </section>

        <section className="mx-panel-section">
          <h4>Keepers</h4>
          <p className="mx-panel-note">
            A keeper is an always-on device you trust to hold encrypted copies, so messages reach people who are offline.
            It can't read them.
          </p>
          {keepers.length > 0 && (
            <ul className="mx-members">
              {keepers.map((m) => (
                <MemberRow
                  key={m.id}
                  m={m}
                  canRemove={isAdmin}
                  confirming={confirm === m.id}
                  onAsk={() => setConfirm(m.id)}
                  onCancel={() => setConfirm(null)}
                  onRemove={() => void run(mycel.chat.removeMember(c.id, m.id), () => setConfirm(null))}
                />
              ))}
            </ul>
          )}
          {isAdmin && (
            <button className="mx-panel-action" onClick={() => startMode("keeper")} aria-expanded={mode === "keeper"}>
              <Icon.Keeper size={16} /> Add a keeper
            </button>
          )}
          {mode === "keeper" && (
            <Picker
              options={candidates}
              picked={picked}
              multi={false}
              onChange={setPicked}
              empty="Add the keeper device as a contact first."
              submitLabel="Add keeper"
              onSubmit={submitPicked}
              busy={busy}
            />
          )}
        </section>

        {error && (
          <p className="mx-panel-error" role="alert">
            {error}
          </p>
        )}

        {c.active && !c.direct && !c.request && (
          <section className="mx-panel-section">
            {confirm === "leave" ? (
              <div className="mx-confirm">
                <p>Leave {c.title}? You'll keep the history on this device but won't get new messages.</p>
                <div>
                  <button className="mx-btn mx-btn-quiet mx-btn-small" onClick={() => setConfirm(null)}>
                    Stay
                  </button>
                  <button
                    className="mx-btn mx-btn-danger mx-btn-small"
                    disabled={busy}
                    onClick={() => {
                      const me = c.members.find((m) => m.isMe);
                      if (me) void run(mycel.chat.removeMember(c.id, me.id), onLeft);
                    }}
                  >
                    Leave group
                  </button>
                </div>
              </div>
            ) : (
              <button className="mx-panel-action is-danger" onClick={() => setConfirm("leave")}>
                <Icon.Leave size={16} /> Leave group
              </button>
            )}
          </section>
        )}
      </div>
    </aside>
  );
}

function PanelHead({ title, onClose }: { title: string; onClose: () => void }) {
  return (
    <header className="mx-panel-head">
      <h2>{title}</h2>
      <button className="mx-icon-btn" onClick={onClose} aria-label="Close panel">
        <Icon.X />
      </button>
    </header>
  );
}

function MemberRow({
  m,
  canRemove,
  confirming,
  onAsk,
  onCancel,
  onRemove,
}: {
  m: Member;
  canRemove: boolean;
  confirming: boolean;
  onAsk: () => void;
  onCancel: () => void;
  onRemove: () => void;
}) {
  return (
    <li className="mx-member">
      <Avatar id={m.id} name={m.name} size={32} />
      <span className="mx-member-name">
        {m.name}
        {m.isMe && <span className="mx-you"> (you)</span>}
      </span>
      <span className={`mx-role role-${m.role}`}>{ROLE_LABEL[m.role]}</span>
      {!canRemove && <span className="mx-member-spacer" />}
      {canRemove &&
        (confirming ? (
          <span className="mx-member-confirm">
            <button className="mx-link" onClick={onCancel}>
              Keep
            </button>
            <button className="mx-link is-danger" onClick={onRemove}>
              Remove
            </button>
          </span>
        ) : (
          <button className="mx-icon-btn mx-member-remove" onClick={onAsk} aria-label={`Remove ${m.name}`} title="Remove">
            <Icon.X size={15} />
          </button>
        ))}
    </li>
  );
}

function Picker({
  options,
  picked,
  multi,
  onChange,
  empty,
  submitLabel,
  onSubmit,
  busy,
}: {
  options: Contact[];
  picked: string[];
  multi: boolean;
  onChange: (ids: string[]) => void;
  empty: string;
  submitLabel: string;
  onSubmit: () => void;
  busy: boolean;
}) {
  if (options.length === 0) return <p className="mx-panel-note">{empty}</p>;
  const toggle = (id: string) =>
    onChange(multi ? (picked.includes(id) ? picked.filter((x) => x !== id) : [...picked, id]) : picked[0] === id ? [] : [id]);
  return (
    <div className="mx-picker-list">
      <ul>
        {options.map((o) => (
          <li key={o.id}>
            <label className={`mx-person is-compact${picked.includes(o.id) ? " is-checked" : ""}`}>
              <input type={multi ? "checkbox" : "radio"} name="mx-pick" checked={picked.includes(o.id)} onChange={() => toggle(o.id)} />
              <Avatar id={o.id} name={o.name} size={28} />
              <span className="mx-person-text">
                <span className="mx-person-name">{o.name}</span>
              </span>
              <span className="mx-check" aria-hidden="true">
                <Icon.Check size={13} />
              </span>
            </label>
          </li>
        ))}
      </ul>
      <button className="mx-btn mx-btn-primary mx-btn-small" disabled={!picked.length || busy} onClick={onSubmit}>
        {submitLabel}
      </button>
    </div>
  );
}
