import { useState } from "react";
import { useMycel, useNearby, useNetwork } from "@mycel/sdk/react";
import { Avatar, errorText } from "./common.tsx";

export function NearbyPanel() {
  const mycel = useMycel();
  const { nearby, loading } = useNearby();
  const { status } = useNetwork();
  const [pending, setPending] = useState<Set<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, string>>({});

  const add = async (id: string) => {
    setPending((p) => new Set(p).add(id));
    setErrors(({ [id]: _, ...rest }) => rest);
    try {
      await mycel.contacts.addNearby(id);
    } catch (e) {
      setErrors((x) => ({ ...x, [id]: errorText(e) }));
    } finally {
      setPending((p) => {
        const n = new Set(p);
        n.delete(id);
        return n;
      });
    }
  };

  const localOnly = status?.mode === "local";
  const sorted = [...nearby].sort((a, b) => Number(a.isContact) - Number(b.isContact) || a.name.localeCompare(b.name));

  return (
    <div className="p-nearby">
      <div className="p-scan" aria-hidden="true">
        <span />
        <span />
        <span />
      </div>
      <p className="p-help">
        {localOnly
          ? "This device is in local-only mode, so it isn't looking for anyone on the network."
          : "People running Mycel on the same Wi-Fi or wired network show up here. No internet needed."}
      </p>

      {!loading && nearby.length === 0 && !localOnly && (
        <p className="p-empty">Nobody nearby right now. They'll appear here as soon as they open Mycel on this network.</p>
      )}

      <ul className="p-people">
        {sorted.map((n) => (
          <li key={n.id} className="p-person">
            <Avatar id={n.id} name={n.name} size={36} status="nearby" />
            <span className="p-person-text">
              <span className="p-person-name">{n.name}</span>
              <span className="p-person-note">{errors[n.id] ?? (n.isContact ? "In your contacts" : "Not in your contacts")}</span>
            </span>
            {n.isContact ? (
              <span className="p-tag">Contact</span>
            ) : (
              <button className="h-btn h-btn-primary h-btn-small" disabled={pending.has(n.id)} onClick={() => void add(n.id)}>
                {pending.has(n.id) ? "Adding…" : "Add"}
              </button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
