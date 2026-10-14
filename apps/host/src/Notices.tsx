import { useState } from "react";
import { useNotices } from "@mycel/sdk/react";
import { Glyph } from "./icons.tsx";
import { noticeView } from "./noticeText.ts";

/**
 * What the runtime wants the user to know (a new identity, a reset network
 * setting, set-aside records, a failing disk), above whichever app is open.
 * Dismissing hides a notice for this session; a failing disk stays until
 * saving works again.
 */
export function NoticeBanner({ onOpenNetwork }: { onOpenNetwork: () => void }) {
  const { notices } = useNotices();
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(new Set());
  const shown = notices.map(noticeView).filter((n) => n.ongoing || !dismissed.has(n.key));
  if (!shown.length) return null;
  return (
    <div className="notices">
      {shown.map((n) => (
        <div key={n.key} className={`notice${n.ongoing ? " is-ongoing" : ""}`} role={n.ongoing ? "alert" : "status"}>
          <span className="notice-mark" aria-hidden="true" />
          <p className="notice-text">{n.text}</p>
          {n.action === "network" && (
            <button className="h-btn h-btn-quiet h-btn-small" onClick={onOpenNetwork}>
              Open Network
            </button>
          )}
          {!n.ongoing && (
            <button
              className="notice-dismiss"
              onClick={() => setDismissed((d) => new Set(d).add(n.key))}
              aria-label="Dismiss"
              title="Dismiss"
            >
              <Glyph.Close />
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
