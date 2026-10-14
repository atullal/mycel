import { useState } from "react";
import { useMycel, useNotices } from "@mycel/sdk/react";
import { Glyph } from "./icons.tsx";
import { noticeView } from "./noticeText.ts";

/**
 * What the runtime wants the user to know (a new identity, a reset network
 * setting, set-aside records, a failing disk), above whichever app is open.
 * Dismissing tells the runtime, which stops reporting it (across restarts:
 * a phone may have started Mycel unseen); a failing disk stays until saving
 * works again.
 */
export function NoticeBanner({ onOpenNetwork }: { onOpenNetwork: () => void }) {
  const mycel = useMycel();
  const { notices } = useNotices();
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(new Set());
  const shown = notices
    .map((notice) => ({ notice, ...noticeView(notice) }))
    .filter((n) => n.ongoing || !dismissed.has(n.key));
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
              onClick={() => {
                // Hide at once; the runtime forgets it for good (a failed
                // save just means it shows again next start).
                setDismissed((d) => new Set(d).add(n.key));
                mycel.notices.dismiss(n.notice).catch(() => {});
              }}
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
