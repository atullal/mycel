// Small pieces shared by the host panels. The host deliberately does not import
// UI from apps. Presence labels share a pure semantic helper with messaging.
import { presenceOf, PRESENCE_LABEL } from "../../../messaging/src/presence.ts";

const TONES = ["moss", "slate", "ochre", "plum", "clay", "tide"] as const;

export function toneFor(id: string) {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return TONES[h % TONES.length]!;
}

export function initials(name: string) {
  // Words that start with a letter, ignoring "(M5)"-style suffixes, so a
  // device name like "iPad Pro 11-inch (M5)" gives "IP".
  const words = name.trim().split(/\s+/).filter(Boolean);
  const lettered = name.replace(/\([^)]*\)/g, " ").trim().split(/\s+/).filter((w) => /^\p{L}/u.test(w));
  const parts = lettered.length ? lettered : words;
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  return (parts[0]![0]! + parts[parts.length - 1]![0]!).toUpperCase();
}

export function Avatar({
  id,
  name,
  size = 36,
  status,
}: {
  id: string;
  name: string;
  size?: number;
  status?: "online" | "nearby" | "offline";
}) {
  return (
    <span
      className={`h-avatar tone-${toneFor(id)}`}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.38) }}
      aria-hidden="true"
    >
      {initials(name)}
      {status && status !== "offline" && <span className={`h-presence is-${status}`} />}
    </span>
  );
}

export const statusOf = presenceOf;
export const STATUS_LABEL = PRESENCE_LABEL;

export function errorText(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

/** Short, readable form of a hex id: first and last 4 characters. */
export function shortId(id: string) {
  return id.length > 12 ? `${id.slice(0, 4)}…${id.slice(-4)}` : id;
}
