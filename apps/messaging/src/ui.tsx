import type { ReactNode, SVGProps } from "react";
import type { Member, MessageView } from "@mycel/sdk";

// ---------------------------------------------------------------------------
// Icons (1.6px strokes on a 20px grid, drawn for this app)

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 20, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const Icon = {
  Compose: (p: IconProps) => (
    <Svg {...p}>
      <path d="M9 3.5H5.5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2V11" />
      <path d="M14.6 2.9a1.5 1.5 0 0 1 2.1 2.1L10 11.7l-2.8.7.7-2.8z" />
    </Svg>
  ),
  Send: (p: IconProps) => (
    <Svg {...p}>
      <path d="M3.5 10h7" />
      <path d="M3 3.6l13.6 6.1a.3.3 0 0 1 0 .6L3 16.4a.3.3 0 0 1-.4-.4L5 10 2.6 4a.3.3 0 0 1 .4-.4z" />
    </Svg>
  ),
  Clip: (p: IconProps) => (
    <Svg {...p}>
      <path d="M15.5 9.5l-5.8 5.8a3.5 3.5 0 0 1-5-5L10.6 4.4a2.3 2.3 0 0 1 3.3 3.3L8 13.6a1.2 1.2 0 0 1-1.7-1.7l5.4-5.4" />
    </Svg>
  ),
  Smile: (p: IconProps) => (
    <Svg {...p}>
      <circle cx="10" cy="10" r="7" />
      <path d="M7.2 11.8a3.4 3.4 0 0 0 5.6 0" />
      <path d="M7.6 8h.01M12.4 8h.01" strokeWidth={2.2} />
    </Svg>
  ),
  Reply: (p: IconProps) => (
    <Svg {...p}>
      <path d="M8 5L3.5 9.5 8 14" />
      <path d="M3.5 9.5H11a5 5 0 0 1 5 5v1" />
    </Svg>
  ),
  Edit: (p: IconProps) => (
    <Svg {...p}>
      <path d="M13.6 3.4a1.8 1.8 0 0 1 2.6 2.6L7 15.2l-3.5.9.9-3.5z" />
    </Svg>
  ),
  Trash: (p: IconProps) => (
    <Svg {...p}>
      <path d="M3.5 5.5h13M8 5.5V4a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v1.5M5 5.5l.8 10a1.5 1.5 0 0 0 1.5 1.4h5.4a1.5 1.5 0 0 0 1.5-1.4l.8-10" />
    </Svg>
  ),
  People: (p: IconProps) => (
    <Svg {...p}>
      <circle cx="7.5" cy="7" r="2.8" />
      <path d="M2.5 16a5 5 0 0 1 10 0" />
      <path d="M13 4.5a2.6 2.6 0 0 1 0 5M14.5 11.5a4.6 4.6 0 0 1 3 4.5" />
    </Svg>
  ),
  X: (p: IconProps) => (
    <Svg {...p}>
      <path d="M5 5l10 10M15 5L5 15" />
    </Svg>
  ),
  Check: (p: IconProps) => (
    <Svg {...p}>
      <path d="M4 10.5l3.5 3.5L16 5.5" />
    </Svg>
  ),
  Search: (p: IconProps) => (
    <Svg {...p}>
      <circle cx="9" cy="9" r="5.5" />
      <path d="M13 13l4 4" />
    </Svg>
  ),
  Lock: (p: IconProps) => (
    <Svg {...p}>
      <rect x="4" y="9" width="12" height="8.5" rx="2" />
      <path d="M6.8 9V6.5a3.2 3.2 0 0 1 6.4 0V9" />
    </Svg>
  ),
  File: (p: IconProps) => (
    <Svg {...p}>
      <path d="M11.5 2.5H6a1.5 1.5 0 0 0-1.5 1.5v12A1.5 1.5 0 0 0 6 17.5h8a1.5 1.5 0 0 0 1.5-1.5V6.5z" />
      <path d="M11.5 2.5v4h4" />
    </Svg>
  ),
  Download: (p: IconProps) => (
    <Svg {...p}>
      <path d="M10 3v9.5M6 8.8l4 3.9 4-3.9M4 16.5h12" />
    </Svg>
  ),
  Open: (p: IconProps) => (
    <Svg {...p}>
      <path d="M11 3.5h5.5V9M16.5 3.5L9 11M14.5 12v3a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 15V7A1.5 1.5 0 0 1 5 5.5h3" />
    </Svg>
  ),
  Keeper: (p: IconProps) => (
    <Svg {...p}>
      <rect x="3.5" y="4" width="13" height="5" rx="1.5" />
      <rect x="3.5" y="11" width="13" height="5" rx="1.5" />
      <path d="M6.5 6.5h.01M6.5 13.5h.01" strokeWidth={2.2} />
    </Svg>
  ),
  Back: (p: IconProps) => (
    <Svg {...p}>
      <path d="M12.5 4.5L7 10l5.5 5.5" />
    </Svg>
  ),
  Leave: (p: IconProps) => (
    <Svg {...p}>
      <path d="M8 3.5H5a1.5 1.5 0 0 0-1.5 1.5v10A1.5 1.5 0 0 0 5 16.5h3M12.5 13.5L16 10l-3.5-3.5M16 10H7.5" />
    </Svg>
  ),
  Shield: (p: IconProps) => (
    <Svg {...p}>
      <path d="M10 2.5l6 2.3v4.6c0 3.8-2.5 6.6-6 8.1-3.5-1.5-6-4.3-6-8.1V4.8z" />
      <path d="M7.5 10l1.8 1.8 3.4-3.6" />
    </Svg>
  ),
  Plus: (p: IconProps) => (
    <Svg {...p}>
      <path d="M10 4v12M4 10h12" />
    </Svg>
  ),
};

// ---------------------------------------------------------------------------
// Delivery ticks: clock (local), one tick (sent), two (delivered), two filled (read)

export function DeliveryMark({ delivery }: { delivery: MessageView["delivery"] }) {
  const label = {
    local: "Saved on this device",
    sent: "Sent",
    delivered: "Delivered to everyone",
    read: "Read by everyone",
  }[delivery];
  return (
    <span className={`mx-tick mx-tick-${delivery}`} title={label} aria-label={label} role="img">
      {delivery === "local" ? (
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">
          <circle cx="7" cy="7" r="5" />
          <path d="M7 4.3V7l1.8 1.2" />
        </svg>
      ) : (
        <svg width="18" height="14" viewBox="0 0 18 14" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
          <path d="M1.8 7.4l3 3 6.4-7" />
          {delivery !== "sent" && <path d="M7.6 10.1l.3.3 6.4-7" />}
        </svg>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Avatars

// Six muted, mutually harmonious hues; picked by id so a person keeps theirs everywhere.
const AVATAR_TONES = ["moss", "slate", "ochre", "plum", "clay", "tide"] as const;

export function toneFor(id: string): (typeof AVATAR_TONES)[number] {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return AVATAR_TONES[h % AVATAR_TONES.length]!;
}

export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
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
      className={`mx-avatar tone-${toneFor(id)}`}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.38) }}
      aria-hidden="true"
    >
      {initials(name)}
      {status && status !== "offline" && <span className={`mx-presence mx-presence-${status}`} />}
    </span>
  );
}

/** Avatar for a conversation: the other person for direct chats, a cluster for groups. */
export function ConversationAvatar({
  id,
  direct,
  members,
  title,
  size = 40,
}: {
  id: string;
  direct: boolean;
  members: Member[];
  title: string;
  size?: number;
}) {
  const others = members.filter((m) => !m.isMe && m.role !== "keeper");
  if (direct && others[0]) return <Avatar id={others[0].id} name={others[0].name} size={size} />;
  const shown = others.slice(0, 2);
  if (shown.length < 2) return <Avatar id={id} name={title} size={size} />;
  const small = Math.round(size * 0.64);
  return (
    <span className="mx-avatar-cluster" style={{ width: size, height: size }} aria-hidden="true">
      <Avatar id={shown[0]!.id} name={shown[0]!.name} size={small} />
      <Avatar id={shown[1]!.id} name={shown[1]!.name} size={small} />
    </span>
  );
}

// ---------------------------------------------------------------------------
// Formatting

const dayMs = 86_400_000;

function startOfDay(t: number) {
  const d = new Date(t);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

export function formatClock(t: number): string {
  return new Date(t).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
}

/** Short stamp for the conversation list. */
export function formatListTime(t: number, now = Date.now()): string {
  const today = startOfDay(now);
  if (t >= today) return formatClock(t);
  if (t >= today - dayMs) return "Yesterday";
  if (t >= today - 6 * dayMs) return new Date(t).toLocaleDateString(undefined, { weekday: "short" });
  return new Date(t).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

/** Day separator label in the chat. */
export function formatDay(t: number, now = Date.now()): string {
  const today = startOfDay(now);
  if (t >= today) return "Today";
  if (t >= today - dayMs) return "Yesterday";
  if (t >= today - 6 * dayMs) return new Date(t).toLocaleDateString(undefined, { weekday: "long" });
  const sameYear = new Date(t).getFullYear() === new Date(now).getFullYear();
  return new Date(t).toLocaleDateString(undefined, {
    weekday: "long",
    day: "numeric",
    month: "long",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

export function sameDay(a: number, b: number) {
  return startOfDay(a) === startOfDay(b);
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

export function fileNameFromPath(path: string): string {
  const parts = path.split(/[\\/]/);
  const last = parts[parts.length - 1] || path;
  try {
    return decodeURIComponent(last);
  } catch {
    return last;
  }
}

/** One-line preview of a message for lists and reply quotes. */
export function previewText(m: MessageView): string {
  if (m.deleted) return "Message deleted";
  const body = m.body.replace(/\s+/g, " ").trim();
  if (body) return body;
  const a = m.attachments[0];
  if (!a) return "";
  const kind = a.mime.startsWith("image/") ? "Photo" : a.name;
  return m.attachments.length > 1 ? `${kind} and ${m.attachments.length - 1} more` : kind;
}

export const ROLE_LABEL: Record<Member["role"], string> = {
  admin: "Admin",
  member: "Member",
  readOnly: "Read only",
  keeper: "Keeper",
};

export function errorText(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
