// In-memory mock of the Mycel runtime.
//
// Used automatically when the SDK is not running inside Tauri (plain browser,
// `vite` dev server, storybook-style work). It implements every command in
// docs/RUNTIME_API.md with the documented semantics and simulates a small,
// lively network: contacts who reply and type, delivery receipts that progress
// local -> sent -> delivered -> read, people appearing on the LAN, a contact
// coming online, lazy attachments that "download", and a group you get added to.

import type { ArgsOf, Command, FileHost, ResultOf, Transport } from "./transport.ts";
import { encodeVideoFrame } from "./video.ts";
import type {
  Attachment,
  CallEndReason,
  CallInfo,
  ParticipantState,
  Contact,
  ConversationSummary,
  Delivery,
  MemberRole,
  MessageView,
  MycelEvent,
  NearbyPeer,
  NetworkMode,
  NetworkStatus,
  PathKind,
  PeerId,
  Profile,
  Reaction,
} from "./types.ts";

export interface MockOptions {
  /** Your display name. Default "Juno Park". */
  name?: string;
  /** Simulated IPC latency range in ms. Default [25, 90]. */
  latency?: [number, number];
  /** Background activity (people appearing, coming online, new messages). Default true. */
  ambient?: boolean;
  /** Contacts reply to what you send. Default true. */
  replies?: boolean;
  /** Network mode reported by `network_status`. Default "lan". */
  mode?: NetworkMode;
}

// ---------------------------------------------------------------------------
// ids & codes

function fnv(seed: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Deterministic pseudo-random hex (NOT a hash; ids only). */
function hexFrom(seed: string, bytes = 32): string {
  let x = fnv(seed) || 1;
  let out = "";
  for (let i = 0; i < bytes; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    out += ((x >>> 0) & 0xff).toString(16).padStart(2, "0");
  }
  return out;
}

function randomHex(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) crypto.getRandomValues(buf);
  else for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

const B32 = "abcdefghijklmnopqrstuvwxyz234567";
function base32(hex: string): string {
  let bits = "";
  for (let i = 0; i < hex.length; i += 2) bits += parseInt(hex.slice(i, i + 2), 16).toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return out;
}

/** Contact code format used by the mock: `myc1` + base32(peer id). */
export function mockContactCode(id: PeerId): string {
  return `myc1${base32(id)}`;
}

// ---------------------------------------------------------------------------
// people

interface Person {
  id: PeerId;
  name: string;
  contact: boolean;
  nearby: boolean;
  online: boolean;
}

const pid = (name: string) => hexFrom(`peer:${name}`);

const SEED_PEOPLE: Person[] = [
  { id: pid("Ines Duarte"), name: "Ines Duarte", contact: true, nearby: true, online: true },
  { id: pid("Tobias Wren"), name: "Tobias Wren", contact: true, nearby: false, online: true },
  { id: pid("Hana Sato"), name: "Hana Sato", contact: true, nearby: false, online: false },
  { id: pid("Kofi Mensah"), name: "Kofi Mensah", contact: false, nearby: true, online: false },
  // Not visible at start: shows up on the LAN a little later.
  { id: pid("Lena Brandt"), name: "Lena Brandt", contact: false, nearby: false, online: false },
  // Only reachable by contact code (see MOCK_CONTACT_CODES).
  { id: pid("Ravi Iyer"), name: "Ravi Iyer", contact: false, nearby: false, online: true },
];

/** Codes the mock recognises in `add_contact`, by person name. Any other well-formed code adds an unnamed peer. */
export const MOCK_CONTACT_CODES: Record<string, string> = Object.fromEntries(
  SEED_PEOPLE.map((p) => [p.name, mockContactCode(p.id)]),
);

// ---------------------------------------------------------------------------
// conversations

interface Msg {
  id: string;
  author: PeerId;
  sentAt: number;
  body: string;
  replyTo: string | null;
  edited: boolean;
  deleted: boolean;
  attachments: string[]; // blob ids
  reactions: Reaction[];
  delivery: Delivery;
}

interface Conv {
  id: string;
  title: string | null;
  members: { id: PeerId; role: MemberRole }[];
  messages: Msg[];
  unread: number;
  active: boolean;
  /** Ever-increasing activity clock, for "newest activity first" ordering. */
  activity: number;
  /** Set while this is a message request from a non-contact. */
  invitedBy: PeerId | null;
  /** Declined requests disappear from the list. */
  hidden: boolean;
}

interface Blob_ {
  blob: string;
  name: string;
  mime: string;
  size: number;
  local: boolean;
  make: () => Blob;
}

const MIN = 60_000;
const HOUR = 60 * MIN;

const RIDGE_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="960" height="600" viewBox="0 0 960 600">
<defs><linearGradient id="s" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#cfe0d8"/><stop offset="1" stop-color="#eef1e6"/></linearGradient></defs>
<rect width="960" height="600" fill="url(#s)"/>
<path d="M0 380 L140 250 L230 320 L360 170 L470 290 L590 200 L720 330 L830 240 L960 310 L960 600 L0 600Z" fill="#8fa89a"/>
<path d="M0 450 L120 390 L260 430 L400 350 L540 420 L700 370 L860 430 L960 400 L960 600 L0 600Z" fill="#5d7b6b"/>
<path d="M90 560 C 220 500, 260 470, 360 470 S 520 430, 590 400 S 700 360, 760 330" fill="none" stroke="#f4efe2" stroke-width="5" stroke-dasharray="14 10" stroke-linecap="round"/>
<circle cx="590" cy="400" r="12" fill="#c46a3c"/><circle cx="590" cy="400" r="24" fill="none" stroke="#c46a3c" stroke-width="3"/>
<text x="612" y="392" font-family="Georgia, serif" font-size="26" fill="#1d2a24">second fork</text>
<circle cx="760" cy="330" r="9" fill="#1d2a24"/><text x="776" y="320" font-family="Georgia, serif" font-size="22" fill="#1d2a24">ridge</text>
</svg>`;

const ROUTE_TXT = `Saturday climb — plan

07:40  leave from Tobias's (2 seats) and Hana's (3 seats)
08:00  gym opens, warm up on the slab wall
09:30  lead practice in pairs, rotate every 3 routes
12:00  lunch at the bakery across the road

Bring: spare harness (Juno), chalk, tape, water.
`;

const REPLIES = {
  question: [
    "Good question. Let me check and get back to you.",
    "I think so? Not 100% sure.",
    "Yes, works for me.",
    "Hmm, maybe. What did you have in mind?",
  ],
  thanks: ["Any time.", "Of course!", "Happy to help."],
  generic: [
    "Ha, love that.",
    "Makes sense to me.",
    "Sounds good 👍",
    "Okay, noted.",
    "Oh nice, tell me more later.",
    "Agreed.",
    "On it.",
  ],
};

function pick<T>(list: T[]): T {
  return list[Math.floor(Math.random() * list.length)]!;
}

function guessMime(name: string): string {
  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  const map: Record<string, string> = {
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    webp: "image/webp",
    svg: "image/svg+xml",
    pdf: "application/pdf",
    txt: "text/plain",
    md: "text/markdown",
    json: "application/json",
    zip: "application/zip",
    mp3: "audio/mpeg",
    mp4: "video/mp4",
  };
  return map[ext] ?? "application/octet-stream";
}

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

// ---------------------------------------------------------------------------

export interface MockTransport extends Transport {
  readonly kind: "mock";
  readonly files: FileHost;
  /** Stop all timers (tests). */
  dispose(): void;
}

export function createMockTransport(options: MockOptions = {}): MockTransport {
  const opts = {
    name: options.name ?? "Juno Park",
    latency: options.latency ?? ([25, 90] as [number, number]),
    ambient: options.ambient ?? true,
    replies: options.replies ?? true,
    mode: options.mode ?? ("lan" as NetworkMode),
  };

  const meId = hexFrom(`peer:me:${opts.name}`);
  const profile: Profile = { id: meId, name: opts.name, contactCode: mockContactCode(meId) };
  const people = new Map<PeerId, Person>(SEED_PEOPLE.map((p) => [p.id, { ...p }]));
  const convs = new Map<string, Conv>();
  const hiddenMessages = new Map<string, Set<string>>();
  const locallyHidden = (c: Conv, m: Msg) => hiddenMessages.get(c.id)?.has(m.id) ?? false;
  const blobs = new Map<string, Blob_>();
  const uploads = new Map<string, File>();
  const objectUrls = new Map<string, string>();
  const handlers = new Set<(e: MycelEvent) => void>();
  const blocked = new Set<PeerId>();
  let nextMode: NetworkMode = opts.mode;
  const timers = new Set<ReturnType<typeof setTimeout>>();
  let clock = 0;

  const person = (name: string) => people.get(pid(name))!;
  const ines = person("Ines Duarte");
  const tobias = person("Tobias Wren");
  const hana = person("Hana Sato");

  // --- helpers --------------------------------------------------------------

  function later(ms: number, fn: () => void) {
    const t = setTimeout(() => {
      timers.delete(t);
      fn();
    }, ms);
    timers.add(t);
  }

  function emit(event: MycelEvent) {
    // Events are delivered asynchronously, like the real host.
    later(0, () => {
      for (const h of [...handlers]) {
        try {
          h(event);
        } catch (err) {
          console.error("[mycel mock] event handler failed", err);
        }
      }
    });
  }

  const nameOf = (id: PeerId) => (id === meId ? profile.name : people.get(id)?.name ?? `Peer ${id.slice(0, 6)}`);

  function addBlob(name: string, mime: string, size: number, local: boolean, make: () => Blob): string {
    const blob = randomHex(32);
    blobs.set(blob, { blob, name, mime, size, local, make });
    return blob;
  }

  const blobPath = (b: Blob_) => `mock://blob/${b.blob}/${encodeURIComponent(b.name)}`;

  function attachmentView(blob: string): Attachment {
    const b = blobs.get(blob)!;
    return { blob, name: b.name, mime: b.mime, size: b.size, localPath: b.local ? blobPath(b) : null };
  }

  function msgView(c: Conv, m: Msg): MessageView {
    return {
      id: m.id,
      conversation: c.id,
      author: m.author,
      authorName: nameOf(m.author),
      sentAt: m.sentAt,
      body: m.deleted ? "" : m.body,
      replyTo: m.replyTo,
      edited: m.edited,
      deleted: m.deleted,
      attachments: m.deleted ? [] : m.attachments.map(attachmentView),
      reactions: m.deleted ? [] : m.reactions.map((r) => ({ emoji: r.emoji, by: [...r.by] })),
      isMine: m.author === meId,
      delivery: m.delivery,
    };
  }

  const isDirect = (c: Conv) => c.title == null && c.members.length === 2;
  const myRole = (c: Conv): MemberRole | null => (c.active ? c.members.find((m) => m.id === meId)?.role ?? null : null);

  function titleOf(c: Conv): string {
    if (c.title) return c.title;
    const others = c.members.filter((m) => m.id !== meId && m.role !== "keeper").map((m) => nameOf(m.id));
    if (others.length === 0) return "Just you";
    return others.join(", ");
  }

  function summary(c: Conv): ConversationSummary {
    const last = [...c.messages].reverse().find((m) => !m.deleted && !locallyHidden(c, m));
    const hiddenUnread = [...c.messages].reverse().filter((m) => m.author !== meId && !m.deleted)
      .slice(0, c.unread).filter((m) => locallyHidden(c, m)).length;
    return {
      id: c.id,
      aliases: [c.id],
      threadKey: c.id,
      title: titleOf(c),
      direct: isDirect(c),
      members: c.members.map((m) => ({ id: m.id, name: nameOf(m.id), role: m.role, isMe: m.id === meId })),
      lastMessage: last ? msgView(c, last) : null,
      unread: Math.max(0, c.unread - hiddenUnread),
      active: c.active,
      myRole: myRole(c),
      request: c.invitedBy != null,
      invitedBy: c.invitedBy,
    };
  }

  function getConv(id: string): Conv {
    const c = convs.get(id);
    if (!c) throw `No conversation ${id.slice(0, 8)}…`;
    return c;
  }

  function getMsg(c: Conv, id: string): Msg {
    const m = c.messages.find((x) => x.id === id);
    if (!m) throw "That message no longer exists";
    return m;
  }

  function requireActive(c: Conv) {
    if (c.invitedBy) throw "accept this message request before replying";
    if (!c.active) throw "You're no longer a member of this conversation";
  }

  function requireAdmin(c: Conv) {
    requireActive(c);
    if (myRole(c) !== "admin") throw "Only admins can do that";
  }

  function touch(c: Conv) {
    c.activity = ++clock;
    emit({ type: "conversationUpdated", conversation: c.id });
  }

  function otherMembers(c: Conv) {
    return c.members.filter((m) => m.id !== meId && m.role !== "keeper");
  }

  function hasOnlineDevice(c: Conv) {
    return c.members.some((m) => m.id !== meId && people.get(m.id)?.online);
  }

  function allOthersOnline(c: Conv) {
    return otherMembers(c).every((m) => people.get(m.id)?.online);
  }

  // --- delivery simulation ---------------------------------------------------

  const RANK: Record<Delivery, number> = { local: 0, sent: 1, delivered: 2, read: 3 };

  /** Move my messages in `c` forward to at least `to`. */
  function advance(c: Conv, to: Delivery, upTo?: string) {
    let changed = false;
    for (const m of c.messages) {
      if (m.author === meId && RANK[m.delivery] < RANK[to]) {
        m.delivery = to;
        changed = true;
      }
      if (upTo && m.id === upTo) break;
    }
    if (changed) touch(c);
  }

  function progressDelivery(c: Conv, messageId: string) {
    later(450 + Math.random() * 300, () => {
      if (!hasOnlineDevice(c)) return;
      advance(c, "sent", messageId);
      later(700 + Math.random() * 500, () => {
        if (!allOthersOnline(c)) return;
        advance(c, "delivered", messageId);
        // In a group, "read" needs everyone; responders read in simulateReply.
        if (!opts.replies) later(1500, () => advance(c, "read", messageId));
      });
    });
  }

  function chooseReply(text: string): string {
    const t = text.toLowerCase();
    if (/thank|cheers|ta\b/.test(t)) return pick(REPLIES.thanks);
    if (t.includes("?")) return pick(REPLIES.question);
    return pick(REPLIES.generic);
  }

  function typingBurst(c: Conv, peer: PeerId, durationMs: number) {
    for (let t = 0; t < durationMs; t += 1500) {
      later(t, () => emit({ type: "typing", conversation: c.id, peer }));
    }
  }

  function receive(c: Conv, author: PeerId, body: string, extra: Partial<Msg> = {}) {
    if (!c.active) return;
    const m: Msg = {
      id: randomHex(32),
      author,
      sentAt: Date.now(),
      body,
      replyTo: null,
      edited: false,
      deleted: false,
      attachments: [],
      reactions: [],
      delivery: "read",
      ...extra,
    };
    c.messages.push(m);
    c.unread += 1;
    touch(c);
    return m;
  }

  const pendingReply = new Set<string>();

  function simulateReply(c: Conv, mine: Msg) {
    if (!opts.replies || pendingReply.has(c.id)) return;
    const candidates = otherMembers(c).filter((m) => people.get(m.id)?.online);
    if (candidates.length === 0) return;
    const responder = pick(candidates).id;
    pendingReply.add(c.id);
    const think = 1200 + Math.random() * 1200;
    const typeFor = 1800 + Math.random() * 2200;
    later(think, () => {
      // They've opened the conversation: my messages are read (if everyone else has too).
      if (otherMembers(c).length === 1) advance(c, "read", mine.id);
      typingBurst(c, responder, typeFor);
      later(typeFor, () => {
        pendingReply.delete(c.id);
        if (!c.members.some((m) => m.id === responder)) return;
        const lastMine = [...c.messages].reverse().find((m) => m.author === meId && !m.deleted);
        receive(c, responder, chooseReply(lastMine?.body ?? mine.body));
        if (Math.random() < 0.35 && lastMine) {
          // An occasional reaction on what you said.
          lastMine.reactions.push({ emoji: pick(["❤️", "👍", "😂", "✨"]), by: [responder] });
          touch(c);
        }
        if (otherMembers(c).length > 1 && allOthersOnline(c)) later(800, () => advance(c, "read", mine.id));
      });
    });
  }

  // --- seed -------------------------------------------------------------------

  function seedConv(id: string, title: string | null, members: [PeerId, MemberRole][], activityAgo: number): Conv {
    const c: Conv = {
      id,
      title,
      members: members.map(([id, role]) => ({ id, role })),
      messages: [],
      unread: 0,
      active: true,
      activity: -activityAgo,
      invitedBy: null,
      hidden: false,
    };
    convs.set(id, c);
    return c;
  }

  function seedMsg(c: Conv, author: PeerId, ago: number, body: string, extra: Partial<Msg> = {}): Msg {
    const m: Msg = {
      id: hexFrom(`msg:${c.id}:${c.messages.length}`),
      author,
      sentAt: Date.now() - ago,
      body,
      replyTo: null,
      edited: false,
      deleted: false,
      attachments: [],
      reactions: [],
      delivery: "read",
      ...extra,
    };
    c.messages.push(m);
    return m;
  }

  {
    const now = new Date();
    const minutesToday = now.getHours() * 60 + now.getMinutes();
    const yesterday = (minutesToday + 6 * 60) * MIN; // ~6pm yesterday
    const thisMorning = Math.max(minutesToday - 9 * 60, 20) * MIN;

    // 1:1 with Ines: walk notes, a map, a reply, an edit, unread question.
    const di = seedConv(hexFrom("conv:ines"), null, [[meId, "admin"], [ines.id, "admin"]], 1);
    seedMsg(di, ines.id, yesterday + 14 * MIN, "Did the seed swap end up happening on Saturday?");
    seedMsg(di, meId, yesterday + 9 * MIN, "It did! Way more people than last year.");
    seedMsg(di, meId, yesterday + 8.5 * MIN, "Someone brought forty kinds of tomato.");
    seedMsg(di, ines.id, yesterday + 6 * MIN, "Forty. Of course they did.", {
      reactions: [{ emoji: "😂", by: [meId] }],
    });
    const mapBlob = addBlob("ridge-map.svg", "image/svg+xml", RIDGE_SVG.length, false, () => new Blob([RIDGE_SVG], { type: "image/svg+xml" }));
    const mapMsg = seedMsg(di, ines.id, thisMorning, "Putting the walk notes together. Here's the map from the ridge.", {
      attachments: [mapBlob],
    });
    seedMsg(di, ines.id, thisMorning - 1 * MIN, "The second fork is the one we missed last time");
    seedMsg(di, meId, thisMorning - 12 * MIN, "Oh, that's where we went wrong. The trail marker was half buried.", {
      replyTo: mapMsg.id,
      edited: true,
    });
    seedMsg(di, ines.id, 4 * MIN, "Next weekend? Weather looks clear from Friday.");
    di.unread = 1;

    // Group: Saturday climb (Hana is offline, so my latest is only "sent").
    const g = seedConv(hexFrom("conv:climb"), "Saturday climb", [
      [meId, "admin"],
      [tobias.id, "admin"],
      [ines.id, "member"],
      [hana.id, "member"],
    ], 2);
    seedMsg(g, tobias.id, 3 * HOUR, "Gym opens at 8, I can drive two people");
    seedMsg(g, hana.id, 3 * HOUR - 4 * MIN, "I'm in. Can someone bring the spare harness?");
    seedMsg(g, meId, 3 * HOUR - 6 * MIN, "I have it, will pack it tonight", {
      reactions: [{ emoji: "🙏", by: [hana.id, tobias.id] }],
    });
    seedMsg(g, ines.id, 2 * HOUR, "", { deleted: true });
    const planBlob = addBlob("climb-plan.txt", "text/plain", ROUTE_TXT.length, true, () => new Blob([ROUTE_TXT], { type: "text/plain" }));
    seedMsg(g, tobias.id, 47 * MIN, "Plan attached, roughly", { attachments: [planBlob] });
    seedMsg(g, meId, 30 * MIN, "Perfect. Can we push lunch to 12:30?", { delivery: "sent" });
    seedMsg(g, tobias.id, 22 * MIN, "Leaving from mine at 7:40. Don't be late, Juno");
    g.unread = 1;

    // 1:1 with Tobias: older, all read.
    const dt = seedConv(hexFrom("conv:tobias"), null, [[meId, "admin"], [tobias.id, "admin"]], 3);
    seedMsg(dt, tobias.id, 3 * 24 * HOUR, "Sent the invoice to the co-op, they paid already");
    seedMsg(dt, meId, 3 * 24 * HOUR - 3 * MIN, "Brilliant, thank you", { reactions: [{ emoji: "🙏", by: [tobias.id] }] });

    // A group we were removed from: history readable, composer disabled.
    const bc = seedConv(hexFrom("conv:books"), "Book circle", [[hana.id, "admin"], [ines.id, "member"]], 4);
    seedMsg(bc, hana.id, 9 * 24 * HOUR, "Next pick: The Overstory?");
    seedMsg(bc, meId, 9 * 24 * HOUR - 20 * MIN, "Yes please, I've been meaning to read it");
    seedMsg(bc, hana.id, 6 * 24 * HOUR, "We're moving the circle to the new group. See you there!");
    bc.active = false;

    // A message request: Kofi (on the LAN, not a contact) started a chat.
    const kofi = person("Kofi Mensah");
    const rq = seedConv(hexFrom("conv:kofi"), null, [[kofi.id, "admin"], [meId, "admin"]], 0);
    rq.invitedBy = kofi.id;
    seedMsg(rq, kofi.id, 7 * MIN, "Hi Juno, it's Kofi from the bike co-op. We met at the repair night on Thursday.");
    const quote = addBlob("brake-quote.pdf", "application/pdf", 48_213, false, () => new Blob(["(mock pdf)"], { type: "application/pdf" }));
    seedMsg(rq, kofi.id, 6 * MIN, "Here's the quote for your brakes, and the shop's page: https://example.org/coop", {
      attachments: [quote],
    });
    rq.unread = 2;
  }

  // --- calls ---------------------------------------------------------------------
  //
  // Simulated voice calls, 1:1 and group: ringing, answering, people joining
  // and leaving, a path per person that depends on how they're reachable, a
  // bitrate that follows it, moving level meters.

  interface MockPart {
    person: Person;
    state: ParticipantState;
    muted: boolean;
    seed: number;
    /** Their camera is on (they turn it on a moment after we do). */
    camera: boolean;
    /** Their fake camera, while we can see it. */
    feed: { stop(): void } | null;
  }
  interface MockCall {
    info: CallInfo;
    activeAt: number | null;
    parts: MockPart[];
    /** Our camera is wanted on. */
    camera: boolean;
    /** Our fake camera (self-view). */
    local: { stop(): void } | null;
  }
  const calls = new Map<string, MockCall>();

  // --- video ------------------------------------------------------------------------
  //
  // A fake camera: an animated picture encoded to H.264 with the browser's own
  // WebCodecs VideoEncoder, handed out in the runtime's frame layout, so the
  // app decodes it exactly as it would real video. No VideoEncoder (or no
  // H.264 encoder): no pictures, the call UI still works.

  const videoHandlers = new Set<(frame: ArrayBuffer) => void>();

  function fakeCamera(source: "remote" | "local", peer: string, label: string, hue: number): { stop(): void } | null {
    const VE = (globalThis as { VideoEncoder?: typeof VideoEncoder }).VideoEncoder;
    if (!VE || typeof document === "undefined") return null;
    const [w, h, fps] = [640, 360, 15];
    const canvas = document.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    const g = canvas.getContext("2d");
    if (!g) return null;
    let seq = 0;
    let config: Uint8Array | null = null;
    let stopped = false;
    const enc = new VE({
      output: (chunk, meta) => {
        const desc = meta?.decoderConfig?.description;
        if (desc) config = new Uint8Array(desc instanceof ArrayBuffer ? desc : (desc as ArrayBufferView).buffer.slice(0));
        const data = new Uint8Array(chunk.byteLength);
        chunk.copyTo(data);
        const key = chunk.type === "key";
        const buf = encodeVideoFrame({
          source,
          peer,
          seq: seq++,
          capturedAt: chunk.timestamp / 1000,
          keyframe: key,
          width: w,
          height: h,
          config: key ? config : null,
          data,
        });
        for (const fn of [...videoHandlers]) fn(buf);
      },
      error: () => {
        stopped = true;
      },
    });
    try {
      enc.configure({ codec: "avc1.42e01f", width: w, height: h, bitrate: 600_000, framerate: fps, latencyMode: "realtime", avc: { format: "avc" } });
    } catch {
      return null;
    }
    let n = 0;
    const timer = setInterval(() => {
      if (stopped || enc.state !== "configured") return;
      const t = n / fps;
      const grad = g.createLinearGradient(0, 0, w, h);
      grad.addColorStop(0, `hsl(${hue} 45% ${30 + 6 * Math.sin(t)}%)`);
      grad.addColorStop(1, `hsl(${(hue + 40) % 360} 50% 18%)`);
      g.fillStyle = grad;
      g.fillRect(0, 0, w, h);
      // a "head and shoulders" that sways a little
      const x = w / 2 + 18 * Math.sin(t * 0.9);
      g.fillStyle = `hsl(${hue} 30% 78%)`;
      g.beginPath();
      g.arc(x, h * 0.42, 62, 0, Math.PI * 2);
      g.fill();
      g.beginPath();
      g.ellipse(x, h * 1.02, 150, 120, 0, Math.PI, 0);
      g.fill();
      if (label) {
        g.fillStyle = "rgba(255,255,255,0.85)";
        g.font = "600 22px system-ui, sans-serif";
        g.fillText(label, 20, h - 24);
      }
      const frame = new VideoFrame(canvas, { timestamp: Date.now() * 1000 });
      enc.encode(frame, { keyFrame: n % (fps * 4) === 0 });
      frame.close();
      n++;
    }, 1000 / fps);
    return {
      stop() {
        stopped = true;
        clearInterval(timer);
        try {
          enc.close();
        } catch {
          // already closed
        }
      },
    };
  }

  const slowPath = (path: CallInfo["path"]) => path === "bluetooth" || path === "ieee802154" || path === "mesh";

  /** Start or stop the fake cameras to match the call. */
  function syncVideo(c: MockCall) {
    const active = c.info.state === "active";
    const wantLocal = active && c.camera;
    if (wantLocal && !c.local) c.local = fakeCamera("local", meId, "", 205); // (mirrored: no text)
    if (!wantLocal && c.local) {
      c.local.stop();
      c.local = null;
    }
    c.parts.forEach((p, i) => {
      const joined = active && p.state === "joined";
      // they turn their camera on a moment after we do, and leave it on
      if (joined && c.camera && !p.camera) {
        later(1500 + i * 700, () => {
          if (c.info.state !== "active") return;
          p.camera = true;
          syncVideo(c);
        });
      }
      const want = joined && p.camera && !slowPath(pathFor(p.person));
      if (want && !p.feed) p.feed = fakeCamera("remote", p.person.id, p.person.name, (145 + i * 70) % 360);
      if (!want && p.feed) {
        p.feed.stop();
        p.feed = null;
      }
    });
  }

  /** Video with one person, as the runtime reports it. */
  function peerVideo(c: MockCall, p: MockPart): CallInfo["participants"][number]["video"] {
    const joined = c.info.state === "active" && p.state === "joined";
    const slow = slowPath(pathFor(p.person));
    const sending = joined && c.camera && !slow;
    const receiving = !!p.feed;
    return {
      sending,
      paused: joined && c.camera && slow,
      remoteCamera: joined && p.camera,
      remotePaused: joined && p.camera && slow,
      receiving,
      sendWidth: sending ? 640 : 0,
      sendHeight: sending ? 360 : 0,
      sendFps: sending ? 15 : 0,
      bitrate: sending ? 600_000 : 0,
      sentBitrate: sending ? 600_000 : 0,
      queueMs: 0,
      recvWidth: receiving ? 640 : 0,
      recvHeight: receiving ? 360 : 0,
      recvFps: receiving ? 15 : 0,
      latencyMs: receiving ? 38 : 0,
      framesSent: 0,
      framesReceived: 0,
      framesSkipped: 0,
      keyframesSent: 0,
      keyframeRequests: 0,
      encoder: "H.264 (WebCodecs)",
    };
  }

  function pathFor(p: Person | undefined): CallInfo["path"] {
    if (!p) return null;
    if (p.nearby) return "network";
    return p.name === "Tobias Wren" ? "bluetooth" : "peerWifi";
  }

  function bitrateFor(path: CallInfo["path"]): number {
    return path === "bluetooth" ? 12_000 : path === "relay" ? 24_000 : 32_000;
  }

  function rttFor(path: CallInfo["path"]): number {
    return path === "bluetooth" ? 48 : path === "relay" ? 70 : 4;
  }

  /** In it, or calling out: other calls get "busy". */
  function engaged(c: MockCall): boolean {
    const s = c.info.state;
    return s === "active" || s === "connecting" || (s === "ringing" && c.info.direction === "outgoing");
  }

  function snapshot(c: MockCall): CallInfo {
    const now = Date.now();
    const active = c.info.state === "active";
    const t = now / 1000;
    const voice = (seed: number) => Math.max(0, 0.45 + 0.35 * Math.sin(t * 3.1 + seed) * Math.sin(t * 1.7 + seed * 2));
    c.info.durationMs = c.activeAt ? (c.info.state === "ended" ? c.info.durationMs : now - c.activeAt) : 0;
    c.info.level = active && !c.info.muted ? voice(0) : 0;
    const rank = (s: ParticipantState) => (s === "joined" ? 0 : s === "connecting" ? 1 : s === "ringing" ? 2 : 3);
    c.info.participants = c.parts
      .map((p) => {
        const path = p.state === "joined" || p.state === "ringing" ? pathFor(p.person) : null;
        const level = active && p.state === "joined" && !p.muted ? voice(p.seed) : 0;
        return {
          id: p.person.id,
          name: p.person.name,
          state: p.state,
          muted: p.muted,
          level,
          speaking: level > 0.55,
          path,
          bitrate: active && p.state === "joined" ? bitrateFor(path) : 0,
          rttMs: active && p.state === "joined" ? rttFor(path) : 0,
          lossPct: 0,
          video: peerVideo(c, p),
        };
      })
      .sort((a, b) => rank(a.state) - rank(b.state) || a.name.localeCompare(b.name));
    const joined = c.info.participants.filter((p) => p.state === "joined");
    const inCall = active || (c.info.direction === "outgoing" && (c.info.state === "connecting" || c.info.state === "ringing"));
    c.info.joinedCount = joined.length + (inCall ? 1 : 0);
    const loudest = joined.filter((p) => p.speaking).sort((a, b) => b.level - a.level)[0];
    c.info.activeSpeaker = loudest?.id ?? null;
    c.info.remoteLevel = active ? Math.max(0, ...joined.map((p) => p.level)) : 0;
    c.info.remoteMuted = !c.info.group && (c.parts[0]?.muted ?? false);
    const main = c.info.group ? (joined[0] ?? null) : (c.info.participants[0] ?? null);
    c.info.path = main ? pathFor(people.get(main.id)) : null;
    c.info.bitrate = bitrateFor(c.info.path);
    const rtt = rttFor(c.info.path);
    c.info.stats = {
      ...c.info.stats,
      rttMs: active ? rtt : 0,
      jitterMs: active ? 2 : 0,
      bufferMs: active ? (c.info.path === "bluetooth" ? 80 : 40) : 0,
      latencyMs: active ? rtt / 2 + (c.info.path === "bluetooth" ? 80 : 40) + 55 : 0,
      framesSent: active ? Math.floor(c.info.durationMs / 20) : c.info.stats.framesSent,
      framesReceived: active ? Math.floor(c.info.durationMs / 20) : c.info.stats.framesReceived,
    };
    const first = c.parts.find((p) => p.person.id === joined[0]?.id) ?? (c.info.group ? null : c.parts[0]);
    const pv = first ? peerVideo(c, first) : null;
    c.info.video = {
      ...(pv ?? peerVideo(c, { person: people.get(c.info.peer) ?? c.parts[0]!.person, state: "left", muted: false, seed: 0, camera: false, feed: null })),
      camera: c.camera && c.info.state !== "ended" ? "on" : "off",
      error: null,
      source: "Simulated camera",
    };
    return structuredClone(c.info);
  }

  function callUpdate(c: MockCall) {
    emit({ type: "callUpdated", call: snapshot(c) });
  }

  function setCallState(c: MockCall, state: CallInfo["state"], end: CallEndReason | null = null) {
    if (c.info.state === "ended") return;
    c.info.state = state;
    syncVideo(c);
    if (state === "active" && !c.activeAt) {
      c.activeAt = Date.now();
      c.info.connectedAt = c.activeAt;
      tickCall(c);
    }
    if (state === "ended") {
      c.info.endReason = end;
      if (c.activeAt) c.info.durationMs = Date.now() - c.activeAt;
      later(10_000, () => calls.delete(c.info.id));
    }
    callUpdate(c);
  }

  /** Someone else's state in a call changed. */
  function setPart(c: MockCall, who: Person, state: ParticipantState) {
    const p = c.parts.find((x) => x.person.id === who.id);
    if (!p || c.info.state === "ended") return;
    p.state = state;
    syncVideo(c);
    const anyoneIn = c.parts.some((x) => x.state === "joined");
    const stillRinging = c.parts.some((x) => x.state === "ringing" || x.state === "connecting");
    const outgoing = c.info.direction === "outgoing";
    if (c.info.state === "active" && !anyoneIn) {
      setCallState(c, "ended", "remoteHungUp");
    } else if (outgoing && c.info.state !== "active" && state === "joined") {
      setCallState(c, "active");
    } else if (outgoing && c.info.state !== "active" && !anyoneIn && !stillRinging) {
      const any = (s: ParticipantState) => c.parts.some((x) => x.state === s);
      setCallState(c, "ended", any("declined") ? "remoteDeclined" : any("busy") ? "busy" : any("missed") ? "noAnswer" : "unavailable");
    } else if ((c.info.state === "joinable" || c.info.state === "ringing") && !outgoing && !anyoneIn) {
      setCallState(c, "ended", "missed");
    } else {
      callUpdate(c);
    }
  }

  function tickCall(c: MockCall) {
    later(100, () => {
      if (c.info.state !== "active") return;
      callUpdate(c);
      tickCall(c);
    });
  }

  /** A call in `conv`; `from` is who started it (null: you). */
  function newCall(conv: Conv, direction: CallInfo["direction"], from: Person | null): MockCall {
    const others = otherMembers(conv)
      .map((m) => people.get(m.id))
      .filter((p): p is Person => !!p);
    const group = others.length > 1;
    const peer = from ?? others[0]!;
    const c: MockCall = {
      activeAt: null,
      camera: false,
      local: null,
      parts: others.map((p, i) => ({
        person: p,
        state: direction === "outgoing" ? "ringing" : p === from ? "joined" : "ringing",
        muted: false,
        seed: 1.3 + i * 0.9,
        camera: false,
        feed: null,
      })),
      info: {
        id: randomHex(32),
        conversation: conv.id,
        group,
        title: group ? conv.title : null,
        peer: group && !from ? meId : peer.id,
        peerName: group && !from ? "You" : peer.name,
        direction,
        state: direction === "outgoing" ? "connecting" : "ringing",
        endReason: null,
        error: null,
        startedAt: Date.now(),
        connectedAt: null,
        durationMs: 0,
        participants: [],
        joinedCount: 0,
        activeSpeaker: null,
        path: null,
        bitrate: 32_000,
        muted: false,
        remoteMuted: false,
        level: 0,
        remoteLevel: 0,
        echoCancellation: true,
        stats: {
          rttMs: 0,
          lossPct: 0,
          jitterMs: 0,
          bufferMs: 0,
          latencyMs: 0,
          framesSent: 0,
          framesReceived: 0,
          framesLost: 0,
          framesLate: 0,
          transport: "datagram",
          audioDevice: "Voice processing (echo cancellation)",
          heardToneHz: null,
          measuredRoundTripMs: null,
        },
        video: {
          camera: "off",
          error: null,
          sending: false,
          paused: false,
          remoteCamera: false,
          remotePaused: false,
          receiving: false,
          sendWidth: 0,
          sendHeight: 0,
          sendFps: 0,
          bitrate: 0,
          sentBitrate: 0,
          queueMs: 0,
          recvWidth: 0,
          recvHeight: 0,
          recvFps: 0,
          latencyMs: 0,
          framesSent: 0,
          framesReceived: 0,
          framesSkipped: 0,
          keyframesSent: 0,
          keyframeRequests: 0,
          source: "Simulated camera",
          encoder: "H.264 (WebCodecs)",
        },
      },
    };
    calls.set(c.info.id, c);
    return c;
  }

  const liveCalls = () => [...calls.values()].filter((c) => c.info.state !== "ended");

  function getCall(id: string): MockCall {
    const c = calls.get(id);
    if (!c) throw "no such call";
    return c;
  }

  function startCall(conversation: string, video = false): CallInfo {
    const conv = getConv(conversation);
    if (conv.invitedBy) throw "accept this message request before calling";
    if (!conv.active) throw "you're no longer a member of this conversation";
    if (otherMembers(conv).length === 0) throw "there's nobody else in this conversation to call";
    const waiting = liveCalls().find(
      (c) =>
        c.info.direction === "incoming" &&
        c.info.conversation === conversation &&
        (c.info.state === "ringing" || c.info.state === "joinable"),
    );
    if (waiting) return acceptCall(waiting.info.id, video);
    if (liveCalls().some(engaged)) throw "You're already in a call.";
    const c = newCall(conv, "outgoing", null);
    c.camera = video;
    const reachable = c.parts.filter((p) => p.person.online || p.person.nearby);
    if (reachable.length === 0) {
      later(1800, () => {
        c.info.error = c.info.group
          ? "Nobody in the group can be reached right now"
          : `${c.parts[0]!.person.name} can't be reached right now`;
        for (const p of c.parts) p.state = "unavailable";
        setCallState(c, "ended", "unavailable");
      });
      return snapshot(c);
    }
    later(500, () => {
      for (const p of c.parts) if (!reachable.includes(p)) p.state = "unavailable";
      setCallState(c, "ringing");
    });
    // the first two who can be reached answer; anyone else lets it ring out
    reachable.forEach((p, i) => {
      if (i < 2) later(3200 + i * 1800, () => setPart(c, p.person, "joined"));
      else later(9000, () => setPart(c, p.person, "missed"));
    });
    // they occasionally mute for a moment
    later(9000, () => {
      const p = reachable[0]!;
      p.muted = true;
      later(2500, () => (p.muted = false));
    });
    return snapshot(c);
  }

  function acceptCall(id: string, video = false): CallInfo {
    const c = getCall(id);
    if (video) c.camera = true;
    if (c.info.direction !== "incoming" || !(c.info.state === "ringing" || c.info.state === "joinable")) {
      throw "This call isn't ringing any more.";
    }
    for (const other of liveCalls()) if (other !== c && engaged(other)) setCallState(other, "ended", "hungUp");
    setCallState(c, "connecting");
    later(400, () => setCallState(c, "active"));
    return snapshot(c);
  }

  /** Decline (or let ring out): a group call stays joinable while it goes on. */
  function declineCall(c: MockCall, missed = false) {
    if (c.info.group && c.info.direction === "incoming" && c.info.state === "ringing") {
      setCallState(c, "joinable");
    } else {
      const unanswered = c.info.state === "ringing" && c.info.direction === "incoming";
      setCallState(c, "ended", missed ? "missed" : unanswered ? "declined" : "hungUp");
    }
  }

  // --- ambient activity ------------------------------------------------------------

  if (opts.ambient) {
    const lena = person("Lena Brandt");
    later(9_000, () => {
      lena.nearby = true;
      emit({ type: "nearbyChanged" });
      emit({ type: "networkChanged" });
    });
    later(28_000, () => {
      hana.online = true;
      emit({ type: "contactsChanged" });
      emit({ type: "networkChanged" });
      for (const c of convs.values()) if (c.active && allOthersOnline(c)) advance(c, "delivered");
    });
    later(45_000, () => {
      const g = convs.get(hexFrom("conv:climb"));
      if (!g?.active) return;
      typingBurst(g, hana.id, 3000);
      later(3000, () => {
        receive(g, hana.id, "12:30 works. I'll bring snacks for the drive");
        advance(g, "read");
      });
    });
    // Ines calls you (once), unless you're already in a call
    later(40_000, () => {
      const conv = convs.get(hexFrom("conv:ines"));
      if (!conv?.active || liveCalls().some(engaged)) return;
      const c = newCall(conv, "incoming", ines);
      emit({ type: "callIncoming", call: snapshot(c) });
      later(30_000, () => {
        if (c.info.state === "ringing") declineCall(c, true);
      });
    });
    // Tobias calls the climbing group and Ines picks up. Unanswered, it
    // stays joinable while they talk; a few minutes later they hang up.
    later(100_000, () => {
      const g = convs.get(hexFrom("conv:climb"));
      if (!g?.active || liveCalls().some(engaged)) return;
      const c = newCall(g, "incoming", tobias);
      emit({ type: "callIncoming", call: snapshot(c) });
      later(2500, () => setPart(c, ines, "joined"));
      later(30_000, () => {
        setPart(c, hana, "missed");
        if (c.info.state === "ringing") declineCall(c, true);
      });
      later(180_000, () => {
        if (c.info.state === "active") return; // you're in it: they stay
        setPart(c, ines, "left");
        setPart(c, tobias, "left");
      });
    });
    later(75_000, () => {
      const id = randomHex(32);
      const c: Conv = {
        id,
        title: "Garden plot rota",
        members: [
          { id: ines.id, role: "admin" },
          { id: meId, role: "member" },
          { id: hana.id, role: "member" },
        ],
        messages: [],
        unread: 0,
        active: true,
        activity: ++clock,
        invitedBy: null,
        hidden: false,
      };
      convs.set(id, c);
      emit({ type: "conversationAdded", conversation: id });
      later(1200, () => receive(c, ines.id, "Made a group for the plot. Who can water on Tuesdays?"));
    });
  }

  // --- commands ----------------------------------------------------------------------

  function contactView(p: Person): Contact {
    return { id: p.id, name: p.name, nearby: p.nearby, online: p.online };
  }

  function requireContact(id: PeerId): Person {
    const p = people.get(id);
    if (!p || !p.contact) throw "You can only add people who are in your contacts";
    return p;
  }

  async function addNearby(id: PeerId): Promise<Contact> {
    const p = people.get(id);
    if (!p || !p.nearby) throw "That person is no longer on your network";
    await new Promise((r) => later(600, () => r(null)));
    if (!p.contact) {
      p.contact = true;
      p.online = true;
      emit({ type: "contactsChanged" });
      emit({ type: "nearbyChanged" });
      emit({ type: "networkChanged" });
    }
    return contactView(p);
  }

  async function fetchAttachment(blob: string): Promise<string> {
    const b = blobs.get(blob);
    if (!b) throw "Unknown attachment";
    if (!b.local) {
      const total = Math.max(b.size, 1);
      for (let i = 1; i <= 4; i++) {
        await new Promise((r) => later(250 + Math.random() * 150, () => r(null)));
        emit({ type: "transferProgress", direction: "download", id: blob, done: Math.round((total * i) / 4), total, rate: Math.round(total / 1.2) });
      }
      b.local = true;
      emit({ type: "blobReady", blob });
      for (const c of convs.values()) {
        if (c.messages.some((m) => m.attachments.includes(blob))) touch(c);
      }
    }
    return blobPath(b);
  }

  const handlersByCmd: { [C in Command]: (args: ArgsOf<C>) => ResultOf<C> | Promise<ResultOf<C>> } = {
    get_profile: () => ({ ...profile }),
    set_name: ({ name }) => {
      const n = name.trim();
      if (!n) throw "Name can't be empty";
      profile.name = n;
      for (const c of convs.values()) if (c.members.some((m) => m.id === meId)) emit({ type: "conversationUpdated", conversation: c.id });
      return { ...profile };
    },
    add_contact: ({ code }) => {
      const c = code.trim().toLowerCase();
      if (!/^myc1[a-z2-7]{40,}$/.test(c)) throw "That isn't a Mycel contact code. Codes start with myc1.";
      if (c === profile.contactCode) throw "That's your own contact code";
      let p = [...people.values()].find((x) => mockContactCode(x.id) === c);
      if (!p) {
        const id = hexFrom(`code:${c}`);
        p = { id, name: `Peer ${id.slice(0, 6)}`, contact: false, nearby: false, online: false };
        people.set(id, p);
      }
      if (!p.contact) {
        p.contact = true;
        emit({ type: "contactsChanged" });
        if (p.nearby) emit({ type: "nearbyChanged" });
      }
      return contactView(p);
    },
    add_nearby_contact: ({ id }) => addNearby(id),
    remove_contact: ({ id }) => {
      const p = people.get(id);
      if (p?.contact) {
        p.contact = false;
        emit({ type: "contactsChanged" });
        if (p.nearby) emit({ type: "nearbyChanged" });
      }
      return null;
    },
    list_contacts: () =>
      [...people.values()].filter((p) => p.contact).sort((a, b) => a.name.localeCompare(b.name)).map(contactView),
    list_nearby: (): NearbyPeer[] =>
      [...people.values()].filter((p) => p.nearby).map((p) => ({ id: p.id, name: p.name, isContact: p.contact })),
    restart_app: () => null,
    set_network_mode: ({ mode }): NetworkStatus => {
      nextMode = mode;
      emit({ type: "networkChanged" });
      return handlersByCmd.network_status({} as Record<string, never>) as NetworkStatus;
    },
    network_status: (): NetworkStatus => ({
      mode: opts.mode,
      nextMode,
      links: [
        { kind: "peerWifi", active: true, detail: null, peers: 1 },
        { kind: "bluetooth", active: true, detail: null, peers: 1 },
        { kind: "ethernet", label: "bridge0", active: true, detail: null, peers: 0 },
        { kind: "mesh", active: true, detail: "2 nearby, relaying for others", peers: 1 },
      ],
      peers: [...people.values()]
        .filter((p) => p.contact && (p.online || p.nearby))
        .map((p, i, all) => {
          // the last one is out of range, reached through the first
          const meshed = !p.nearby && all.length > 1 && i === all.length - 1;
          return {
            id: p.id,
            name: p.name,
            online: true,
            via: (p.nearby ? "network" : meshed ? "mesh" : i % 2 ? "bluetooth" : "peerWifi") as PathKind,
            available: (p.nearby ? ["network", "peerWifi", "bluetooth"] : meshed ? ["mesh"] : ["bluetooth"]) as PathKind[],
            mesh: meshed ? { via: all[0].id, viaName: all[0].name, hops: 2, gateway: false } : null,
          };
        }),
      onlinePeers: [...people.values()].filter((p) => p.contact && p.online).map((p) => p.id),
      nearbyPeers: [...people.values()].filter((p) => p.nearby).length,
      addresses: ["192.168.1.24:51820", "[fe80::1c2a:8ff:fe3d:91b2]:51820", "127.0.0.1:51820"],
    }),
    list_conversations: () =>
      [...convs.values()].filter((c) => !c.hidden).sort((a, b) => b.activity - a.activity).map(summary),
    get_conversation: ({ id }) => summary(getConv(id)),
    create_conversation: ({ title, members }) => {
      const t = title?.trim() || null;
      const ids = [...new Set(members)].filter((m) => m !== meId);
      if (ids.length === 0) throw "Pick at least one person";
      ids.forEach(requireContact);
      if (!t && ids.length === 1) {
        const existing = [...convs.values()].find((c) => c.active && isDirect(c) && c.members.some((m) => m.id === ids[0]));
        if (existing) return summary(existing);
      }
      const c: Conv = {
        id: randomHex(32),
        title: t,
        members: [{ id: meId, role: "admin" }, ...ids.map((id) => ({ id, role: (ids.length === 1 && !t ? "admin" : "member") as MemberRole }))],
        messages: [],
        unread: 0,
        active: true,
        activity: ++clock,
        invitedBy: null,
        hidden: false,
      };
      convs.set(c.id, c);
      emit({ type: "conversationAdded", conversation: c.id });
      return summary(c);
    },
    list_messages: ({ id, limit, before }) => {
      const c = getConv(id);
      let end = c.messages.length;
      if (before) {
        const i = c.messages.findIndex((m) => m.id === before);
        if (i >= 0) end = i;
      }
      const visible = c.messages.slice(0, end).filter((m) => !locallyHidden(c, m));
      const count = Math.min(limit ?? 200, 10_000);
      return visible.slice(Math.max(0, visible.length - count)).map((m) => msgView(c, m));
    },
    messages_around: ({ id, message, before, after }) => {
      const c = getConv(id);
      const at = c.messages.findIndex((m) => m.id === message);
      if (at < 0) throw "unknown message";
      const visible = (m: Msg) => !locallyHidden(c, m);
      const take = (n: number | null | undefined) => Math.min(n ?? 25, 10_000);
      const earlier = c.messages.slice(0, at).filter(visible);
      const later = c.messages.slice(at + 1).filter(visible);
      const b = take(before);
      const a = take(after);
      const anchor = visible(c.messages[at]!) ? [c.messages[at]!] : [];
      return {
        messages: [...earlier.slice(Math.max(0, earlier.length - b)), ...anchor, ...later.slice(0, a)].map((m) => msgView(c, m)),
        hasEarlier: earlier.length > b,
        hasLater: later.length > a,
      };
    },
    search_messages: ({ id, query, limit }) => {
      const c = getConv(id);
      const terms = query.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
      if (!terms.length) return [];
      return [...c.messages].reverse().filter((m) => !m.deleted && !locallyHidden(c, m))
        .filter((m) => {
          const content = [m.body, ...m.attachments.map((blob) => attachmentView(blob).name)].join(" ").toLocaleLowerCase();
          return terms.every((term) => content.includes(term));
        }).slice(0, Math.min(limit ?? 100, 1_000)).map((m) => msgView(c, m));
    },
    send_message: ({ id, body, replyTo, attachments }) => {
      const c = getConv(id);
      requireActive(c);
      if (myRole(c) === "readOnly") throw "You can read this conversation but not post in it";
      const text = body.trim();
      const paths = attachments ?? [];
      if (!text && paths.length === 0) throw "Message is empty";
      if (replyTo) getMsg(c, replyTo);
      const blobIds = paths.map((path) => {
        const file = uploads.get(path);
        if (file) return addBlob(file.name, file.type || guessMime(file.name), file.size, true, () => file);
        const name = basename(path);
        return addBlob(name, guessMime(name), 0, true, () => new Blob([`(mock) ${path}`], { type: "text/plain" }));
      });
      const m: Msg = {
        id: randomHex(32),
        author: meId,
        sentAt: Date.now(),
        body: text,
        replyTo: replyTo ?? null,
        edited: false,
        deleted: false,
        attachments: blobIds,
        reactions: [],
        delivery: "local",
      };
      c.messages.push(m);
      c.unread = 0;
      touch(c);
      progressDelivery(c, m.id);
      simulateReply(c, m);
      return msgView(c, m);
    },
    edit_message: ({ id, message, body }) => {
      const c = getConv(id);
      requireActive(c);
      const m = getMsg(c, message);
      if (m.author !== meId) throw "You can only edit your own messages";
      if (m.deleted) throw "That message was deleted";
      const text = body.trim();
      if (!text && m.attachments.length === 0) throw "Message is empty";
      if (text !== m.body) {
        m.body = text;
        m.edited = true;
        touch(c);
      }
      return null;
    },
    delete_message: ({ id, message }) => {
      const c = getConv(id);
      requireActive(c);
      const m = getMsg(c, message);
      if (m.author !== meId) throw "You can only delete your own messages";
      if (!m.deleted) {
        m.deleted = true;
        m.body = "";
        m.attachments = [];
        m.reactions = [];
        touch(c);
      }
      return null;
    },
    delete_message_local: ({ id, message }) => {
      const c = getConv(id);
      getMsg(c, message);
      const hidden = hiddenMessages.get(id) ?? new Set<string>();
      hidden.add(message);
      hiddenMessages.set(id, hidden);
      emit({ type: "conversationUpdated", conversation: id });
      return null;
    },
    restore_message_local: ({ id, message }) => {
      const c = getConv(id);
      getMsg(c, message);
      hiddenMessages.get(id)?.delete(message);
      emit({ type: "conversationUpdated", conversation: id });
      return null;
    },
    toggle_reaction: ({ id, message, emoji }) => {
      const c = getConv(id);
      requireActive(c);
      const m = getMsg(c, message);
      if (m.deleted) throw "That message was deleted";
      const r = m.reactions.find((x) => x.emoji === emoji);
      if (!r) m.reactions.push({ emoji, by: [meId] });
      else if (r.by.includes(meId)) {
        r.by = r.by.filter((p) => p !== meId);
        if (r.by.length === 0) m.reactions = m.reactions.filter((x) => x !== r);
      } else r.by.push(meId);
      emit({ type: "conversationUpdated", conversation: c.id });
      return null;
    },
    mark_read: ({ id }) => {
      const c = getConv(id);
      // A read receipt would tell a stranger you've seen their request.
      if (c.invitedBy) throw "accept this message request before replying";
      if (c.unread !== 0) {
        c.unread = 0;
        emit({ type: "conversationUpdated", conversation: c.id });
      }
      return null;
    },
    set_typing: ({ id }) => {
      if (getConv(id).invitedBy) throw "accept this message request before replying";
      return null;
    },
    add_members: ({ id, members }) => {
      const c = getConv(id);
      requireAdmin(c);
      let added = false;
      for (const m of members) {
        requireContact(m);
        if (!c.members.some((x) => x.id === m)) {
          c.members.push({ id: m, role: "member" });
          added = true;
        }
      }
      // Adding a third person turns a direct chat into a group (see isDirect).
      if (added) touch(c);
      return null;
    },
    remove_member: ({ id, member }) => {
      const c = getConv(id);
      requireActive(c);
      if (member !== meId) requireAdmin(c);
      const before = c.members.length;
      c.members = c.members.filter((m) => m.id !== member);
      if (c.members.length !== before) {
        if (member === meId) c.active = false;
        touch(c);
      }
      return null;
    },
    add_keeper: ({ id, keeper }) => {
      const c = getConv(id);
      requireAdmin(c);
      requireContact(keeper);
      const existing = c.members.find((m) => m.id === keeper);
      if (existing) {
        if (existing.role === "keeper") return null;
        throw "That person is already a member";
      }
      c.members.push({ id: keeper, role: "keeper" });
      touch(c);
      return null;
    },
    rename_conversation: ({ id, title }) => {
      const c = getConv(id);
      requireAdmin(c);
      const t = title.trim();
      if (!t) throw "Title can't be empty";
      c.title = t;
      touch(c);
      return null;
    },
    fetch_attachment: ({ blob }) => fetchAttachment(blob),
    accept_request: ({ id }) => {
      const c = getConv(id);
      const inviter = c.invitedBy;
      if (!inviter) throw "not a message request";
      c.invitedBy = null;
      const p = people.get(inviter);
      if (p && !p.contact) {
        p.contact = true;
        p.online = true;
        emit({ type: "contactsChanged" });
        emit({ type: "nearbyChanged" });
        emit({ type: "networkChanged" });
      }
      touch(c);
      // They see your introduction and say hello back.
      if (opts.replies && p) {
        later(1500, () => {
          typingBurst(c, inviter, 2000);
          later(2000, () => receive(c, inviter, "Thanks for accepting! No rush on the brakes."));
        });
      }
      return summary(c);
    },
    start_call: ({ conversation, video }) => startCall(conversation, video ?? false),
    accept_call: ({ call, video }) => acceptCall(call, video ?? false),
    set_camera: ({ call, on }) => {
      const c = getCall(call);
      if (c.info.state === "ended") throw "This call already ended.";
      c.camera = on;
      syncVideo(c);
      callUpdate(c);
      return snapshot(c);
    },
    video_keyframe: () => null,
    decline_call: ({ call }) => {
      declineCall(getCall(call));
      return null;
    },
    end_call: ({ call }) => {
      const c = getCall(call);
      if (c.info.direction === "incoming" && c.info.state === "ringing") declineCall(c);
      else setCallState(c, "ended", c.info.state === "joinable" ? "declined" : "hungUp");
      return null;
    },
    set_muted: ({ call, muted }) => {
      const c = getCall(call);
      c.info.muted = muted;
      callUpdate(c);
      return snapshot(c);
    },
    call_status: () => [...calls.values()].map(snapshot).sort((a, b) => b.startedAt - a.startedAt),
    decline_request: ({ id, block }) => {
      const c = getConv(id);
      const inviter = c.invitedBy;
      if (!inviter) throw "not a message request";
      c.invitedBy = null;
      c.active = false;
      c.hidden = true;
      c.members = c.members.filter((m) => m.id !== meId);
      if (block) blocked.add(inviter);
      emit({ type: "conversationUpdated", conversation: c.id });
      return null;
    },
  };

  // --- file host ------------------------------------------------------------------------

  let uploadSeq = 0;
  const files: FileHost = {
    pick() {
      return new Promise<string[]>((resolve) => {
        if (typeof document === "undefined") return resolve([]);
        const input = document.createElement("input");
        input.type = "file";
        input.multiple = true;
        input.style.display = "none";
        let settled = false;
        const done = (paths: string[]) => {
          if (settled) return;
          settled = true;
          input.remove();
          resolve(paths);
        };
        input.addEventListener("change", () => {
          const paths = Array.from(input.files ?? []).map((f) => {
            const path = `mock://upload/${++uploadSeq}/${encodeURIComponent(f.name)}`;
            uploads.set(path, f);
            return path;
          });
          done(paths);
        });
        input.addEventListener("cancel", () => done([]));
        document.body.appendChild(input);
        input.click();
      });
    },
    url(path) {
      const cached = objectUrls.get(path);
      if (cached) return cached;
      let blob: Blob | undefined = uploads.get(path);
      const m = /^mock:\/\/blob\/([0-9a-f]+)\//.exec(path);
      if (!blob && m) blob = blobs.get(m[1]!)?.make();
      if (!blob || typeof URL === "undefined" || !URL.createObjectURL) return path;
      const url = URL.createObjectURL(blob);
      objectUrls.set(path, url);
      return url;
    },
    async open(path) {
      if (typeof window !== "undefined") window.open(files.url(path), "_blank", "noopener");
    },
    async stage(list) {
      return list.map((f) => {
        const path = `mock://upload/${++uploadSeq}/${encodeURIComponent(f.name || "pasted")}`;
        uploads.set(path, f);
        return path;
      });
    },
  };

  // --- transport -----------------------------------------------------------------------

  return {
    kind: "mock",
    files,
    async invoke<C extends Command>(cmd: C, args: ArgsOf<C>): Promise<ResultOf<C>> {
      const [lo, hi] = opts.latency;
      await new Promise((r) => later(lo + Math.random() * (hi - lo), () => r(null)));
      const handler = handlersByCmd[cmd] as ((a: ArgsOf<C>) => ResultOf<C> | Promise<ResultOf<C>>) | undefined;
      if (!handler) throw `Unknown command: ${String(cmd)}`;
      // Errors are thrown as plain strings, the way Tauri rejects.
      const result = await handler((args ?? {}) as ArgsOf<C>);
      return structuredClone(result);
    },
    listen(handler) {
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
    video(handler) {
      videoHandlers.add(handler);
      return () => videoHandlers.delete(handler);
    },
    dispose() {
      for (const c of calls.values()) {
        c.local?.stop();
        for (const p of c.parts) p.feed?.stop();
      }
      videoHandlers.clear();
      for (const t of timers) clearTimeout(t);
      timers.clear();
      handlers.clear();
      for (const url of objectUrls.values()) URL.revokeObjectURL(url);
    },
  };
}
