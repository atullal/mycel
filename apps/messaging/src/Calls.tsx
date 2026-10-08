import { useEffect, useState } from "react";
import { useMycel } from "@mycel/sdk/react";
import type { CallInfo, Participant, ParticipantState, PathKind } from "@mycel/sdk";
import { Avatar, Icon, errorText } from "./ui.tsx";

// Voice calls in the Messaging app: the incoming-call sheet, the in-call bar,
// the group call's people and the "join call" banner, and the bits they
// share. Audio itself runs in the Mycel runtime; this is only the remote
// control.

export const PATH_LABEL: Record<PathKind, string> = {
  network: "Same network",
  peerWifi: "Peer-to-peer Wi-Fi",
  bluetooth: "Bluetooth",
  relay: "Internet relay",
  wifiDirect: "Wi-Fi Direct",
  uwb: "UWB",
  ieee802154: "Thread / 802.15.4",
  ethernet: "Cable",
  other: "Other link",
};

/** How a path reads after "via". */
export const VIA_LABEL: Record<PathKind, string> = {
  network: "your network",
  peerWifi: "Peer-to-peer Wi-Fi",
  bluetooth: "Bluetooth",
  relay: "an internet relay",
  wifiDirect: "Wi-Fi Direct",
  uwb: "UWB",
  ieee802154: "Thread / 802.15.4",
  ethernet: "a cable",
  other: "another link",
};

export function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}

/**
 * Calls the user should see: not the half of a simultaneous call that merged
 * away, nor a group call that ended while you could only have joined it.
 */
export function visibleCalls(calls: CallInfo[]): CallInfo[] {
  return calls.filter(
    (c) => c.endReason !== "replaced" && !(c.group && c.state === "ended" && !c.connectedAt && c.direction === "incoming"),
  );
}

/** You're in it, or on your way in (not: a group call you may join). */
export function isLive(c: CallInfo): boolean {
  return c.state !== "ended" && c.state !== "joinable";
}

/** What to call a call: the person, or the group. */
export function callTitle(c: CallInfo): string {
  return c.group ? c.title || "Group call" : c.peerName;
}

export function firstName(name: string): string {
  return name.split(" ")[0] || name;
}

function endedText(c: CallInfo): string {
  const first = firstName(c.peerName);
  switch (c.endReason) {
    case "remoteDeclined":
      return c.group ? "Nobody joined" : `${first} declined`;
    case "busy":
      return c.group ? "Everyone's on another call" : `${first} is on another call`;
    case "unavailable":
      return c.group ? "Nobody in the group can be reached right now" : `${first} can't be reached right now`;
    case "noAnswer":
      return "No answer";
    case "full":
      return "The call is full (8 people at most)";
    case "missed":
      return "Missed call";
    case "declined":
      return "Declined";
    case "connectionLost":
      return "Call dropped: the connection was lost";
    case "micDenied":
      return "Microphone not allowed";
    case "failed":
      return c.error ? `Call failed: ${c.error}` : "Call failed";
    default:
      return c.durationMs > 0 ? `Call ended · ${formatDuration(c.durationMs)}` : "Call ended";
  }
}

function statusText(c: CallInfo): string {
  if (c.state === "ended") return endedText(c);
  if (c.state === "active") return formatDuration(c.durationMs);
  if (c.direction === "outgoing") return c.state === "ringing" ? "Ringing…" : "Calling…";
  return c.group ? "Joining…" : "Connecting…";
}

/** "3 in call" (you included when you're in it). */
export function inCallText(c: CallInfo): string {
  return `${c.joinedCount} in call`;
}

/** Five-bar level meter (0..1). */
export function LevelMeter({ level, label, muted }: { level: number; label: string; muted?: boolean }) {
  const lit = muted ? 0 : Math.round(Math.min(1, Math.max(0, level)) * 5);
  return (
    <span className={`mx-meter${muted ? " is-muted" : ""}`} role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={5} aria-valuenow={lit} title={label}>
      {[0, 1, 2, 3, 4].map((i) => (
        <i key={i} className={i < lit ? "is-lit" : undefined} />
      ))}
    </span>
  );
}

/** Someone is calling: Accept / Decline, over whatever conversation is open. */
export function IncomingCall({ call, onAnswered }: { call: CallInfo; onAnswered: (conversation: string) => void }) {
  const mycel = useMycel();
  const [busy, setBusy] = useState<"accept" | "decline" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const answer = async () => {
    setBusy("accept");
    setError(null);
    try {
      await mycel.calls.accept(call.id);
      onAnswered(call.conversation);
    } catch (e) {
      setError(errorText(e));
      setBusy(null);
    }
  };
  const decline = async () => {
    setBusy("decline");
    try {
      await mycel.calls.decline(call.id);
    } catch {
      setBusy(null);
    }
  };

  return (
    <div className="mx-incoming" role="alertdialog" aria-label={`Incoming call from ${call.peerName}`} aria-describedby={`mx-incoming-${call.id}`}>
      <span className="mx-incoming-avatar">
        <Avatar id={call.peer} name={call.peerName} size={48} />
      </span>
      <div className="mx-incoming-text" id={`mx-incoming-${call.id}`}>
        <strong>{call.peerName}</strong>
        {call.group ? (
          <span>
            Group call · {callTitle(call)}
            {call.joinedCount > 1 ? ` · ${inCallText(call)}` : ""}
          </span>
        ) : (
          <span>
            Voice call
            {call.path ? ` · via ${VIA_LABEL[call.path]}` : ""}
          </span>
        )}
        {error && (
          <span className="mx-incoming-error" role="alert">
            {error}
          </span>
        )}
      </div>
      <div className="mx-incoming-actions">
        <button className="mx-call-round is-decline" onClick={() => void decline()} disabled={!!busy} aria-label="Decline" title="Decline">
          <Icon.HangUp size={22} />
        </button>
        <button className="mx-call-round is-accept" onClick={() => void answer()} disabled={!!busy} aria-label="Accept" title="Accept">
          <Icon.Phone size={21} />
        </button>
      </div>
    </div>
  );
}

/** The call in progress (or just ended): duration, path, meters, mute, hang up. */
export function CallBar({
  call,
  onOpen,
  error,
  onDismissError,
}: {
  call: CallInfo | null;
  onOpen: (conversation: string) => void;
  error: string | null;
  onDismissError: () => void;
}) {
  const mycel = useMycel();
  const [pending, setPending] = useState(false);

  // a fresh call clears the previous one's pending state
  useEffect(() => setPending(false), [call?.id]);

  if (!call) {
    if (!error) return null;
    return (
      <div className="mx-callbar is-error" role="alert">
        <Icon.Phone size={16} />
        <span className="mx-callbar-error">{error}</span>
        <button className="mx-icon-btn" onClick={onDismissError} aria-label="Dismiss">
          <Icon.X size={16} />
        </button>
      </div>
    );
  }

  const live = isLive(call);
  const active = call.state === "active";
  const toggleMute = async () => {
    setPending(true);
    try {
      await mycel.calls.setMuted(call.id, !call.muted);
    } finally {
      setPending(false);
    }
  };
  const hangUp = () => void mycel.calls.end(call.id).catch(() => {});

  return (
    <div className={`mx-callbar is-${call.state}`} role="region" aria-label={`Call: ${callTitle(call)}`}>
      <button className="mx-callbar-who" onClick={() => onOpen(call.conversation)} title="Open the conversation">
        <span className={`mx-call-dot${active ? " is-live" : ""}`} aria-hidden="true" />
        <span className="mx-callbar-name">{callTitle(call)}</span>
        <span className="mx-callbar-status" aria-live="polite">
          {statusText(call)}
        </span>
      </button>
      {live && call.group && (
        <span className="mx-callbar-path">
          {inCallText(call)}
          {active && speakerName(call) && <span className="mx-callbar-rate"> · {speakerName(call)} is talking</span>}
        </span>
      )}
      {live && !call.group && (
        <span className="mx-callbar-path">
          {call.path ? `via ${VIA_LABEL[call.path]}` : "Finding a path…"}
          {active && call.bitrate > 0 && <span className="mx-callbar-rate"> · {Math.round(call.bitrate / 1000)} kbps</span>}
          {active && call.remoteMuted && <span className="mx-callbar-rate"> · {firstName(call.peerName)} is muted</span>}
        </span>
      )}
      {active && !call.echoCancellation && (
        <span className="mx-callbar-hint" title="This device has no echo cancellation">
          Use headphones to avoid echo
        </span>
      )}
      {active && (
        <span className="mx-callbar-meters">
          <span className="mx-meter-label">You</span>
          <LevelMeter level={call.level} label="Your microphone" muted={call.muted} />
          <span className="mx-meter-label">{call.group ? "Everyone" : firstName(call.peerName)}</span>
          <LevelMeter
            level={call.remoteLevel}
            label={call.group ? "Everyone else" : `${call.peerName}'s voice`}
            muted={!call.group && call.remoteMuted}
          />
        </span>
      )}
      {live && (
        <span className="mx-callbar-actions">
          {active && (
            <button
              className={`mx-icon-btn${call.muted ? " is-on" : ""}`}
              onClick={() => void toggleMute()}
              disabled={pending}
              aria-pressed={call.muted}
              aria-label={call.muted ? "Unmute" : "Mute"}
              title={call.muted ? "Unmute" : "Mute"}
            >
              {call.muted ? <Icon.MicOff /> : <Icon.Mic />}
            </button>
          )}
          <button
            className="mx-call-round is-decline is-small"
            onClick={hangUp}
            aria-label={active ? (call.group ? "Leave call" : "Hang up") : "Cancel call"}
            title={active ? (call.group ? "Leave (the call goes on for the others)" : "Hang up") : "Cancel"}
          >
            <Icon.HangUp size={18} />
          </button>
        </span>
      )}
    </div>
  );
}

function speakerName(c: CallInfo): string | null {
  const p = c.participants.find((x) => x.id === c.activeSpeaker);
  return p ? firstName(p.name) : null;
}

const STATE_LABEL: Record<ParticipantState, string> = {
  ringing: "Ringing…",
  connecting: "Connecting…",
  joined: "In the call",
  declined: "Declined",
  missed: "Didn't answer",
  busy: "On another call",
  unavailable: "Can't be reached",
  left: "Left",
};

function participantDetail(p: Participant): string {
  if (p.state !== "joined") return STATE_LABEL[p.state];
  if (!p.path) return "Connecting…";
  return p.bitrate > 0 ? `${PATH_LABEL[p.path]} · ${Math.round(p.bitrate / 1000)} kbps` : PATH_LABEL[p.path];
}

/** One person in a group call: avatar with a ring that grows as they talk. */
function ParticipantTile({
  id,
  name,
  level,
  speaking,
  muted,
  state,
  detail,
}: {
  id: string;
  name: string;
  level: number;
  speaking: boolean;
  muted: boolean;
  state: ParticipantState | "you";
  detail: string;
}) {
  const away = state !== "joined" && state !== "you";
  const pending = state === "ringing" || state === "connecting";
  const ring = muted || away ? 0 : Math.min(1, Math.max(0, level));
  return (
    <li
      className={`mx-gcall-tile${speaking ? " is-speaking" : ""}${away && !pending ? " is-away" : ""}${pending ? " is-pending" : ""}`}
      title={`${name}: ${detail}${muted ? " (muted)" : ""}`}
    >
      <span className="mx-gcall-avatar" style={{ ["--lvl" as string]: ring.toFixed(2) }}>
        <Avatar id={id} name={name} size={44} />
        {muted && (
          <span className="mx-gcall-muted" aria-label="Muted">
            <Icon.MicOff size={12} />
          </span>
        )}
      </span>
      <span className="mx-gcall-name">{name}</span>
      <span className="mx-gcall-detail">{detail}</span>
    </li>
  );
}

/** Who's in a group call you're in: everyone's tile, level rings, path and mute. */
export function GroupCallPanel({ call, me }: { call: CallInfo; me: { id: string; name: string } }) {
  return (
    <section className="mx-gcall" aria-label={`People in the call (${inCallText(call)})`}>
      <ul>
        <ParticipantTile
          id={me.id}
          name={me.name}
          level={call.level}
          speaking={!call.muted && call.level > 0.55}
          muted={call.muted}
          state="you"
          detail={call.muted ? "Muted" : "You"}
        />
        {call.participants.map((p) => (
          <ParticipantTile
            key={p.id}
            id={p.id}
            name={p.name}
            level={p.level}
            speaking={p.speaking}
            muted={p.muted && p.state === "joined"}
            state={p.state}
            detail={participantDetail(p)}
          />
        ))}
      </ul>
    </section>
  );
}

/** A group call is going on in this conversation without you: join it. */
export function JoinBanner({ call }: { call: CallInfo }) {
  const mycel = useMycel();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inIt = call.participants.filter((p) => p.state === "joined");
  const names = inIt.map((p) => firstName(p.name));
  const who =
    names.length === 0
      ? ""
      : names.length <= 2
        ? names.join(" and ")
        : `${names.slice(0, 2).join(", ")} and ${names.length - 2} more`;
  const join = async () => {
    setBusy(true);
    setError(null);
    try {
      await mycel.calls.join(call.id);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <div className="mx-join" role="region" aria-label="Group call in progress">
      <span className="mx-call-dot is-live" aria-hidden="true" />
      <span className="mx-join-faces" aria-hidden="true">
        {inIt.slice(0, 3).map((p) => (
          <Avatar key={p.id} id={p.id} name={p.name} size={24} />
        ))}
      </span>
      <span className="mx-join-text">
        <strong>Group call · {inCallText(call)}</strong>
        <span className={error ? "is-error" : undefined}>
          {error ?? (who ? `${who} ${inIt.length === 1 ? "is" : "are"} talking` : "Going on now")}
        </span>
      </span>
      <button className="mx-btn mx-btn-primary mx-join-btn" onClick={() => void join()} disabled={busy}>
        <Icon.Phone size={15} />
        {busy ? "Joining…" : "Join call"}
      </button>
    </div>
  );
}
