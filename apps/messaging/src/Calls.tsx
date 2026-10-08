import { useEffect, useState } from "react";
import { useMycel } from "@mycel/sdk/react";
import type { CallInfo, PathKind } from "@mycel/sdk";
import { Avatar, Icon, errorText } from "./ui.tsx";

// Voice calls in the Messaging app: the incoming-call sheet, the in-call bar
// and the bits they share. Audio itself runs in the Mycel runtime; this is
// only the remote control.

export const PATH_LABEL: Record<PathKind, string> = {
  network: "Same network",
  peerWifi: "Peer-to-peer Wi-Fi",
  bluetooth: "Bluetooth",
  relay: "Internet relay",
};

export function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}

/** Calls the user should see: not the half of a simultaneous call that merged away. */
export function visibleCalls(calls: CallInfo[]): CallInfo[] {
  return calls.filter((c) => c.endReason !== "replaced");
}

export function isLive(c: CallInfo): boolean {
  return c.state !== "ended";
}

function endedText(c: CallInfo): string {
  const first = c.peerName.split(" ")[0] || c.peerName;
  switch (c.endReason) {
    case "remoteDeclined":
      return `${first} declined`;
    case "busy":
      return `${first} is on another call`;
    case "unavailable":
      return `${first} can't be reached right now`;
    case "noAnswer":
      return "No answer";
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
  return "Connecting…";
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
        <span>
          Voice call
          {call.path ? ` · via ${PATH_LABEL[call.path]}` : ""}
        </span>
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
    <div className={`mx-callbar is-${call.state}`} role="region" aria-label={`Call with ${call.peerName}`}>
      <button className="mx-callbar-who" onClick={() => onOpen(call.conversation)} title="Open the conversation">
        <span className={`mx-call-dot${active ? " is-live" : ""}`} aria-hidden="true" />
        <span className="mx-callbar-name">{call.peerName}</span>
        <span className="mx-callbar-status" aria-live="polite">
          {statusText(call)}
        </span>
      </button>
      {live && (
        <span className="mx-callbar-path">
          {call.path ? `via ${PATH_LABEL[call.path]}` : "Finding a path…"}
          {active && call.bitrate > 0 && <span className="mx-callbar-rate"> · {Math.round(call.bitrate / 1000)} kbps</span>}
          {active && call.remoteMuted && <span className="mx-callbar-rate"> · {call.peerName.split(" ")[0]} is muted</span>}
        </span>
      )}
      {active && !call.echoCancellation && (
        <span className="mx-callbar-hint" title="This device has no echo cancellation">
          Use headphones to avoid echo
        </span>
      )}
      {active && (
        <span className="mx-callbar-meters">
          <LevelMeter level={call.level} label="Your microphone" muted={call.muted} />
          <LevelMeter level={call.remoteLevel} label={`${call.peerName}'s voice`} muted={call.remoteMuted} />
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
          <button className="mx-call-round is-decline is-small" onClick={hangUp} aria-label={active ? "Hang up" : "Cancel call"} title={active ? "Hang up" : "Cancel"}>
            <Icon.HangUp size={18} />
          </button>
        </span>
      )}
    </div>
  );
}
