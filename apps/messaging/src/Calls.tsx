import { useEffect, useRef, useState } from "react";
import { useMycel, useVideoCanvas } from "@mycel/sdk/react";
import type { CallInfo, PathKind } from "@mycel/sdk";
import { Avatar, Icon, errorText } from "./ui.tsx";

// Calls in the Messaging app: the incoming-call sheet, the in-call bar, the
// video stage and the bits they share. Audio and video capture run in the
// Mycel runtime; the webview only decodes and shows the video it's handed.

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

  const answer = async (video: boolean) => {
    setBusy("accept");
    setError(null);
    try {
      await mycel.calls.accept(call.id, { video });
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
          {call.video.remoteCamera ? "Video call" : "Call"}
          {call.path ? ` · via ${VIA_LABEL[call.path]}` : ""}
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
        <button className="mx-call-round is-accept is-video" onClick={() => void answer(true)} disabled={!!busy} aria-label="Accept with video" title="Accept with video">
          <Icon.Video size={21} />
        </button>
        <button className="mx-call-round is-accept" onClick={() => void answer(false)} disabled={!!busy} aria-label="Accept" title="Accept (voice)">
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
  const cameraOn = call.video.camera === "on" || call.video.camera === "starting";
  const toggleCamera = async () => {
    setPending(true);
    try {
      await mycel.calls.setCamera(call.id, !cameraOn);
    } catch {
      // `video.error` says why (shown below)
    } finally {
      setPending(false);
    }
  };
  const cameraProblem = call.video.camera === "denied" || call.video.camera === "failed" ? call.video.error : null;

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
          {call.path ? `via ${VIA_LABEL[call.path]}` : "Finding a path…"}
          {active && call.bitrate > 0 && <span className="mx-callbar-rate"> · {Math.round(call.bitrate / 1000)} kbps</span>}
          {active && call.remoteMuted && <span className="mx-callbar-rate"> · {call.peerName.split(" ")[0]} is muted</span>}
        </span>
      )}
      {live && cameraProblem && (
        <span className="mx-callbar-hint is-error" role="alert">
          {cameraProblem}
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
          <span className="mx-meter-label">{call.peerName.split(" ")[0]}</span>
          <LevelMeter level={call.remoteLevel} label={`${call.peerName}'s voice`} muted={call.remoteMuted} />
        </span>
      )}
      {live && (
        <span className="mx-callbar-actions">
          <button
            className={`mx-icon-btn${cameraOn ? " is-on" : ""}`}
            onClick={() => void toggleCamera()}
            disabled={pending}
            aria-pressed={cameraOn}
            aria-label={cameraOn ? "Turn camera off" : "Turn camera on"}
            title={cameraOn ? "Turn camera off" : "Turn camera on"}
          >
            {cameraOn ? <Icon.Video /> : <Icon.VideoOff />}
          </button>
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

/** The call has video in it: ours, theirs, or both. */
export function hasVideo(c: CallInfo | null): boolean {
  if (!c || !isLive(c)) return false;
  const v = c.video;
  return v.camera === "on" || v.camera === "starting" || v.remoteCamera;
}

/**
 * The video of a call: their picture large, ours small in the corner
 * (mirrored, as a mirror would show it), and what's happening when there's
 * no picture: camera off, video paused on a slow connection, connecting.
 */
export function VideoStage({ call }: { call: CallInfo }) {
  const remote = useRef<HTMLCanvasElement>(null);
  const self = useRef<HTMLCanvasElement>(null);
  const v = call.video;
  const live = call.state === "active";
  const them = useVideoCanvas(remote, { call: live ? call.id : null, source: "remote", peer: call.peer });
  const me = useVideoCanvas(self, { call: live ? call.id : null, source: "local" });
  const first = call.peerName.split(" ")[0] || call.peerName;
  const ourCamera = v.camera === "on" || v.camera === "starting";

  let note: string | null = null;
  if (!them.supported) note = "Video can't be shown in this window (it needs WebCodecs: Safari 16.4 or later).";
  else if (!live) note = call.direction === "outgoing" ? "Calling…" : "Connecting…";
  else if (!v.remoteCamera) note = `${first}'s camera is off`;
  else if (v.remotePaused) note = "Video paused: slow connection";
  else if (!them.picture) note = "Connecting video…";

  return (
    <section className="mx-stage" aria-label={`Video call with ${call.peerName}`}>
      <canvas ref={remote} className={`mx-stage-remote${them.picture && !note ? " is-on" : ""}`} aria-label={`${call.peerName}'s video`} />
      {note && (
        <div className="mx-stage-note">
          <Avatar id={call.peer} name={call.peerName} size={64} />
          <span>{note}</span>
        </div>
      )}
      {/* always mounted, so the decoder attaches once; hidden with the camera off */}
      <div className={`mx-stage-self${me.picture ? " is-on" : ""}${ourCamera ? "" : " is-hidden"}`} aria-hidden={!ourCamera}>
        <canvas ref={self} aria-label="Your video" />
        {v.paused && <span className="mx-stage-self-note">Your video is paused: slow connection</span>}
        {!v.paused && !me.picture && <span className="mx-stage-self-note">Starting camera…</span>}
      </div>
      {live && them.picture && !note && v.recvWidth > 0 && (
        <span className="mx-stage-stats" title="What you receive">
          {v.recvHeight}p · {Math.round(v.recvFps)} fps
          {v.latencyMs > 0 ? ` · ${v.latencyMs} ms` : ""}
        </span>
      )}
    </section>
  );
}
