import { useEffect, useRef, useState } from "react";
import { useMycel, useVideoCanvas } from "@mycel/sdk/react";
import type { CallInfo, Participant, ParticipantState, PathKind } from "@mycel/sdk";
import { Avatar, Icon, errorText } from "./ui.tsx";

// Calls in the Messaging app: the incoming-call sheet, the in-call bar, the
// group call's people (with their video) and the "join call" banner, the
// 1:1 video stage, and the bits they share. Audio and video capture run in
// the Mycel runtime; the webview only decodes and shows the video.

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
        {call.group ? (
          <span>
            Group call · {callTitle(call)}
            {call.joinedCount > 1 ? ` · ${inCallText(call)}` : ""}
          </span>
        ) : (
          <span>
            {call.video.remoteCamera ? "Video call" : "Call"}
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
        <button className="mx-call-round is-accept" onClick={() => void answer(true)} disabled={!!busy} aria-label="Accept with video" title="Accept with video">
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

/** One person's video in a tile (theirs, or ours mirrored); hidden until a picture is up. */
function TileVideo({ call, peer, local }: { call: CallInfo; peer: string; local: boolean }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const live = call.state === "active";
  const { picture } = useVideoCanvas(canvas, { call: live ? call.id : null, source: local ? "local" : "remote", peer });
  return <canvas ref={canvas} className={`mx-gcall-video${local ? " is-self" : ""}${picture ? " is-on" : ""}`} aria-label={local ? "Your video" : "Video"} />;
}

/** One person in a group call: avatar with a ring that grows as they talk, or their video. */
function ParticipantTile({
  id,
  name,
  level,
  speaking,
  muted,
  state,
  detail,
  video,
}: {
  id: string;
  name: string;
  level: number;
  speaking: boolean;
  muted: boolean;
  state: ParticipantState | "you";
  detail: string;
  /** Show their (or our) video in the tile. */
  video?: { call: CallInfo; local: boolean } | null;
}) {
  const away = state !== "joined" && state !== "you";
  const pending = state === "ringing" || state === "connecting";
  const ring = muted || away ? 0 : Math.min(1, Math.max(0, level));
  return (
    <li
      className={`mx-gcall-tile${speaking ? " is-speaking" : ""}${away && !pending ? " is-away" : ""}${pending ? " is-pending" : ""}${video ? " has-video" : ""}`}
      title={`${name}: ${detail}${muted ? " (muted)" : ""}`}
    >
      {video && <TileVideo call={video.call} peer={id} local={video.local} />}
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

function peerVideoDetail(p: Participant): string | null {
  if (p.state !== "joined") return null;
  if (p.video.remotePaused) return "Video paused: slow connection";
  if (p.video.paused) return "Your video to them is paused: slow connection";
  return null;
}

/** Who's in a group call you're in: everyone's tile (with video when their camera is on), level rings, path and mute. */
export function GroupCallPanel({ call, me }: { call: CallInfo; me: { id: string; name: string } }) {
  const ourCamera = call.video.camera === "on";
  const anyVideo = ourCamera || call.participants.some((p) => p.video.remoteCamera);
  return (
    <section className={`mx-gcall${anyVideo ? " has-video" : ""}`} aria-label={`People in the call (${inCallText(call)})`}>
      <ul>
        <ParticipantTile
          id={me.id}
          name={me.name}
          level={call.level}
          speaking={!call.muted && call.level > 0.55}
          muted={call.muted}
          state="you"
          detail={call.muted ? "Muted" : "You"}
          video={ourCamera ? { call, local: true } : null}
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
            detail={peerVideoDetail(p) ?? participantDetail(p)}
            video={p.state === "joined" && p.video.receiving ? { call, local: false } : null}
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

/** The call has video in it: ours, theirs, or both. */
export function hasVideo(c: CallInfo | null): boolean {
  if (!c || !isLive(c) || c.group) return false;
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
