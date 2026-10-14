import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useMycel, useVideoCanvas } from "@mycel/sdk/react";
import type { CallInfo, Participant, ParticipantState, PathKind } from "@mycel/sdk";
import { Avatar, Icon, errorText } from "./ui.tsx";
import "./call-layout.css";
import type { VideoLayout } from "./layout.ts";

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
  mesh: "Mesh",
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
  mesh: "nearby devices (mesh)",
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
 *
 * Where it shows depends on the screen (`videoLayout` in layout.ts): on a
 * wide screen above the conversation, which stays usable below it; on a
 * phone full screen, or floating small over the app once minimized. Moving
 * between inline and full screen/floating (a window resized across the
 * phone breakpoint) mounts new canvases, which ask for a fresh keyframe.
 */
export function VideoStage({ call, layout, onMinimize, onRestore, onOpenChat }: {
  call: CallInfo;
  layout: VideoLayout;
  onMinimize: () => void;
  onRestore: () => void;
  onOpenChat: () => void;
}) {
  if (layout === "inline") return <InlineVideoStage call={call} />;
  return (
    <OverlayVideoStage
      call={call}
      minimized={layout === "floating"}
      onMinimize={onMinimize}
      onRestore={onRestore}
      onOpenChat={onOpenChat}
    />
  );
}

/** Their picture and ours, plus what to say while there's no picture. */
function useStagePicture(call: CallInfo) {
  const remote = useRef<HTMLCanvasElement>(null);
  const self = useRef<HTMLCanvasElement>(null);
  const v = call.video;
  const live = call.state === "active";
  const them = useVideoCanvas(remote, { call: live ? call.id : null, source: "remote", peer: call.peer });
  const me = useVideoCanvas(self, { call: live ? call.id : null, source: "local" });
  const first = call.peerName.split(" ")[0] || call.peerName;
  let note: string | null = null;
  if (!them.supported) note = "Video can't be shown in this window (it needs WebCodecs: Safari 16.4 or later).";
  else if (!live) note = call.direction === "outgoing" ? "Calling…" : "Connecting…";
  else if (!v.remoteCamera) note = `${first}'s camera is off`;
  else if (v.remotePaused) note = "Video paused: slow connection";
  else if (!them.picture) note = "Connecting video…";
  const compactNote = !them.supported
    ? "Video unavailable"
    : !live
      ? "Calling…"
      : !v.remoteCamera
        ? "Camera off"
        : v.remotePaused
          ? "Video paused"
          : "Connecting…";
  return { remote, self, them, me, note, compactNote, live };
}

/** The canvases, notes and stats inside a stage, whichever layout it has. */
function StagePicture({ call, picture, compact }: { call: CallInfo; picture: ReturnType<typeof useStagePicture>; compact: boolean }) {
  const { remote, self, them, me, note, compactNote, live } = picture;
  const v = call.video;
  const ourCamera = v.camera === "on" || v.camera === "starting";
  return (
    <>
      <canvas ref={remote} className={`mx-stage-remote${them.picture && !note ? " is-on" : ""}`} aria-label={`${call.peerName}'s video`} />
      {note && (
        <div className="mx-stage-note">
          <Avatar id={call.peer} name={call.peerName} size={64} />
          <span title={note} aria-label={note}>{compact ? compactNote : note}</span>
        </div>
      )}
      {/* always mounted, so the decoder attaches once; hidden with the camera off */}
      <div
        className={`mx-stage-self${me.picture ? " is-on" : ""}${ourCamera ? "" : " is-hidden"}`}
        style={me.picture ? { aspectRatio: `${me.picture.width} / ${me.picture.height}` } : undefined}
        aria-hidden={!ourCamera}
      >
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
    </>
  );
}

/** Wide screens: the stage sits above the conversation, under the call bar. */
function InlineVideoStage({ call }: { call: CallInfo }) {
  const picture = useStagePicture(call);
  return (
    <section className="mx-stage" aria-label={`Video call with ${call.peerName}`}>
      <StagePicture call={call} picture={picture} compact={false} />
    </section>
  );
}

/** Phones: full screen over the app, or a small floating picture. */
function OverlayVideoStage({ call, minimized, onMinimize, onRestore, onOpenChat }: {
  call: CallInfo;
  minimized: boolean;
  onMinimize: () => void;
  onRestore: () => void;
  onOpenChat: () => void;
}) {
  const picture = useStagePicture(call);
  const { them } = picture;
  const stage = useRef<HTMLElement>(null);
  const restore = useRef<HTMLButtonElement>(null);
  const drag = useRef<{ x: number; y: number; left: number; top: number; moved: boolean; pointer: number } | null>(null);
  const swipe = useRef<{ x: number; y: number } | null>(null);
  const suppressRestore = useRef(false);
  const [position, setPosition] = useState<{ left: number; top: number } | null>(null);
  const [availableHeight, setAvailableHeight] = useState<number | undefined>();
  const [corner, setCorner] = useState({ right: true, bottom: false });
  const [dragging, setDragging] = useState(false);

  // visualViewport shrinks and moves when the phone keyboard opens. Keep
  // the floating call above it, and remember which corner was chosen.
  useEffect(() => {
    if (!minimized) return;
    const place = () => {
      const rect = stage.current?.getBoundingClientRect();
      if (!rect) return;
      const vp = window.visualViewport;
      const left = vp?.offsetLeft ?? 0;
      const top = vp?.offsetTop ?? 0;
      const width = vp?.width ?? window.innerWidth;
      const height = vp?.height ?? window.innerHeight;
      const pad = 12;
      const safeTop = Math.max(top + pad, parseFloat(getComputedStyle(stage.current!).getPropertyValue("--call-top-inset")) || 0);
      setAvailableHeight(Math.max(80, Math.min(300, height * 0.4, height - (safeTop - top) - pad)));
      setPosition({
        left: corner.right ? Math.max(left + pad, left + width - rect.width - pad) : left + pad,
        top: corner.bottom ? Math.max(safeTop, top + height - rect.height - pad) : safeTop,
      });
    };
    place();
    const viewport = window.visualViewport;
    window.addEventListener("resize", place);
    viewport?.addEventListener("resize", place);
    viewport?.addEventListener("scroll", place);
    const observer = new ResizeObserver(place);
    if (stage.current) observer.observe(stage.current);
    return () => {
      window.removeEventListener("resize", place);
      viewport?.removeEventListener("resize", place);
      viewport?.removeEventListener("scroll", place);
      observer.disconnect();
    };
  }, [minimized, corner]);

  useEffect(() => {
    if (minimized) restore.current?.focus({ preventScroll: true });
    else stage.current?.focus({ preventScroll: true });
  }, [minimized]);

  return createPortal(
    <section
      ref={stage}
      className={`mx-stage mx-call-stage${minimized ? " is-floating" : " is-expanded"}${dragging ? " is-dragging" : ""}`}
      style={minimized ? { left: position?.left ?? 12, top: position?.top ?? 48, maxHeight: availableHeight,
        aspectRatio: them.picture ? `${them.picture.width} / ${them.picture.height}` : undefined } : undefined}
      role={minimized ? "region" : "dialog"}
      aria-modal={minimized ? undefined : true}
      aria-label={`Video call with ${call.peerName}`}
      tabIndex={-1}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !minimized) { e.preventDefault(); onMinimize(); }
        if (!minimized && e.key === "Tab") {
          const buttons = Array.from(stage.current!.querySelectorAll<HTMLButtonElement>("button:not(:disabled)"));
          const first = buttons[0], last = buttons.at(-1);
          if (e.shiftKey && (document.activeElement === first || document.activeElement === stage.current)) {
            e.preventDefault(); last?.focus();
          } else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
        }
      }}
      onPointerDown={(e) => {
        if (!minimized && !(e.target as Element).closest("button")) swipe.current = { x: e.clientX, y: e.clientY };
      }}
      onPointerUp={(e) => {
        const start = swipe.current;
        swipe.current = null;
        if (!minimized && start && e.clientY - start.y > 90 && Math.abs(e.clientX - start.x) < 65) onMinimize();
      }}
      onPointerCancel={() => { swipe.current = null; }}
    >
      <StagePicture call={call} picture={picture} compact={minimized} />
      {!minimized && (
        <div className="mx-stage-controls">
          <button className="mx-stage-minimize" onClick={onMinimize} aria-label="Minimize video call" title="Return to chat">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="m6 9 6 6 6-6" /></svg>
          </button>
          <CallBar call={call} onOpen={onOpenChat} error={null} onDismissError={() => {}} />
        </div>
      )}
      {minimized && (
        <>
          <button
            ref={restore}
            className="mx-stage-restore"
            aria-label="Restore video call"
            title="Tap to open. Drag to move."
            onClick={(e) => {
              if (suppressRestore.current) { e.preventDefault(); suppressRestore.current = false; }
              else onRestore();
            }}
            onKeyDown={(e) => {
              if (e.key.startsWith("Arrow")) {
                e.preventDefault();
                setCorner((c) => ({ right: e.key === "ArrowRight" ? true : e.key === "ArrowLeft" ? false : c.right,
                  bottom: e.key === "ArrowDown" ? true : e.key === "ArrowUp" ? false : c.bottom }));
              }
            }}
            onPointerDown={(e) => {
              if (e.pointerType === "mouse" && e.button !== 0) return;
              suppressRestore.current = false;
              const rect = stage.current!.getBoundingClientRect();
              drag.current = { x: e.clientX, y: e.clientY, left: rect.left, top: rect.top, moved: false, pointer: e.pointerId };
              e.currentTarget.setPointerCapture(e.pointerId);
            }}
            onPointerMove={(e) => {
              const d = drag.current;
              if (!d || d.pointer !== e.pointerId) return;
              const dx = e.clientX - d.x, dy = e.clientY - d.y;
              if (!d.moved && Math.hypot(dx, dy) < 6) return;
              d.moved = true;
              setDragging(true);
              const vp = window.visualViewport;
              const bounds = stage.current!.getBoundingClientRect();
              const minX = (vp?.offsetLeft ?? 0) + 12, minY = (vp?.offsetTop ?? 0) + 12;
              const maxX = Math.max(minX, (vp?.offsetLeft ?? 0) + (vp?.width ?? innerWidth) - bounds.width - 12);
              const maxY = Math.max(minY, (vp?.offsetTop ?? 0) + (vp?.height ?? innerHeight) - bounds.height - 12);
              setPosition({ left: Math.min(maxX, Math.max(minX, d.left + dx)), top: Math.min(maxY, Math.max(minY, d.top + dy)) });
            }}
            onPointerUp={(e) => {
              const d = drag.current;
              if (!d || d.pointer !== e.pointerId) return;
              drag.current = null;
              setDragging(false);
              suppressRestore.current = d.moved;
              if (d.moved) {
                const rect = stage.current!.getBoundingClientRect(), vp = window.visualViewport;
                setCorner({ right: rect.left + rect.width / 2 > (vp?.offsetLeft ?? 0) + (vp?.width ?? innerWidth) / 2,
                  bottom: rect.top + rect.height / 2 > (vp?.offsetTop ?? 0) + (vp?.height ?? innerHeight) / 2 });
              }
              e.currentTarget.releasePointerCapture(e.pointerId);
            }}
            onPointerCancel={() => { drag.current = null; setDragging(false); suppressRestore.current = true; setCorner((c) => ({ ...c })); }}
          >
            <span><span className="mx-stage-caption-name">{call.peerName}</span><span className="mx-stage-caption-time">{statusText(call)}</span></span>
          </button>
          <button className="mx-stage-corner" aria-label="Move floating call to another corner" title="Move to next corner"
            onClick={() => setCorner((c) => ({ right: c.bottom ? !c.right : c.right, bottom: !c.bottom }))}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M4 9V4h5m6 0h5v5m0 6v5h-5M9 20H4v-5" /></svg>
          </button>
        </>
      )}
    </section>
    , document.body
  );
}
