import { useEffect, useRef, useState } from "react";
import { Icon, errorText } from "./ui.tsx";

const MAX_SECONDS = 300;
const MAX_BYTES = 16 * 1024 * 1024;

/** Recording is local until the user reviews it and explicitly sends the draft. */
export function VoiceRecorder({ onAttach, onCancel }: { onAttach: (file: File) => Promise<void>; onCancel: () => void }) {
  const recorder = useRef<MediaRecorder | null>(null);
  const [status, setStatus] = useState<"starting" | "recording" | "paused" | "preview" | "error">("starting");
  const [seconds, setSeconds] = useState(0);
  const [clip, setClip] = useState<{ file: File; url: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    let stream: MediaStream | null = null;
    let timer: ReturnType<typeof setInterval> | undefined;
    let url: string | undefined;
    let failed = false;
    const stopTracks = () => stream?.getTracks().forEach((track) => track.stop());
    const stop = () => { if (recorder.current?.state !== "inactive") recorder.current?.stop(); stopTracks(); };
    const background = () => { if (document.hidden) stop(); };
    void (async () => {
      try {
        if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === "undefined") throw new Error("Voice recording is unavailable on this device.");
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        if (!alive) { stopTracks(); return; }
        const mime = ["audio/mp4", "audio/webm;codecs=opus", "audio/webm", "audio/ogg;codecs=opus"].find((m) => MediaRecorder.isTypeSupported(m));
        if (!mime) throw new Error("This device does not support a compatible voice recording format.");
        const rec = new MediaRecorder(stream, { mimeType: mime }); recorder.current = rec;
        const chunks: Blob[] = []; let bytes = 0; let elapsed = 0;
        rec.ondataavailable = (e) => {
          if (!alive || failed || !e.data.size) return;
          bytes += e.data.size;
          if (bytes > MAX_BYTES) { failed = true; setError("The recording reached the size limit. Record a shorter voice note."); setStatus("error"); stop(); return; }
          chunks.push(e.data);
        };
        rec.onerror = () => { failed = true; if (alive) { setError("Recording failed. Try again."); setStatus("error"); } stop(); };
        rec.onstop = () => {
          clearInterval(timer); stopTracks();
          if (!alive || failed) return;
          if (!chunks.length) { setError("No audio was recorded. Try again."); setStatus("error"); return; }
          const ext = mime.startsWith("audio/mp4") ? "m4a" : mime.startsWith("audio/ogg") ? "ogg" : "weba";
          const file = new File(chunks, `Voice note ${new Date().toISOString().replace(/[:.]/g, "-")}.${ext}`, { type: mime });
          url = URL.createObjectURL(file); setClip({ file, url }); setStatus("preview");
        };
        rec.start(1000); setStatus("recording");
        timer = setInterval(() => { if (rec.state === "recording") { elapsed++; setSeconds(elapsed); if (elapsed >= MAX_SECONDS) stop(); } }, 1000);
        document.addEventListener("visibilitychange", background);
      } catch (e) { stopTracks(); if (alive) { setError(errorText(e)); setStatus("error"); } }
    })();
    return () => { alive = false; clearInterval(timer); document.removeEventListener("visibilitychange", background); stop(); if (url) URL.revokeObjectURL(url); };
  }, []);
  return <div className="mx-voice-recorder" aria-label="Voice note recorder">
    <div className="mx-voice-status" role="status">{status === "starting" ? "Opening microphone…" : status === "preview" ? "Review voice note" : status === "error" ? "Recording stopped" : `${status === "paused" ? "Paused" : "Recording"} ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`}</div>
    {clip && <audio src={clip.url} controls aria-label="Voice note preview" />}
    {error && <p className="mx-error" role="alert">{error}</p>}
    <div className="mx-voice-controls">
      <button className="mx-btn mx-btn-quiet" disabled={busy} onClick={onCancel}>Cancel recording</button>
      {(status === "recording" || status === "paused") && <>
        <button className="mx-btn mx-btn-quiet" onClick={() => { const rec = recorder.current!; if (rec.state === "recording") { rec.pause(); setStatus("paused"); } else { rec.resume(); setStatus("recording"); } }}>{status === "paused" ? "Resume" : "Pause"}</button>
        <button className="mx-btn" onClick={() => recorder.current?.stop()}><Icon.Stop size={16} />Stop</button>
      </>}
      {clip && <button className="mx-btn mx-btn-primary" disabled={busy} onClick={async () => { setBusy(true); try { await onAttach(clip.file); onCancel(); } catch (e) { setError(errorText(e)); setBusy(false); } }}>{busy ? "Adding…" : "Use recording"}</button>}
    </div>
  </div>;
}
