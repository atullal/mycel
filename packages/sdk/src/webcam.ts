import { invoke } from "@tauri-apps/api/core";
import { invokeBytes } from "./ipc.ts";
import type { CallInfo } from "./types.ts";

/**
 * Our camera on Android, Windows and Linux: the host has no camera of its
 * own there, so the web view captures (`getUserMedia`) and encodes H.264
 * with WebCodecs (hardware where the platform has it), and the runtime
 * sends the frames like any others (`mycel_video::web`). Apple devices use
 * their native camera: `video_targets` is always `null` there, so this
 * never starts.
 *
 * Driven by call events: it runs while any live call has our camera on.
 * Each pushed frame comes back with what to encode next (size, frame rate,
 * bitrate from the rate controller, and when a keyframe is needed).
 */

interface Targets {
  width: number;
  height: number;
  fps: number;
  bitrate: number;
  keyframe: boolean;
}

/** Wall-clock µs (capture times travel with frames for latency stats). */
const wallUs = () => Math.round((performance.timeOrigin + performance.now()) * 1000);

const even = (n: number) => Math.max(2, Math.round(n / 2) * 2);

/** The camera stream while the web view is capturing for a call (the self-view draws it). */
export function webCameraStream(): MediaStream | null {
  return (globalThis as { __mycelWebcam?: WebCamera }).__mycelWebcam?.liveStream() ?? null;
}

export class WebCamera {
  /** Live calls with our camera on. */
  private wanted = new Set<string>();
  private running = false;
  private starting = false;
  /** The host has its own camera (Apple devices): never capture here. */
  private native = false;
  private stream: MediaStream | null = null;
  private encoder: VideoEncoder | null = null;
  private config: VideoEncoderConfig | null = null;
  private targets: Targets | null = null;
  private description: Uint8Array | null = null;
  private wantKey = true;
  private lastFrameAt = 0;
  /** Capture time and size of each frame in the encoder, oldest first (no B-frames). */
  private inFlight: { at: number; width: number; height: number }[] = [];
  private video: HTMLVideoElement | null = null;
  private timer: number | null = null;
  /** No hardware encoder for this config (emulators, some PCs): let the web view pick. */
  private noHardware = false;
  private configuredAt = 0;
  private lastKeyAt = 0;
  /** Pushes go one after another, in encode order (a reordered frame breaks H.264's chain). */
  private sending: Promise<void> = Promise.resolve();
  private encoded = 0;
  /** For debugging from the web inspector: `__mycelWebcam`. */
  readonly stats = { frames: 0, encoded: 0, keyframes: 0, keyAsked: 0, pushed: 0, dropped: 0 };

  constructor() {
    (globalThis as { __mycelWebcam?: WebCamera }).__mycelWebcam = this;
  }

  liveStream(): MediaStream | null {
    return this.running ? this.stream : null;
  }

  /** A call event: keep the camera running while any live call wants it. */
  onCall(call: CallInfo) {
    if (this.native) return;
    if (call.state !== "ended" && call.video.camera === "on") this.wanted.add(call.id);
    else this.wanted.delete(call.id);
    if (this.wanted.size > 0 && !this.running && !this.starting) void this.start();
    else if (this.wanted.size === 0 && this.running) this.stop();
  }

  private async start() {
    this.starting = true;
    const t = await invoke<Targets | null>("video_targets").catch(() => null);
    this.starting = false;
    if (!t) {
      // The camera is on but the host doesn't want frames: it has its own.
      this.native = true;
      return;
    }
    if (this.wanted.size === 0) return;
    this.running = true;
    if (typeof VideoEncoder === "undefined" || !navigator.mediaDevices?.getUserMedia) {
      console.warn("[mycel] this web view can't capture or encode video; the call stays voice-only");
      this.running = false;
      return;
    }
    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
      });
    } catch (e) {
      console.warn("[mycel] camera unavailable", e);
      this.running = false;
      for (const id of this.wanted) void invoke("set_camera", { call: id, on: false }).catch(() => {});
      return;
    }
    this.targets = t;
    this.wantKey = true;
    const track = this.stream.getVideoTracks()[0]!;
    if ("MediaStreamTrackProcessor" in window) {
      // Chromium (Android WebView, WebView2): every camera frame as a VideoFrame.
      const Processor = (window as unknown as { MediaStreamTrackProcessor: new (o: { track: MediaStreamTrack }) => { readable: ReadableStream<VideoFrame> } }).MediaStreamTrackProcessor;
      const reader = new Processor({ track }).readable.getReader();
      void (async () => {
        while (this.running) {
          const { value, done } = await reader.read().catch(() => ({ value: undefined, done: true }));
          if (done || !value) break;
          this.frame(value);
        }
        reader.releaseLock();
      })();
    } else {
      // WebKitGTK: draw from a <video> at the target frame rate.
      const video = document.createElement("video");
      video.muted = true;
      video.playsInline = true;
      video.srcObject = this.stream;
      await video.play().catch(() => {});
      this.video = video;
      const tick = () => {
        if (!this.running) return;
        if (video.videoWidth > 0) this.frame(new VideoFrame(video, { timestamp: wallUs() }));
        this.timer = window.setTimeout(tick, 1000 / Math.max(1, this.targets?.fps ?? 15));
      };
      tick();
    }
  }

  private stop() {
    this.running = false;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    this.video?.pause();
    this.video = null;
    for (const t of this.stream?.getTracks() ?? []) t.stop();
    this.stream = null;
    if (this.encoder && this.encoder.state !== "closed") this.encoder.close();
    this.encoder = null;
    this.config = null;
    this.description = null;
    this.inFlight = [];
  }

  /** One camera frame: pace it to the target frame rate, fit it to the target size, encode. */
  private frame(frame: VideoFrame) {
    const t = this.targets;
    const now = performance.now();
    if (!t || !this.running || now - this.lastFrameAt < (1000 / Math.max(1, t.fps)) * 0.85) {
      frame.close();
      return;
    }
    const enc = this.ensureEncoder(frame.displayWidth, frame.displayHeight, t);
    if (!enc || enc.encodeQueueSize > 2) {
      frame.close(); // the encoder is behind: skip rather than queue
      this.stats.dropped++;
      return;
    }
    this.stats.frames++;
    this.lastFrameAt = now;
    this.inFlight.push({ at: wallUs(), width: this.config!.width, height: this.config!.height });
    // Asked for, or every 10 s as a backstop (as the Mac's encoder does), so
    // a viewer that missed a request still catches up.
    const key = this.wantKey || now - this.lastKeyAt > 10_000;
    this.wantKey = false;
    if (key) {
      this.stats.keyAsked++;
      this.lastKeyAt = now;
    }
    try {
      enc.encode(frame, { keyFrame: key });
    } catch (e) {
      console.warn("[mycel] video encode failed:", e instanceof Error ? e.message : e);
      this.inFlight.pop();
    } finally {
      frame.close();
    }
  }

  /** The encoder for this frame size and the current targets (re-configured when they move). */
  private ensureEncoder(fw: number, fh: number, t: Targets): VideoEncoder | null {
    // Fit the camera's picture into the target box, keeping its shape
    // (a portrait phone camera gets a portrait box).
    const portrait = fh > fw;
    const [bw, bh] = portrait ? [t.height, t.width] : [t.width, t.height];
    const scale = Math.min(1, bw / fw, bh / fh);
    const width = even(fw * scale);
    const height = even(fh * scale);
    // Re-configuring can make the encoder start over with a keyframe, so only
    // for a new size, or a clearly different bitrate at most every 2 s (the
    // rate controller nudges it all the time). The frame rate is paced above.
    const c = this.config;
    const now = performance.now();
    const resized = !c || c.width !== width || c.height !== height;
    const rerated = !!c && Math.abs((c.bitrate ?? 0) - t.bitrate) > t.bitrate * 0.4 && now - this.configuredAt > 2000;
    if (this.encoder && this.encoder.state === "configured" && !resized && !rerated) return this.encoder;
    if (!this.encoder || this.encoder.state === "closed") {
      this.encoder = new VideoEncoder({
        output: (chunk, meta) => this.output(chunk, meta),
        error: (e) => {
          console.warn("[mycel] video encoder:", e.message);
          if (this.config?.hardwareAcceleration === "prefer-hardware") this.noHardware = true;
          this.encoder = null;
          this.config = null;
          this.inFlight = [];
        },
      });
    }
    this.config = {
      // Constrained Baseline: no B-frames, decodes everywhere (level 3.1 up to 720p, 4.0 above)
      codec: width * height <= 921_600 ? "avc1.42E01F" : "avc1.42E028",
      width,
      height,
      bitrate: t.bitrate,
      framerate: 30,
      latencyMode: "realtime",
      hardwareAcceleration: this.noHardware ? "no-preference" : "prefer-hardware",
      avc: { format: "avc" },
    } as VideoEncoderConfig;
    try {
      this.encoder.configure(this.config);
    } catch (e) {
      console.warn("[mycel] video encoder config:", e instanceof Error ? e.message : e);
      this.config = null;
      return null;
    }
    this.configuredAt = now;
    // a new size starts with a keyframe (receivers need its new config)
    if (resized) this.wantKey = true;
    return this.encoder;
  }

  private output(chunk: EncodedVideoChunk, meta: EncodedVideoChunkMetadata | undefined) {
    const { at: captured, width, height } = this.inFlight.shift() ?? { at: wallUs(), width: 0, height: 0 };
    if (!width || !height) return;
    const desc = meta?.decoderConfig?.description;
    if (desc) {
      this.description = ArrayBuffer.isView(desc)
        ? new Uint8Array(desc.buffer, desc.byteOffset, desc.byteLength).slice()
        : new Uint8Array(desc).slice();
    }
    const key = chunk.type === "key";
    const n = this.encoded++;
    this.stats.encoded++;
    if (key) this.stats.keyframes++;
    const cfg = key && this.description ? this.description : new Uint8Array(0);
    const body = new Uint8Array(cfg.length + chunk.byteLength);
    body.set(cfg, 0);
    chunk.copyTo(body.subarray(cfg.length));
    const header = `key=${key ? 1 : 0};w=${width};h=${height};cfg=${cfg.length};t=${captured};n=${n}`;
    this.sending = this.sending
      .then(() => invokeBytes<Targets | null>("video_push", body, { "x-mycel-frame": header }))
      .then((next) => {
        this.stats.pushed++;
        if (!next) {
          this.stop(); // the camera went off
          return;
        }
        if (next.keyframe) this.wantKey = true;
        this.targets = next;
      })
      .catch((e) => console.warn("[mycel] video push", e));
  }
}
