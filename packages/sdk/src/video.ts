// Video frames from the runtime, and decoding them onto a canvas.
//
// The runtime never decodes video for the app: it hands over encoded H.264
// frames (a few KB each) and the webview decodes them in hardware with
// WebCodecs' VideoDecoder. Binary layout of one frame (little-endian), as
// in docs/RUNTIME_API.md "Video":
//
//   0      layout version (1)
//   1      source: 0 = the other device, 1 = our own camera (self-view)
//   2      flags (bit 0: keyframe)
//   3      0
//   4..36  peer: whose video this is (32-byte device key)
//   36..40 sequence number u32
//   40..48 capture time, µs since the Unix epoch, u64
//   48..50 width u16      50..52 height u16
//   52..54 config length u16, then the avcC config (keyframes), then the
//          frame (AVCC: NAL units with 4-byte big-endian lengths)

import type { PeerId } from "./types.ts";

export type VideoSource = "remote" | "local";

/** One encoded video frame. */
export interface VideoFrameData {
  source: VideoSource;
  /** Whose video: the other device's id, or ours for the self-view. */
  peer: PeerId;
  seq: number;
  /** Capture time, ms since the epoch. */
  capturedAt: number;
  keyframe: boolean;
  width: number;
  height: number;
  /** H.264 `avcC` record (SPS + PPS), on keyframes. */
  config: Uint8Array | null;
  data: Uint8Array;
}

const HEADER = 54;

function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** Parse one frame; null if it isn't one. */
export function parseVideoFrame(buf: ArrayBuffer): VideoFrameData | null {
  if (buf.byteLength <= HEADER) return null;
  const v = new DataView(buf);
  if (v.getUint8(0) !== 1) return null;
  const src = v.getUint8(1);
  if (src > 1) return null;
  const cfgLen = v.getUint16(52, true);
  if (buf.byteLength <= HEADER + cfgLen) return null;
  const capturedUs = v.getUint32(40, true) + v.getUint32(44, true) * 2 ** 32;
  return {
    source: src === 0 ? "remote" : "local",
    peer: hex(new Uint8Array(buf, 4, 32)),
    seq: v.getUint32(36, true),
    capturedAt: capturedUs / 1000,
    keyframe: (v.getUint8(2) & 1) === 1,
    width: v.getUint16(48, true),
    height: v.getUint16(50, true),
    config: cfgLen > 0 ? new Uint8Array(buf, HEADER, cfgLen) : null,
    data: new Uint8Array(buf, HEADER + cfgLen),
  };
}

/** Build a frame in the runtime's layout (the mock backend uses this). */
export function encodeVideoFrame(f: VideoFrameData): ArrayBuffer {
  const cfg = f.config ?? new Uint8Array(0);
  const out = new ArrayBuffer(HEADER + cfg.length + f.data.length);
  const v = new DataView(out);
  const b = new Uint8Array(out);
  v.setUint8(0, 1);
  v.setUint8(1, f.source === "remote" ? 0 : 1);
  v.setUint8(2, f.keyframe ? 1 : 0);
  for (let i = 0; i < 32; i++) b[4 + i] = parseInt(f.peer.slice(i * 2, i * 2 + 2), 16) || 0;
  v.setUint32(36, f.seq >>> 0, true);
  const us = Math.round(f.capturedAt * 1000);
  v.setUint32(40, us % 2 ** 32, true);
  v.setUint32(44, Math.floor(us / 2 ** 32), true);
  v.setUint16(48, f.width, true);
  v.setUint16(50, f.height, true);
  v.setUint16(52, cfg.length, true);
  b.set(cfg, HEADER);
  b.set(f.data, HEADER + cfg.length);
  return out;
}

/** The WebCodecs codec string for an avcC record, e.g. `avc1.640028`. */
export function codecString(avcc: Uint8Array): string {
  if (avcc.length < 4) return "avc1.42e01f";
  const h = (n: number) => n.toString(16).padStart(2, "0");
  // The constraint byte's two low bits are reserved (zero); some encoders
  // (Chrome's software H.264) set them, and decoders then reject the string.
  return `avc1.${h(avcc[1]!)}${h(avcc[2]! & 0xfc)}${h(avcc[3]!)}`;
}

/** This webview can decode the runtime's video (WebCodecs, Safari 16.4+). */
export function canDecodeVideo(): boolean {
  return typeof globalThis !== "undefined" && "VideoDecoder" in globalThis && "EncodedVideoChunk" in globalThis;
}

export interface VideoCanvas {
  /** Hand it the next frame of this stream (in order). */
  push(frame: VideoFrameData): void;
  /** Stop and release the decoder. */
  close(): void;
}

export interface VideoCanvasOptions {
  /** The first picture is up (or the size changed). */
  onPicture?: (width: number, height: number) => void;
  /** The decoder lost its place: get a keyframe (`calls.requestKeyframe`). */
  onNeedKeyframe?: () => void;
}

/**
 * Decode one video stream onto a canvas. Frames before the first keyframe
 * are skipped; a new `avcC` (resolution change) reconfigures the decoder;
 * a decode error resets it and asks for a keyframe.
 */
export function videoCanvas(canvas: HTMLCanvasElement, opts: VideoCanvasOptions = {}): VideoCanvas {
  const ctx = canvas.getContext("2d");
  let decoder: VideoDecoder | null = null;
  let config: string | null = null;
  let waitingForKey = true;
  let closed = false;
  let lastAsk = 0;

  const ask = () => {
    const now = Date.now();
    if (now - lastAsk < 500) return;
    lastAsk = now;
    opts.onNeedKeyframe?.();
  };

  const reset = () => {
    try {
      decoder?.close();
    } catch {
      // already closed
    }
    decoder = null;
    config = null;
    waitingForKey = true;
  };

  const make = () =>
    new VideoDecoder({
      output: (frame) => {
        if (closed) {
          frame.close();
          return;
        }
        const w = frame.displayWidth;
        const h = frame.displayHeight;
        if (canvas.width !== w || canvas.height !== h) {
          canvas.width = w;
          canvas.height = h;
          opts.onPicture?.(w, h);
        }
        ctx?.drawImage(frame, 0, 0, w, h);
        frame.close();
      },
      error: () => {
        reset();
        ask();
      },
    });

  ask(); // a new viewer: start from a fresh keyframe

  return {
    push(f) {
      if (closed) return;
      if (f.keyframe && f.config) {
        const key = Array.from(f.config).join(",");
        if (key !== config) {
          reset();
          decoder = make();
          decoder.configure({
            codec: codecString(f.config),
            description: f.config,
            optimizeForLatency: true,
            hardwareAcceleration: "no-preference",
          });
          config = key;
        }
        waitingForKey = false;
      }
      if (waitingForKey || !decoder || decoder.state !== "configured") {
        ask();
        return;
      }
      // a backed-up decoder: drop to the next keyframe rather than lag
      if (decoder.decodeQueueSize > 10) {
        waitingForKey = true;
        ask();
        return;
      }
      try {
        decoder.decode(
          new EncodedVideoChunk({ type: f.keyframe ? "key" : "delta", timestamp: f.capturedAt * 1000, data: f.data }),
        );
      } catch {
        reset();
        ask();
      }
    },
    close() {
      closed = true;
      reset();
    },
  };
}
