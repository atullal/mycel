import { invoke } from "@tauri-apps/api/core";

/**
 * Android's web view talks to the host over JSON only (no raw request
 * bodies), so bytes go as base64 there; elsewhere they're the raw body.
 * The host takes either (`body_bytes` in commands.rs).
 */
export const bytesAsJson = typeof navigator !== "undefined" && /Android/.test(navigator.userAgent);

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Invoke a command whose input is bytes (plus metadata in headers). */
export function invokeBytes<T>(cmd: string, bytes: Uint8Array, headers: Record<string, string>): Promise<T> {
  return bytesAsJson ? invoke<T>(cmd, { base64: toBase64(bytes) }, { headers }) : invoke<T>(cmd, bytes, { headers });
}
