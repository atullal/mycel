import type { ArgsOf, Command, FileHost, ResultOf, Transport } from "./transport.ts";
import type { MycelEvent } from "./types.ts";

/**
 * True when the page is served by `mycel serve` (it injects /api/boot.js,
 * which sets this flag before the app loads).
 */
export function isHttpRuntime(): boolean {
  return typeof window !== "undefined" && (window as unknown as { __MYCEL_HTTP__?: boolean }).__MYCEL_HTTP__ === true;
}

/**
 * Per-run token injected into the page by `mycel serve` (cross-origin pages
 * can't read it). Sent on every API call; the server rejects calls without it.
 */
function token(): string {
  return (window as unknown as { __MYCEL_TOKEN__?: string }).__MYCEL_TOKEN__ ?? "";
}
const marker = () => ({ "X-Mycel": token() });

async function upload(file: File, base: string): Promise<string> {
  const res = await fetch(`${base}/api/upload?name=${encodeURIComponent(file.name || "pasted")}`, {
    method: "POST",
    headers: { ...marker(), "Content-Type": "application/octet-stream" },
    body: file,
  });
  const json = (await res.json()) as { path?: string; error?: string };
  if (!res.ok || !json.path) throw json.error ?? `upload failed (${res.status})`;
  return json.path;
}

function httpFiles(base: string): FileHost {
  return {
    pick() {
      return new Promise((resolve, reject) => {
        const input = document.createElement("input");
        input.type = "file";
        input.multiple = true;
        input.style.display = "none";
        let settled = false;
        input.addEventListener("change", async () => {
          settled = true;
          const files = Array.from(input.files ?? []);
          input.remove();
          try {
            resolve(await Promise.all(files.map((f) => upload(f, base))));
          } catch (e) {
            reject(e);
          }
        });
        // a cancelled dialog fires no change event; resolve empty on next focus
        window.addEventListener(
          "focus",
          () =>
            setTimeout(() => {
              if (!settled) {
                input.remove();
                resolve([]);
              }
            }, 500),
          { once: true },
        );
        document.body.appendChild(input);
        input.click();
      });
    },
    url(path) {
      return `${base}/api/file?path=${encodeURIComponent(path)}&t=${encodeURIComponent(token())}`;
    },
    async open(path) {
      window.open(`${base}/api/file?path=${encodeURIComponent(path)}&t=${encodeURIComponent(token())}`, "_blank", "noopener");
    },
    stage(files) {
      return Promise.all(files.map((f) => upload(f, base)));
    },
  };
}

/**
 * Transport over the local HTTP API of `mycel serve`: POST /api/cmd/<name>
 * for commands, Server-Sent Events on /api/events for runtime events.
 */
export function createHttpTransport(base = ""): Transport {
  const handlers = new Set<(event: MycelEvent) => void>();
  let source: EventSource | null = null;

  const ensureListening = () => {
    if (source) return;
    source = new EventSource(`${base}/api/events?t=${encodeURIComponent(token())}`);
    source.onmessage = (msg) => {
      let event: MycelEvent;
      try {
        event = JSON.parse(msg.data) as MycelEvent;
      } catch {
        return;
      }
      for (const h of [...handlers]) {
        try {
          h(event);
        } catch (err) {
          console.error("[mycel] event handler failed", err);
        }
      }
    };
  };

  return {
    kind: "http",
    files: httpFiles(base),
    async invoke<C extends Command>(cmd: C, args: ArgsOf<C>): Promise<ResultOf<C>> {
      let res: Response;
      try {
        res = await fetch(`${base}/api/cmd/${cmd}`, {
          method: "POST",
          headers: { ...marker(), "Content-Type": "application/json" },
          body: JSON.stringify(args ?? {}),
        });
      } catch {
        throw "Can't reach the Mycel runtime (is `mycel serve` still running?)";
      }
      const json = (await res.json().catch(() => null)) as unknown;
      if (!res.ok) {
        const err = (json as { error?: string } | null)?.error;
        throw err ?? `request failed (${res.status})`;
      }
      return json as ResultOf<C>;
    },
    video(handler) {
      // GET /api/video: one long response of [u32 LE length][frame]...
      const abort = new AbortController();
      void (async () => {
        let res: Response;
        try {
          res = await fetch(`${base}/api/video?t=${encodeURIComponent(token())}`, { signal: abort.signal });
        } catch {
          return;
        }
        const reader = res.body?.getReader();
        if (!reader) return;
        let buf = new Uint8Array(0);
        for (;;) {
          let chunk: ReadableStreamReadResult<Uint8Array>;
          try {
            chunk = await reader.read();
          } catch {
            return;
          }
          if (chunk.done) return;
          const joined = new Uint8Array(buf.length + chunk.value.length);
          joined.set(buf);
          joined.set(chunk.value, buf.length);
          buf = joined;
          while (buf.length >= 4) {
            const len = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0, true);
            if (buf.length < 4 + len) break;
            handler(buf.slice(4, 4 + len).buffer);
            buf = buf.slice(4 + len);
          }
        }
      })();
      return () => abort.abort();
    },
    listen(handler) {
      handlers.add(handler);
      ensureListening();
      return () => {
        handlers.delete(handler);
        if (handlers.size === 0 && source) {
          source.close();
          source = null;
        }
      };
    },
  };
}
