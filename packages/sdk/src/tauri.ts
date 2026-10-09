import { Channel, convertFileSrc, invoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { openPath } from "@tauri-apps/plugin-opener";
import type { ArgsOf, Command, FileHost, ResultOf, Transport } from "./transport.ts";
import type { MycelEvent } from "./types.ts";

/** The Tauri event name the host emits runtime events on. */
export const EVENT_NAME = "mycel://event";

/** True when running inside a Tauri webview. */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/**
 * True in the iPhone, iPad and Android apps. There the native file dialog
 * hands back content:// URIs or temporary copies instead of paths, and an
 * app can't relaunch itself. (iPad web views say "Macintosh"; touch gives
 * them away.)
 */
export function isMobile(): boolean {
  if (typeof navigator === "undefined") return false;
  const ua = navigator.userAgent;
  return /Android|iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
}

/** The system's photo / file picker, through a hidden file input. */
function chooseFiles(): Promise<File[]> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    input.style.display = "none";
    const done = (files: File[]) => {
      input.remove();
      resolve(files);
    };
    input.addEventListener("change", () => done(Array.from(input.files ?? [])));
    input.addEventListener("cancel", () => done([]));
    document.body.append(input);
    input.click();
  });
}

const tauriFiles: FileHost = {
  async pick() {
    if (isMobile()) {
      const files = await chooseFiles();
      return files.length ? tauriFiles.stage!(files) : [];
    }
    const picked = await openDialog({ multiple: true, directory: false, title: "Attach files" });
    if (picked == null) return [];
    return Array.isArray(picked) ? picked : [picked];
  },
  url(path) {
    return convertFileSrc(path);
  },
  async open(path) {
    // Phones: the share sheet / "Open with" (the host's `open_file`).
    if (isMobile()) await invoke("open_file", { path });
    else await openPath(path);
  },
  async stage(files) {
    const paths: string[] = [];
    for (const f of files) {
      // Raw body (no JSON): the `stage_file` command writes it under uploads/.
      const bytes = new Uint8Array(await f.arrayBuffer());
      paths.push(
        await invoke<string>("stage_file", bytes, {
          headers: { "x-mycel-name": encodeURIComponent(f.name || "pasted") },
        }),
      );
    }
    return paths;
  },
  onDragDrop(handler) {
    let off: (() => void) | null = null;
    let cancelled = false;
    void getCurrentWebview()
      .onDragDropEvent((e) => {
        const p = e.payload;
        if (p.type === "enter" || p.type === "over") handler({ type: "over" });
        else if (p.type === "leave") handler({ type: "leave" });
        else if (p.type === "drop") handler({ type: "drop", paths: p.paths });
      })
      .then((fn) => {
        if (cancelled) fn();
        else off = fn;
      });
    return () => {
      cancelled = true;
      off?.();
    };
  },
};

/**
 * Transport over Tauri IPC: `invoke(cmd, args)` for commands and a single
 * `mycel://event` listener fanned out to every subscriber.
 */
export function createTauriTransport(): Transport {
  const handlers = new Set<(event: MycelEvent) => void>();
  let unlisten: Promise<() => void> | null = null;

  const ensureListening = () => {
    if (unlisten) return;
    unlisten = tauriListen<MycelEvent>(EVENT_NAME, (e) => {
      for (const h of [...handlers]) {
        try {
          h(e.payload);
        } catch (err) {
          console.error("[mycel] event handler failed", err);
        }
      }
    });
  };

  return {
    kind: "tauri",
    files: tauriFiles,
    invoke<C extends Command>(cmd: C, args: ArgsOf<C>): Promise<ResultOf<C>> {
      return invoke<ResultOf<C>>(cmd, args as Record<string, unknown>);
    },
    listen(handler) {
      handlers.add(handler);
      ensureListening();
      return () => {
        handlers.delete(handler);
        if (handlers.size === 0 && unlisten) {
          const pending = unlisten;
          unlisten = null;
          void pending.then((fn) => fn());
        }
      };
    },
    video(handler) {
      // Raw bytes over a Tauri channel (`video_subscribe`); a new
      // subscription replaces the previous one in the host.
      const channel = new Channel<ArrayBuffer>();
      let live = true;
      channel.onmessage = (buf) => {
        if (live) handler(buf);
      };
      void invoke("video_subscribe", { channel }).catch((e) => console.error("[mycel] video", e));
      return () => {
        live = false;
      };
    },
  };
}
