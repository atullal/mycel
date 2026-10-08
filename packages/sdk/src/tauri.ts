import { convertFileSrc, invoke } from "@tauri-apps/api/core";
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

const tauriFiles: FileHost = {
  async pick() {
    const picked = await openDialog({ multiple: true, directory: false, title: "Attach files" });
    if (picked == null) return [];
    return Array.isArray(picked) ? picked : [picked];
  },
  url(path) {
    return convertFileSrc(path);
  },
  async open(path) {
    await openPath(path);
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
  };
}
