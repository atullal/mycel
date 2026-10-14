import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, type PluginListener } from "@tauri-apps/api/core";
import { onAction } from "@tauri-apps/plugin-notification";
import { isMobile, isTauri } from "@mycel/sdk";
import { notificationActionId } from "./notificationAction";
import type { NotificationPermission } from "./notificationStatus.ts";

export type { NotificationPermission };

export function useNativeNotifications(enabled: boolean, onOpen: (id: string) => void) {
  const native = isTauri();
  const [permission, setPermission] = useState<NotificationPermission>(native ? "checking" : "unavailable");
  const [error, setError] = useState<string | null>(null);
  const contextQueue = useRef(Promise.resolve());
  const handledActions = useRef(new Set<number>());
  const open = useRef(onOpen);
  open.current = onOpen;

  const checkPermission = useCallback(async () => {
    if (!native || !enabled || document.visibilityState !== "visible") return;
    try {
      setPermission(await invoke<Exclude<NotificationPermission, "checking" | "error">>("prepare_notifications"));
    } catch {
      setPermission("error");
    }
  }, [native, enabled]);

  const setVisibleConversation = useCallback((conversation: string | null) => {
    if (!native) return;
    // React cleanup and the next screen can update context in the same turn.
    // Preserve their order so a delayed old request cannot suppress a new chat.
    contextQueue.current = contextQueue.current
      .catch(() => {})
      .then(() => invoke<void>("set_notification_context", { conversation }))
      .catch(() => setError("Message notification settings could not be updated."));
  }, [native]);

  useEffect(() => {
    if (!native || !enabled) return;
    let cancelled = false;
    let listener: PluginListener | undefined;
    const openingActions = new Set<number>();
    const openAction = async (fallback: number | null = null) => {
      if (cancelled) return;
      let openingId: number | null = null;
      try {
        const pending = await invoke<number | null>("take_notification_action");
        const id = notificationActionId({ id: pending ?? fallback });
        if (id == null || cancelled || handledActions.current.has(id) || openingActions.has(id)) return;
        openingId = id;
        openingActions.add(id);
        const conversation = await invoke<string | null>("notification_target", { id });
        if (cancelled) return;
        handledActions.current.add(id);
        if (handledActions.current.size > 256) {
          const oldest = handledActions.current.values().next().value;
          if (oldest != null) handledActions.current.delete(oldest);
        }
        if (conversation) open.current(conversation);
      } catch {
        if (!cancelled) setError("This notification could not be opened.");
      } finally {
        if (openingId != null) openingActions.delete(openingId);
      }
    };
    const start = async () => {
      if (isMobile()) {
        try {
          const handle = await onAction((payload: unknown) => {
            const id = notificationActionId(payload);
            if (id == null || cancelled) return;
            void openAction(id);
          });
          if (cancelled) await handle.unregister();
          else {
            listener = handle;
            await openAction();
          }
        } catch {
          if (!cancelled) setError("Notification taps could not be enabled.");
        }
      }
      if (!cancelled) await checkPermission();
    };
    void start();
    const refresh = () => {
      if (isMobile() && document.visibilityState === "visible") void openAction();
      void checkPermission();
    };
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      cancelled = true;
      void listener?.unregister();
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [native, enabled, checkPermission]);

  return { native, permission, error, checkPermission, setVisibleConversation };
}
