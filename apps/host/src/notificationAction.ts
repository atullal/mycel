/** iOS wraps the notification; older adapters pass it directly. */
export function notificationActionId(payload: unknown): number | null {
  if (payload == null || typeof payload !== "object") return null;
  const action = payload as Record<string, unknown>;
  if (action.actionId != null && action.actionId !== "tap") return null;
  const notification = action.notification ?? action;
  if (notification == null || typeof notification !== "object") return null;
  const id = (notification as Record<string, unknown>).id;
  return typeof id === "number" && Number.isInteger(id) && id > 0 && id <= 0x7fffffff ? id : null;
}
