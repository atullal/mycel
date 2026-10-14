/**
 * What `prepare_notifications` reports (notify.rs; the plugin's permission
 * states), plus "checking" before it answers and "error" if asking failed.
 * "unavailable": this platform gives no permission state to check (Android,
 * where alerts go through Mycel's service; a desktop without a notification
 * service).
 */
export type NotificationPermission =
  | "checking"
  | "granted"
  | "denied"
  | "prompt"
  | "prompt-with-rationale"
  | "unavailable"
  | "error";

/** What the Profile panel says about notifications, and which button (if any) it offers. */
export function notificationStatus(permission: NotificationPermission): {
  text: string;
  button: string | null;
} {
  switch (permission) {
    case "granted":
      return { text: "Enabled for incoming messages, requests and calls. Names and message contents stay private.", button: null };
    case "denied":
      return {
        text: "Disabled in device settings. Allow notifications for Mycel in Settings to receive alerts.",
        button: "Check notification settings",
      };
    case "prompt":
    case "prompt-with-rationale":
      return { text: "Allow notifications to receive message and call alerts.", button: "Enable notifications" };
    case "checking":
      return { text: "Checking notification permission…", button: null };
    case "error":
      return { text: "Mycel couldn't check whether it may show notifications.", button: "Try again" };
    case "unavailable":
      return {
        text: "Mycel can't check notification permission on this device. If alerts don't appear, allow them for Mycel in your system's notification settings.",
        button: null,
      };
  }
}
