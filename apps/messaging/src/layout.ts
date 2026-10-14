// Phones and computers get different controls: a computer has hover, a
// right-click menu and room for video beside the chat; a phone has long
// press, swipes and one pane at a time. The rules for which is which live
// here, as plain functions, so they can be tested (tests/layout.test.ts).

/** A mouse or trackpad: hover works and clicks are precise. */
export const FINE_POINTER = "(hover: hover) and (pointer: fine)";
/** One pane at a time, the conversation list or a conversation (messaging.css). */
export const PHONE_LAYOUT = "(max-width: 720px)";
/** The details panel slides over the conversation instead of sitting beside it (messaging.css). */
export const PANEL_OVER_CHAT = "(max-width: 1080px)";

/**
 * Right-click on a message with a mouse: the system menu stays where it does
 * something ours can't (copy the selected words, open or copy a link, save a
 * picture or a video). Anywhere else on the message, ours opens instead.
 */
export function keepsSystemMenu(on: { selectionInMessage: boolean; linkOrMedia: boolean }): boolean {
  return on.selectionInMessage || on.linkOrMedia;
}

/** What a right-click on these elements should leave to the system menu. */
export const SYSTEM_MENU_TARGETS = "a[href], img, video, audio";

export type VideoLayout = "inline" | "expanded" | "floating";

/**
 * Where a video call shows. On a wide screen it sits above the conversation,
 * which stays usable below it. On a phone it fills the screen, or floats
 * small over the app once minimized.
 */
export function videoLayout(phoneLayout: boolean, minimized: boolean): VideoLayout {
  if (!phoneLayout) return "inline";
  return minimized ? "floating" : "expanded";
}

/**
 * Is the open conversation actually in view? Only then is it marked read
 * and are its alerts held back. A host panel, the new-conversation dialog,
 * a full-screen call, or a details panel drawn over the chat all hide it; a
 * details panel beside it (wide windows) does not.
 */
export function conversationInView(s: {
  hostVisible: boolean;
  composing: boolean;
  videoLayout: VideoLayout | null;
  membersOpen: boolean;
  panelOverChat: boolean;
}): boolean {
  return s.hostVisible && !s.composing && s.videoLayout !== "expanded" && !(s.membersOpen && s.panelOverChat);
}
