// How an app talks to the host's shell (the app bar, panels) without the
// host knowing anything about the app's own markup.

/**
 * Put this attribute on an element your app renders while it shows one
 * thing full-screen with its own way back (an open conversation, a document
 * being edited). On a phone the host then hides its app bar and gives that
 * room to your view; on larger screens it changes nothing.
 *
 * ```tsx
 * <div {...(open ? { [IMMERSIVE_ATTRIBUTE]: "" } : {})}>…</div>
 * ```
 */
export const IMMERSIVE_ATTRIBUTE = "data-mycel-immersive";
