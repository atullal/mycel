// Identity of a conversation in the UI. One person can end up with several
// direct-chat spaces (each side started one before they synced); the runtime
// shows them as one conversation with a canonical `id`, the other spaces as
// `aliases`, and a `threadKey` that stays the same whichever space is
// canonical. Older runtimes send an empty `threadKey` and no aliases.

import type { ConversationId, ConversationSummary } from "./types.ts";

/**
 * The key for UI state that belongs to the conversation rather than to one
 * of its spaces (React keys, loaded history, scroll position).
 */
export function threadKeyOf(c: Pick<ConversationSummary, "id" | "threadKey">): string {
  return c.threadKey || c.id;
}

/** True when `id` (say, a remembered selection or a notification's target) names this conversation. */
export function isConversation(c: Pick<ConversationSummary, "id" | "aliases">, id: ConversationId | null | undefined): boolean {
  return id != null && (c.id === id || c.aliases.includes(id));
}
