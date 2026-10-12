/** Reachability describes the current route, not whether a device is powered on. */
export type Presence = "nearby" | "online" | "offline";

export const PRESENCE_LABEL: Record<Presence, string> = {
  nearby: "Nearby",
  online: "Online",
  offline: "Not reachable",
};

export function presenceOf(contact: { nearby: boolean; online: boolean }): Presence {
  return contact.nearby ? "nearby" : contact.online ? "online" : "offline";
}

/** Resolve by signing identity. A name, group membership, or absent contact is not presence evidence. */
export function directPresence(
  conversation: { direct: boolean; members: { id: string; isMe: boolean; role: string }[] },
  contacts: ReadonlyMap<string, { nearby: boolean; online: boolean }>,
): Presence | undefined {
  if (!conversation.direct) return undefined;
  const other = conversation.members.find((m) => !m.isMe && m.role !== "keeper");
  const contact = other && contacts.get(other.id);
  return contact ? presenceOf(contact) : undefined;
}
