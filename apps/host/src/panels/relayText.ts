import type { RelayInfo } from "@mycel/sdk";

/** What the device does for others over the internet, and who does it for this one. */
export function relayLines(relay: RelayInfo): string[] {
  const lines: string[] = [];
  if (relay.relaying) {
    const who = relay.clients === 1 ? "1 device" : `${relay.clients} devices`;
    lines.push(
      relay.clients > 0
        ? `Relaying for ${who} that can't be reached directly. It can't read what it passes on.`
        : "This device can be reached from the internet, so it relays for devices that can't. It can't read what it passes on.",
    );
    lines.push("While it relays, its internet address is public to anyone who has its contact code.");
  }
  if (relay.relays.length > 0) {
    lines.push(`The internet can't reach this device directly: ${relay.relays.join(" and ")} pass connections on to it.`);
  }
  if (relay.metered) {
    lines.push("On mobile data: not carrying anyone else's traffic.");
  }
  return lines;
}
