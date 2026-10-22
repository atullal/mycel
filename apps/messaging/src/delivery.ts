import type { MessageView } from "@mycel/sdk";

/** The words for a delivery state (tooltip and screen readers). */
export function deliveryLabel(delivery: MessageView["delivery"], carriedBy = 0): string {
  switch (delivery) {
    case "local":
      return "Saved on this device";
    case "carried":
      return carriedBy > 0
        ? `Waiting for the recipient \u2014 carried by ${carriedBy} ${carriedBy === 1 ? "device" : "devices"}`
        : "Waiting for the recipient \u2014 carried by other devices";
    case "sent":
      return "Sent";
    case "delivered":
      return "Delivered to everyone";
    case "read":
      return "Read by everyone";
  }
}
