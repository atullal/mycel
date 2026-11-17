import { test } from "node:test";
import { strict as assert } from "node:assert";
import { relayLines } from "../src/panels/relayText.ts";

const none = { relaying: false, clients: 0, relays: [], metered: false };

test("a device that neither relays nor is relayed for says nothing", () => {
  assert.deepEqual(relayLines(none), []);
});

test("a relay says how many devices it relays for, and that its address is public", () => {
  const idle = relayLines({ ...none, relaying: true });
  assert.equal(idle.length, 2);
  assert.match(idle[0], /can be reached from the internet/);
  assert.match(idle[1], /address is public/);
  assert.match(relayLines({ ...none, relaying: true, clients: 1 })[0], /^Relaying for 1 device that/);
  assert.match(relayLines({ ...none, relaying: true, clients: 3 })[0], /^Relaying for 3 devices that/);
});

test("a device behind a router names the devices that pass connections on to it", () => {
  assert.deepEqual(relayLines({ ...none, relays: ["Ines's laptop", "Keeper"] }), [
    "The internet can't reach this device directly: Ines's laptop and Keeper pass connections on to it.",
  ]);
});

test("on mobile data it says it carries nobody else's traffic", () => {
  assert.deepEqual(relayLines({ ...none, metered: true }), ["On mobile data: not carrying anyone else's traffic."]);
});
