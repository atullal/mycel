import { test } from "node:test";
import { strict as assert } from "node:assert";
import { deliveryLabel } from "../src/delivery.ts";

test("a carried message says who holds it, between saved and sent", () => {
  assert.equal(deliveryLabel("local"), "Saved on this device");
  assert.equal(deliveryLabel("carried", 3), "Waiting for the recipient — carried by 3 devices");
  assert.equal(deliveryLabel("carried", 1), "Waiting for the recipient — carried by 1 device");
  assert.equal(deliveryLabel("carried"), "Waiting for the recipient — carried by other devices");
  assert.equal(deliveryLabel("sent", 3), "Sent");
  assert.equal(deliveryLabel("read"), "Read by everyone");
});
