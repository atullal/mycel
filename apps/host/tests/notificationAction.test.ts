import assert from "node:assert/strict";
import test from "node:test";
import { notificationActionId } from "../src/notificationAction.ts";

test("accepts live iOS taps and restored opaque notification identifiers", () => {
  assert.equal(notificationActionId({ actionId: "tap", notification: { id: 42 } }), 42);
  assert.equal(notificationActionId({ id: 2147483647 }), 2147483647);
});

test("dismissal, malformed payloads and invalid IDs cannot open a conversation", () => {
  for (const payload of [null, undefined, "42", {}, { actionId: "dismiss", notification: { id: 42 } },
    { notification: "42" }, ...[0, -1, 1.5, NaN, Infinity, 2147483648, "42"].map(id => ({ id }))]) {
    assert.equal(notificationActionId(payload), null);
  }
});
