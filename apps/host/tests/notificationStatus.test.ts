import assert from "node:assert/strict";
import test from "node:test";
import { notificationStatus } from "../src/notificationStatus.ts";

test("a platform without a permission to check gets an explanation and no dead-end button", () => {
  const status = notificationStatus("unavailable");
  assert.equal(status.button, null);
  assert.match(status.text, /can't check/);
});

test("prompts offer to enable, failures offer a retry, granted offers nothing", () => {
  assert.equal(notificationStatus("prompt").button, "Enable notifications");
  assert.equal(notificationStatus("prompt-with-rationale").button, "Enable notifications");
  assert.equal(notificationStatus("error").button, "Try again");
  assert.equal(notificationStatus("granted").button, null);
  assert.equal(notificationStatus("checking").button, null);
});
