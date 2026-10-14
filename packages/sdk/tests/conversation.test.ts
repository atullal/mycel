import { test } from "node:test";
import { strict as assert } from "node:assert";
import { isConversation, threadKeyOf } from "../src/conversation.ts";

test("an empty thread key falls back to the conversation id", () => {
  assert.equal(threadKeyOf({ id: "a1", threadKey: "direct:xyz" }), "direct:xyz");
  assert.equal(threadKeyOf({ id: "a1", threadKey: "" }), "a1");
});

test("a conversation answers to its id and to every alias, never to nothing", () => {
  const c = { id: "a1", aliases: ["a1", "b2"] };
  assert.equal(isConversation(c, "a1"), true);
  assert.equal(isConversation(c, "b2"), true);
  assert.equal(isConversation(c, "c3"), false);
  assert.equal(isConversation(c, null), false);
  assert.equal(isConversation({ id: "a1", aliases: [] }, "a1"), true);
});
