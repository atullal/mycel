import { test } from "node:test";
import { strict as assert } from "node:assert";
import { conversationInView, keepsSystemMenu, videoLayout } from "../src/layout.ts";

test("right-click keeps the system menu for selected text, links and media only", () => {
  assert.equal(keepsSystemMenu({ selectionInMessage: true, linkOrMedia: false }), true);
  assert.equal(keepsSystemMenu({ selectionInMessage: false, linkOrMedia: true }), true);
  assert.equal(keepsSystemMenu({ selectionInMessage: false, linkOrMedia: false }), false);
});

test("video sits above the chat on wide screens and takes over only on phones", () => {
  assert.equal(videoLayout(false, false), "inline");
  assert.equal(videoLayout(false, true), "inline");
  assert.equal(videoLayout(true, false), "expanded");
  assert.equal(videoLayout(true, true), "floating");
});

test("a details panel beside the chat leaves it in view; one drawn over it does not", () => {
  const base = { hostVisible: true, composing: false, videoLayout: null, membersOpen: false, panelOverChat: false } as const;
  assert.equal(conversationInView(base), true);
  assert.equal(conversationInView({ ...base, membersOpen: true }), true);
  assert.equal(conversationInView({ ...base, membersOpen: true, panelOverChat: true }), false);
  assert.equal(conversationInView({ ...base, panelOverChat: true }), true);
});

test("host panels, the new-chat dialog and a full-screen call hide the chat; inline or floating video does not", () => {
  const base = { hostVisible: true, composing: false, videoLayout: null, membersOpen: false, panelOverChat: false } as const;
  assert.equal(conversationInView({ ...base, hostVisible: false }), false);
  assert.equal(conversationInView({ ...base, composing: true }), false);
  assert.equal(conversationInView({ ...base, videoLayout: "expanded" }), false);
  assert.equal(conversationInView({ ...base, videoLayout: "inline" }), true);
  assert.equal(conversationInView({ ...base, videoLayout: "floating" }), true);
});
