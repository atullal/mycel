import { test } from "node:test";
import { strict as assert } from "node:assert";
import { directPresence, presenceOf, PRESENCE_LABEL } from "../src/presence.ts";

test("reachability moves from unavailable to remote to nearby and back", () => {
  assert.equal(presenceOf({ nearby: false, online: false }), "offline");
  assert.equal(PRESENCE_LABEL.offline, "Not reachable");
  assert.equal(presenceOf({ nearby: false, online: true }), "online");
  assert.equal(presenceOf({ nearby: true, online: true }), "nearby");
  assert.equal(presenceOf({ nearby: true, online: false }), "nearby");
});

test("a direct chat uses the other person's identity and never labels unknown people unreachable", () => {
  const members = [
    { id: "self", isMe: true, role: "member" },
    { id: "keeper", isMe: false, role: "keeper" },
    { id: "other", isMe: false, role: "member" },
  ];
  const contacts = new Map([
    ["self", { nearby: true, online: true }],
    ["keeper", { nearby: true, online: true }],
    ["other", { nearby: false, online: false }],
  ]);
  assert.equal(directPresence({ direct: true, members }, contacts), "offline");
  assert.equal(directPresence({ direct: false, members }, contacts), undefined);
  contacts.delete("other");
  assert.equal(directPresence({ direct: true, members }, contacts), undefined);
});
