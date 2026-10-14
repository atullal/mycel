import { test } from "node:test";
import { strict as assert } from "node:assert";
import { createMycel } from "../src/client.ts";
import { createMockTransport } from "../src/mock.ts";

test("cursor pages and windows reach any message without loading the history", async () => {
  const transport = createMockTransport({ latency: [0, 0], ambient: false, replies: false });
  const mycel = createMycel(transport);
  try {
    const [person] = await mycel.contacts.list();
    assert.ok(person);
    const chat = await mycel.chat.create("Paging", [person.id]);
    for (let n = 0; n < 120; n++) await mycel.chat.send(chat.id, `m${n}`);
    const bodies = (list: { body: string }[]) => list.map((m) => m.body);

    // "Show earlier messages": each page starts from the oldest one shown.
    let shown = await mycel.chat.messages(chat.id, { limit: 50 });
    assert.deepEqual(bodies(shown).slice(-2), ["m118", "m119"]);
    for (;;) {
      const page = await mycel.chat.messages(chat.id, { limit: 50, before: shown[0]!.id });
      if (!page.length) break;
      shown = [...page, ...shown];
    }
    assert.deepEqual(bodies(shown), Array.from({ length: 120 }, (_, n) => `m${n}`));

    // A search hit far back opens in one fetch, with more on both sides.
    const hit = shown[10]!;
    const window = await mycel.chat.around(chat.id, hit.id, { before: 3, after: 2 });
    assert.deepEqual(bodies(window.messages), ["m7", "m8", "m9", "m10", "m11", "m12"]);
    assert.equal(window.hasEarlier, true);
    assert.equal(window.hasLater, true);
    const edge = await mycel.chat.around(chat.id, shown[1]!.id, { before: 5, after: 200 });
    assert.equal(edge.messages.length, 120);
    assert.equal(edge.hasEarlier, false);
    assert.equal(edge.hasLater, false);
    await assert.rejects(mycel.chat.around(chat.id, "00".repeat(32)));
  } finally {
    transport.dispose();
  }
});
