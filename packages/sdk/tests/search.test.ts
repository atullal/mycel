import { test } from "node:test";
import { strict as assert } from "node:assert";
import { matchesSearch } from "../src/search.ts";

test("every term must match, in any order and any field", () => {
  assert.equal(matchesSearch("ana lima", "Ana", "Lima"), true);
  assert.equal(matchesSearch("lima ana", "Ana Lima"), true);
  assert.equal(matchesSearch("ana rio", "Ana Lima"), false);
});

test("case and accents are ignored, an empty query matches everything", () => {
  assert.equal(matchesSearch("ZOE", "Zoë"), true);
  assert.equal(matchesSearch("zoë", "Zoe"), true);
  assert.equal(matchesSearch("", "anything"), true);
  assert.equal(matchesSearch("   ", "anything"), true);
});
