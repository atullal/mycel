import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { completesReply, replyDistance } from '../src/messageGesture.ts';

test('only deliberate rightward swipes reply', () => {
  assert.equal(completesReply(60, 8), true);
  assert.equal(completesReply(-90, 0), false);
  assert.equal(completesReply(20, 0), false);
  assert.equal(completesReply(60, 50), false);
  assert.equal(completesReply(10, 120), false);
  assert.equal(replyDistance(200, 5), 80);
});
