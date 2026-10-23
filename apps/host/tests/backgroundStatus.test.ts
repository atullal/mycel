import assert from "node:assert/strict";
import test from "node:test";
import { backgroundCopy, vendorTip, type BackgroundStatus } from "../src/backgroundStatus.ts";

const base: BackgroundStatus = {
  platform: "android",
  mode: "always",
  batteryUnrestricted: false,
  backgroundRestricted: false,
  standbyBucket: "active",
  manufacturer: "google",
  lastCatchUp: null,
};

test("iOS is honest: slow mode, no button, no promise of instant delivery", () => {
  const copy = backgroundCopy({ ...base, platform: "ios", mode: "slow", batteryUnrestricted: null, manufacturer: null });
  assert.match(copy.text, /may wait until you open Mycel/);
  assert.equal(copy.button, null);
  assert.ok(copy.details.some((d) => /no push server/.test(d)));
  assert.ok(copy.details.some((d) => /Swiping Mycel away/.test(d)));
  assert.ok(!copy.details.some((d) => /Last background check/.test(d)), "nothing to report yet");
});

test("iOS reports the last background check in plain words", () => {
  const now = 10 * 3_600_000;
  const at = (ms: number) => backgroundCopy({ ...base, platform: "ios", mode: "slow", lastCatchUp: now - ms }, now).details.at(-1);
  assert.equal(at(10_000), "Last background check: just now.");
  assert.equal(at(5 * 60_000), "Last background check: 5 min ago.");
  assert.equal(at(3 * 3_600_000), "Last background check: 3 h ago.");
});

test("Android explains before offering the battery prompt, and only while optimised", () => {
  const restricted = backgroundCopy(base);
  assert.equal(restricted.button, "Allow background use");
  assert.ok(restricted.details.some((d) => /no push server/.test(d)));
  assert.ok(restricted.details.some((d) => /change it back/.test(d)), "says it's reversible");
  const allowed = backgroundCopy({ ...base, batteryUnrestricted: true });
  assert.equal(allowed.button, null);
  assert.match(allowed.text, /stays connected/);
});

test("a user restriction or the restricted bucket is called out with the way out", () => {
  const blocked = backgroundCopy({ ...base, batteryUnrestricted: true, backgroundRestricted: true });
  assert.match(blocked.text, /stopping Mycel/);
  assert.ok(blocked.details.some((d) => /Unrestricted/.test(d)));
  const idle = backgroundCopy({ ...base, standbyBucket: "restricted" });
  assert.ok(idle.details.some((d) => /wasn't opened for a while/.test(d)));
});

test("vendor tips cover the usual app killers and their sister brands, and nothing else", () => {
  for (const vendor of ["samsung", "Xiaomi", "redmi", "POCO", "huawei", "honor", "oneplus", "oppo", "realme"]) {
    assert.ok(vendorTip(vendor), vendor);
  }
  assert.equal(vendorTip("google"), null);
  assert.equal(vendorTip(null), null);
  assert.match(backgroundCopy({ ...base, manufacturer: "samsung", batteryUnrestricted: true }).tip ?? "", /Never sleeping/);
});

test("computers have nothing to ask for", () => {
  const copy = backgroundCopy({ ...base, platform: "desktop", batteryUnrestricted: null });
  assert.equal(copy.button, null);
  assert.equal(copy.tip, null);
});
