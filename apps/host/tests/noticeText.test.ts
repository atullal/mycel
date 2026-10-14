import assert from "node:assert/strict";
import test from "node:test";
import { noticeView, withoutPaths } from "../src/noticeText.ts";

test("each notice says what happened; only a failing disk stays up", () => {
  const replaced = noticeView({ kind: "identityReplaced", keptIn: "/data/profile-old" });
  assert.match(replaced.text, /new one was started/);
  assert.match(replaced.text, /kept in \/data\/profile-old\./);
  assert.equal(replaced.ongoing, false);

  const reset = noticeView({ kind: "networkModeReset" });
  assert.match(reset.text, /Local only/);
  assert.equal(reset.action, "network");

  assert.match(noticeView({ kind: "recordsSetAside", count: 1 }).text, /^1 damaged stored record was set aside/);
  assert.match(noticeView({ kind: "recordsSetAside", count: 3 }).text, /^3 damaged stored records were set aside/);

  const failing = noticeView({ kind: "storageFailing", error: "No space left on device (os error 28)" });
  assert.equal(failing.ongoing, true);
  assert.match(failing.text, /No space left on device \(os error 28\)/);
  assert.match(failing.text, /can't be sent until it recovers/);
});

test("a dismissed notice stays dismissed only while it's the same notice", () => {
  assert.equal(noticeView({ kind: "recordsSetAside", count: 2 }).key, noticeView({ kind: "recordsSetAside", count: 2 }).key);
  assert.notEqual(noticeView({ kind: "recordsSetAside", count: 2 }).key, noticeView({ kind: "recordsSetAside", count: 5 }).key);
});

test("storage errors lose their file paths, including paths with spaces", () => {
  assert.equal(
    withoutPaths("open /Users/ana/Library/Application Support/dev.mycel.host/mycel.redb: No space left on device (os error 28)"),
    "open …: No space left on device (os error 28)",
  );
  assert.equal(withoutPaths("can't write 'C:\\Users\\ana\\AppData\\Roaming\\mycel.redb': disk full"), "can't write '…': disk full");
  assert.equal(withoutPaths("I/O error: Input/output error"), "I/O error: Input/output error");
  assert.equal(withoutPaths("injected commit failure"), "injected commit failure");
  assert.equal(withoutPaths("Database already open (3 received records will be fetched again)"), "Database already open (3 received records will be fetched again)");
});
