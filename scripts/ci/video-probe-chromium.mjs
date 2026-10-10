// Run video-probe.html in a Chromium browser (CI: headless Edge, the engine
// under WebView2) with Chromium's fake camera, and print what it found.
// Exits 1 if no video came out. The page's title carries the result, read
// from the DevTools target list.
//
//   node scripts/ci/video-probe-chromium.mjs "<path to msedge or chrome>"

import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const browser = process.argv[2];
const page = pathToFileURL(resolve(import.meta.dirname, "video-probe.html")).href;
const port = 9333;
const proc = spawn(
  browser,
  [
    "--headless=new",
    `--remote-debugging-port=${port}`,
    "--use-fake-device-for-media-stream",
    "--use-fake-ui-for-media-stream",
    `--user-data-dir=${mkdtempSync(join(tmpdir(), "video-probe-"))}`,
    page,
  ],
  { stdio: "ignore" },
);

// the list escapes titles as HTML
const unescape = (s) =>
  s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

let result = null;
for (let i = 0; i < 60 && !result; i++) {
  await new Promise((ok) => setTimeout(ok, 1000));
  try {
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const t = targets.find((t) => typeof t.title === "string" && unescape(t.title).startsWith("probe "));
    if (t) result = JSON.parse(unescape(t.title).slice("probe ".length));
  } catch {
    // not up yet
  }
}
proc.kill();
console.log(JSON.stringify(result ?? { error: "no result from the probe page" }, null, 2));
process.exit(result?.ok ? 0 : 1);
