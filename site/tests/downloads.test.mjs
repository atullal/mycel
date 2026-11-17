import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const site = fileURLToPath(new URL('..', import.meta.url));
async function build(t, names) {
  const root = await mkdtemp(join(tmpdir(), 'mycel-site-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, 'site/assets'), { recursive: true });
  await mkdir(join(root, 'docs/screenshots'), { recursive: true });
  for (const file of ['build.mjs', 'index.html', 'style.css', 'site.js']) {
    await copyFile(join(site, file), join(root, 'site', file));
  }
  const fixture = join(root, 'release.json');
  await writeFile(fixture, JSON.stringify({
    tag_name: 'v0.1.0', published_at: '2026-11-17T12:00:00Z',
    html_url: 'https://github.com/atullal/mycel/releases/tag/v0.1.0',
    assets: names.map(name => ({ name, size: 1000000,
      browser_download_url: `https://example.com/${name}` })),
  }));
  execFileSync(process.execPath, [join(root, 'site/build.mjs')], {
    env: { ...process.env, SITE_RELEASE_JSON: fixture },
  });
  return readFile(join(root, 'site/dist/index.html'), 'utf8');
}

test('legacy unsigned Mac downloads are excluded while other systems remain', async t => {
  const page = await build(t, ['Mycel_0.1.0_universal.dmg', 'Mycel_0.1.0_x64-setup.exe']);
  assert.doesNotMatch(page, /href="https:\/\/example.com\/Mycel_0.1.0_universal.dmg"/);
  assert.match(page, /A signed Mac download is not available/);
  assert.match(page, /Mycel_0.1.0_x64-setup.exe/);
  assert.match(page, /data-system="mac" href="#download"/);
  assert.match(page, /data-system="windows"[^>]+ hidden/);
  assert.doesNotMatch(page, /xattr|right-click Mycel/);
});

test('verified Mac package is offered with installation instructions', async t => {
  const page = await build(t, ['Mycel_0.1.0_universal_notarized.dmg']);
  assert.match(page, /Download for macOS/);
  assert.match(page, /href="https:\/\/example.com\/Mycel_0.1.0_universal_notarized.dmg"/);
  assert.match(page, /signed and notarized by Apple/);
  assert.doesNotMatch(page, /not available|not signed yet|xattr/);
});

test('mixed releases select the verified DMG', async t => {
  const page = await build(t, ['Mycel_0.1.0_universal.dmg', 'Mycel_0.1.0_universal_notarized.dmg']);
  assert.match(page, /_universal_notarized.dmg/);
  assert.doesNotMatch(page, /href="https:\/\/example.com\/Mycel_0.1.0_universal.dmg"/);
});

test('a release with only unsigned Mac files has no direct download', async t => {
  const page = await build(t, ['Mycel_0.1.0_universal.dmg']);
  assert.doesNotMatch(page, /https:\/\/example.com/);
  assert.match(page, /No build is published for download yet/);
});
