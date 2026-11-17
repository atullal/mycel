#!/usr/bin/env node
// Builds the website into site/dist. No dependencies: Node 22 or later.
//
//   node site/build.mjs
//
// The download links come from the newest release on GitHub (a full release
// if there is one, otherwise the newest pre-release). GITHUB_TOKEN, if set,
// is used for that one request; GITHUB_REPOSITORY names the repository.
// SITE_RELEASE_JSON=<file> reads a saved release instead of asking GitHub
// (for working on the page offline).

import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const out = join(here, 'dist');
const repo = process.env.GITHUB_REPOSITORY || 'atullal/mycel';
const repoUrl = `https://github.com/${repo}`;

// Whether the Mac app in the release is signed with a Developer ID and
// notarised. Until it is, the page says how to open it.
const MAC_SIGNED = false;

/** Each system, what its builds are called in a release, and what it needs. */
const SYSTEMS = [
  {
    id: 'mac',
    name: 'macOS',
    needs: 'macOS 11 or later, Apple silicon and Intel',
    files: [[/_universal\.dmg$/, 'Disk image']],
  },
  {
    id: 'windows',
    name: 'Windows',
    needs: 'Windows 10 or later, 64-bit',
    files: [
      [/-setup\.exe$/, 'Installer'],
      [/\.msi$/, 'MSI'],
    ],
  },
  {
    id: 'linux',
    name: 'Linux',
    needs: 'x86-64, glibc 2.35 or later',
    files: [
      [/\.AppImage$/, 'AppImage'],
      [/\.deb$/, '.deb'],
      [/\.rpm$/, '.rpm'],
    ],
  },
  {
    id: 'android',
    name: 'Android',
    needs: 'Android 9 or later',
    files: [[/_android\.apk$/, 'APK']],
  },
];

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const megabytes = (bytes) => `${Math.max(1, Math.round(bytes / 1e6))} MB`;

async function newestRelease() {
  if (process.env.SITE_RELEASE_JSON) {
    return JSON.parse(await readFile(process.env.SITE_RELEASE_JSON, 'utf8'));
  }
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'mycel-site-build' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=30`, { headers });
    if (!res.ok) throw new Error(`GitHub answered ${res.status}`);
    const releases = (await res.json()).filter((r) => !r.draft);
    return releases.find((r) => !r.prerelease) ?? releases[0] ?? null;
  } catch (e) {
    console.warn(`no release information (${e.message}): the page will link to the releases list`);
    return null;
  }
}

/** The builds in a release, by system. */
function buildsIn(release) {
  const found = [];
  for (const system of SYSTEMS) {
    const files = [];
    for (const [pattern, label] of system.files) {
      const asset = release?.assets?.find((a) => pattern.test(a.name));
      if (asset) files.push({ label, url: asset.browser_download_url, size: asset.size });
    }
    if (files.length) found.push({ ...system, files });
  }
  return found;
}

function versionOf(release) {
  if (!release) return null;
  // "v1.2.3" is the version; a dated development tag takes it from a file name.
  const fromTag = /^v(\d+\.\d+\.\d+\S*)$/.exec(release.tag_name)?.[1];
  const fromFile = release.assets?.map((a) => /_(\d+\.\d+\.\d+)_/.exec(a.name)?.[1]).find(Boolean);
  return fromTag ?? fromFile ?? release.tag_name;
}

const dateOf = (release) =>
  new Date(release.published_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });

function heroDownload(release, builds, version) {
  const mac = builds.find((b) => b.id === 'mac');
  const first = mac ?? builds[0];
  if (!first) {
    return `<p class="get"><a class="button" id="get" href="${repoUrl}/releases"><span class="what">See the releases</span></a></p>
    <p class="fine">Experimental preview. No build is published for download yet;
      <a href="${repoUrl}#build-from-source">building from source</a> takes a few minutes.</p>`;
  }
  return `<p class="get"><a class="button" id="get" href="${esc(first.files[0].url)}"><span class="what">Download for ${esc(first.name)}</span> <span class="v">${esc(version)}</span></a></p>
    <p class="fine"><span id="get-needs">${esc(first.needs)}</span>. Experimental preview:
      <a href="#status">read this first</a>. <a href="#download">Other systems</a>.</p>`;
}

function downloads(release, builds, version) {
  if (!builds.length) {
    return `<p class="release">No build is published for download yet. The
    <a href="${repoUrl}/releases">releases list</a> has what there is, and
    <a href="${repoUrl}#build-from-source">building from source</a> takes a few minutes.</p>`;
  }
  const rows = builds
    .map(
      (b) => `    <li>
      <span class="os">${esc(b.name)}</span>
      <span class="files">${b.files
        .map((f) => `<span class="file"><a href="${esc(f.url)}">${esc(f.label)}</a> <span class="size">${megabytes(f.size)}</span></span>`)
        .join(' ')}</span>
      <span class="needs">${esc(b.needs)}</span>
    </li>`,
    )
    .join('\n');
  const sums = release.assets.find((a) => /^SHA256SUMS/.test(a.name));
  const after = [];
  if (!MAC_SIGNED && builds.some((b) => b.id === 'mac')) {
    after.push(`<p><strong>The Mac app is not signed yet.</strong> The first time, right-click Mycel in
      Applications and choose Open. If macOS says the app is damaged, run
      <code>xattr -dr com.apple.quarantine /Applications/Mycel.app</code> in Terminal.</p>`);
  }
  if (builds.some((b) => b.id === 'windows')) {
    after.push(`<p><strong>Windows shows a SmartScreen warning,</strong> because the installer is not
      signed: choose More info, then Run anyway.</p>`);
  }
  after.push(`<p><strong>iPhone and iPad</strong> need a build signed with your own Apple developer
      account: see <a href="${repoUrl}/blob/main/docs/PLATFORMS.md">the platform notes</a>.</p>`);
  after.push(
    sums
      ? `<p><strong>Check what you downloaded</strong> against <a href="${esc(sums.browser_download_url)}">SHA256SUMS</a>,
      or its build provenance with <code>gh attestation verify &lt;file&gt; --repo ${esc(repo)}</code>.</p>`
      : `<p>Every build, with its notes, is on the <a href="${esc(release.html_url)}">release page</a>.</p>`,
  );
  return `<p class="release">Version ${esc(version)}, ${esc(dateOf(release))}.
    <a href="${esc(release.html_url)}">Release notes</a>.
    <a href="${repoUrl}/releases">Older versions</a>.</p>
  <ul class="builds">
${rows}
  </ul>
  <div class="after">
    ${after.join('\n    ')}
  </div>`;
}

const release = await newestRelease();
const builds = buildsIn(release);
const version = versionOf(release);

// What the page's script needs to offer the visitor's own system.
const forScript = Object.fromEntries(
  builds.map((b) => [b.id, { url: b.files[0].url, label: `Download for ${b.name}`, needs: b.needs }]),
);

let page = await readFile(join(here, 'index.html'), 'utf8');
const fill = {
  HERO_DOWNLOAD: heroDownload(release, builds, version),
  DOWNLOADS: downloads(release, builds, version),
  BUILDS_JSON: JSON.stringify(forScript).replace(/</g, '\\u003c'),
  REPO_URL: repoUrl,
};
for (const [key, value] of Object.entries(fill)) page = page.replaceAll(`{{${key}}}`, value);
const left = page.match(/\{\{[A-Z_]+\}\}/);
if (left) throw new Error(`unfilled placeholder ${left[0]}`);

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });
await writeFile(join(out, 'index.html'), page);
for (const file of ['style.css', 'site.js']) await cp(join(here, file), join(out, file));
await cp(join(here, 'assets'), join(out, 'assets'), { recursive: true });
await cp(join(root, 'docs', 'screenshots'), join(out, 'screenshots'), { recursive: true });
// GitHub Pages runs Jekyll unless told not to.
await writeFile(join(out, '.nojekyll'), '');

console.log(
  release
    ? `built site/dist for ${release.tag_name} (${builds.map((b) => b.name).join(', ') || 'no builds'})`
    : 'built site/dist without a release',
);
