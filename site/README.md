# The Mycel website

One static page: what Mycel is, the downloads of the newest release, and its
status. It uses the app's own theme (`apps/host/src/theme.css`) and loads
nothing from other sites.

```sh
node site/build.mjs                 # writes site/dist
python3 -m http.server -d site/dist # http://localhost:8000
```

`build.mjs` has no dependencies (Node 22 or later). It asks GitHub for the
newest release and writes the download links into the page; without network
access the page links to the releases list instead. `SITE_RELEASE_JSON=<file>`
builds from a saved release.

| File | What it is |
|---|---|
| `index.html` | the page, with `{{PLACEHOLDERS}}` that `build.mjs` fills |
| `style.css` | the theme tokens and layout |
| `site.js` | offers the build for the visitor's system; animates the mesh drawing |
| `build.mjs` | the build; `MAC_SIGNED` says whether to show how to open an unsigned Mac app |

The Site workflow (`.github/workflows/site.yml`) builds the page on pull
requests and publishes it to GitHub Pages from `main` and when a release
changes.
