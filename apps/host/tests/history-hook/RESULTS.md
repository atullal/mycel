# useMessages actual-hook browser regression

Run 2026-10-12 through local Vite port 1422 and Codex CUA in-app browser. Actual `packages/sdk/react/index.ts` hook, actual React, fake deferred client, original message space ID `original-B`.

All assertions passed:
- Initial two-message page exposes hasMore.
- Canonical B to A within stable thread key retains original-space messages during loading.
- loadOlder retains current history and hasMore while pending.
- Expanded request asks for five records (four-page window plus sentinel).
- Completed expanded page returns four messages and hasMore false.
- Changing logical thread immediately hides previous thread history.
- Resolving stale prior-thread request does not display stale messages.
- New thread renders only its own response.

Server stopped and temporary browser tab closed after verification. No production changes.

Reproduce from apps/host: `../../node_modules/.bin/vite tests/history-hook --host 127.0.0.1 --port 1422 --strictPort`, open URL, click Run regression once.
