# @mycel/sdk

`@mycel/sdk` is the TypeScript client for the Mycel runtime, with React
hooks on top. An app is written against it: the app calls the client, and
the client passes each call to the runtime, which holds the keys, the data
and the network connections. This README is for people who write or change
an app, or the host UI, in this repository.

The package is private to this repository and is not published to npm. It
exports its TypeScript source, so it has no build step. It has two entry
points. Only the second needs React, which is an optional peer dependency.

| Import | Contents |
|---|---|
| `@mycel/sdk` | the client, the types, the transports and a few helpers |
| `@mycel/sdk/react` | React hooks over the client, and the `SearchField` component |

## Use it in an app

An app is an npm workspace under `apps/` that lists `@mycel/sdk` in its
dependencies, as `apps/messaging/package.json` does. Messaging imports
nothing else from Mycel: no Tauri API, no keys, no network access. The host
(`apps/host`) renders the app, and uses the same hooks for its own panels.

A component reads state through a hook and changes it through the client:

```tsx
import { useState } from "react";
import { threadKeyOf, type ConversationSummary } from "@mycel/sdk";
import { useMessages, useMycel } from "@mycel/sdk/react";

export function Chat({ summary }: { summary: ConversationSummary }) {
  const mycel = useMycel();
  const { messages, hasMore, loadOlder } = useMessages(summary.id, undefined, threadKeyOf(summary));
  const [text, setText] = useState("");

  const send = async () => {
    const body = text.trim();
    if (!body) return;
    await mycel.chat.send(summary.id, body);
    setText("");
  };

  return (
    <>
      {hasMore && <button onClick={() => loadOlder()}>Earlier messages</button>}
      {messages.map((m) => (
        <p key={m.id}>{m.authorName}: {m.body}</p>
      ))}
      <input value={text} onChange={(e) => setText(e.target.value)} />
      <button onClick={() => void send()}>Send</button>
    </>
  );
}
```

Each hook loads its data once, then loads it again when a runtime event says
the data may have changed. The component above shows a new message without
subscribing to anything. Client methods return promises, and reject with an
`Error` that carries the runtime's error text.

## The client

`mycel` is the default client, created on first use over the transport that
`autoTransport()` picks. In React, `useMycel()` returns it.

Its methods call the runtime's commands, and are grouped as `profile`,
`contacts`, `nearby`, `network`, `notices`, `chat` and `calls`. It also has:

- `on(type, handler)`, which subscribes to one type of runtime event, or to
  every type with `"*"`, and returns an unsubscribe function;
- `files`, the host's file services: a file picker, staging for pasted or
  dropped files, and URLs for local files;
- `transport`, the transport in use.

[RUNTIME_API.md](../../docs/RUNTIME_API.md) is the reference for the
commands, events and types, and names the client method for each command.
The TypeScript types are in `src/types.ts`.

To use a different client, build one with `createMycel(transport)`. Then
make it the default with `setMycel(client)`, or pass it to the hooks with
`MycelProvider`.

## Transports

A transport carries commands to a runtime and events back. `autoTransport()`
picks the first of these that applies:

| `transport.kind` | Picked when | Commands and events |
|---|---|---|
| `tauri` | the page runs in the host's web view | Tauri IPC; events arrive on `mycel://event` |
| `http` | the page was served by `mycel serve` | `POST /api/cmd/<command>`; Server-Sent Events on `/api/events` |
| `mock` | anything else, such as `npm run dev` | an in-memory runtime inside the page |

The Tauri transport (`src/tauri.ts`) uses the native file dialog and
receives video frames over a Tauri channel. On Android, Windows and Linux
the host has no camera of its own, so during a call this transport also
captures and encodes the camera in the web view.

The HTTP transport (`src/http.ts`) talks to the local API of `mycel serve`.
The server writes a per-run token into the page it serves, and the transport
sends it with every request. Files the user picks are uploaded first.

The mock (`src/mock.ts`) implements every command and simulates a small
network: contacts who reply and type, delivery receipts that progress,
people who appear nearby, attachments that download, and a group you get
added to. `npm run dev` serves the host UI over it, on
<http://localhost:1420>. It sends nothing out of the page and saves nothing.

## React hooks

| Hook | Gives you |
|---|---|
| `useMycel()` | the client: the one from `MycelProvider`, or the default |
| `useProfile()` | `profile`, and `setName(name)` |
| `useContacts()` | `contacts` |
| `useNearby()` | `nearby`, the people advertising on the local network |
| `useNetwork()` | `status`, the network status |
| `useNotices()` | `notices`, the problems to tell the user about |
| `useConversations()` | `conversations`, newest activity first |
| `useConversation(id)` | `conversation`, or `null` |
| `useMessages(id, pageSize?, threadKey?)` | `messages`, oldest first, with paging: `loadOlder`, `loadNewer`, `showMessage`, `showLatest` |
| `useTyping(id)` | the ids of the people typing in a conversation |
| `useTransfer(id)` | the progress of one attachment transfer, or `null` |
| `useCalls()` | the calls on this device, newest first |
| `useVideoCanvas(canvas, options)` | draws one video stream of a call on a canvas |
| `useMycelQuery(fetcher, deps, refreshOn)` | the building block: fetch, then fetch again on matching events |

The hooks are in `react/index.ts`. Those that fetch also return `loading`,
`error` and `refresh`.

## Tests

```sh
npm test -w @mycel/sdk            # the node:test suites in tests/
npm run typecheck -w @mycel/sdk
```

The tests run in Node 22.18 or later, on its built-in type stripping. A test
that needs a runtime builds a client over the mock with the background
activity off, and stops the mock's timers at the end:

```ts
const transport = createMockTransport({ latency: [0, 0], ambient: false, replies: false });
const mycel = createMycel(transport);
// ...
transport.dispose();
```
