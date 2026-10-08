// React bindings for @mycel/sdk. Every hook loads once, then refreshes on the
// runtime events that can change its data.

import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { getMycel, type Mycel } from "../src/client.ts";
import type {
  CallId,
  CallInfo,
  Contact,
  ConversationId,
  ConversationSummary,
  MessageView,
  MycelEvent,
  NearbyPeer,
  NetworkStatus,
  PeerId,
  Profile,
} from "../src/types.ts";

const MycelContext = createContext<Mycel | null>(null);

/** Optional: provide a specific client (otherwise the default `mycel` is used). */
export function MycelProvider({ client, children }: { client: Mycel; children?: ReactNode }) {
  return createElement(MycelContext.Provider, { value: client }, children);
}

/** The Mycel client in scope. */
export function useMycel(): Mycel {
  return useContext(MycelContext) ?? getMycel();
}

export interface QueryState<T> {
  data: T | undefined;
  loading: boolean;
  error: Error | null;
  /** Re-fetch now. */
  refresh: () => void;
}

/**
 * Generic "fetch, then re-fetch on matching events" hook. Stale responses are
 * dropped, and bursts of events are coalesced into one refresh.
 */
export function useMycelQuery<T>(
  fetcher: (client: Mycel) => Promise<T>,
  deps: unknown[],
  refreshOn: (event: MycelEvent) => boolean,
): QueryState<T> {
  const client = useMycel();
  const [data, setData] = useState<T | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const seq = useRef(0);
  const scheduled = useRef<ReturnType<typeof setTimeout> | null>(null);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const fetchNow = useCallback(() => fetcher(client), [client, ...deps]);
  const filterRef = useRef(refreshOn);
  filterRef.current = refreshOn;

  const run = useCallback(() => {
    const mine = ++seq.current;
    fetchNow().then(
      (value) => {
        if (mine !== seq.current) return;
        setData(value);
        setError(null);
        setLoading(false);
      },
      (e: unknown) => {
        if (mine !== seq.current) return;
        setError(e instanceof Error ? e : new Error(String(e)));
        setLoading(false);
      },
    );
  }, [fetchNow]);

  useEffect(() => {
    setLoading(true);
    setData(undefined);
    run();
    const off = client.on("*", (event) => {
      if (!filterRef.current(event)) return;
      if (scheduled.current) return;
      scheduled.current = setTimeout(() => {
        scheduled.current = null;
        run();
      }, 16);
    });
    return () => {
      off();
      seq.current++;
      if (scheduled.current) clearTimeout(scheduled.current);
      scheduled.current = null;
    };
  }, [client, run]);

  return { data, loading, error, refresh: run };
}

// ---------------------------------------------------------------------------
// host-level

// There is no "profile changed" runtime event, so renames made through this
// hook are shared with every other mounted useProfile() directly.
const profileListeners = new Set<(p: Profile) => void>();

export function useProfile() {
  const client = useMycel();
  const q = useMycelQuery((c) => c.profile.get(), [], () => false);
  const [saved, setSaved] = useState<Profile | undefined>(undefined);
  useEffect(() => {
    profileListeners.add(setSaved);
    return () => void profileListeners.delete(setSaved);
  }, []);
  const setName = useCallback(
    async (name: string) => {
      const p = await client.profile.setName(name);
      for (const l of profileListeners) l(p);
      return p;
    },
    [client],
  );
  return { ...q, profile: saved ?? q.data, setName };
}

export function useContacts() {
  const q = useMycelQuery(
    (c) => c.contacts.list(),
    [],
    (e) => e.type === "contactsChanged" || e.type === "nearbyChanged" || e.type === "networkChanged",
  );
  return { ...q, contacts: q.data ?? ([] as Contact[]) };
}

export function useNearby() {
  const q = useMycelQuery(
    (c) => c.nearby.list(),
    [],
    (e) => e.type === "nearbyChanged" || e.type === "contactsChanged",
  );
  return { ...q, nearby: q.data ?? ([] as NearbyPeer[]) };
}

export function useNetwork() {
  const q = useMycelQuery(
    (c) => c.network.status(),
    [],
    (e) => e.type === "networkChanged" || e.type === "nearbyChanged" || e.type === "contactsChanged",
  );
  return { ...q, status: q.data as NetworkStatus | undefined };
}

// ---------------------------------------------------------------------------
// chat

export function useConversations() {
  const q = useMycelQuery(
    (c) => c.chat.list(),
    [],
    (e) =>
      e.type === "conversationUpdated" ||
      e.type === "conversationAdded" ||
      e.type === "contactsChanged",
  );
  return { ...q, conversations: q.data ?? ([] as ConversationSummary[]) };
}

export function useConversation(id: ConversationId | null | undefined) {
  const q = useMycelQuery(
    (c) => (id ? c.chat.get(id) : Promise.resolve(null)),
    [id],
    (e) =>
      ((e.type === "conversationUpdated" || e.type === "conversationAdded") && e.conversation === id) ||
      e.type === "contactsChanged",
  );
  return { ...q, conversation: (q.data ?? null) as ConversationSummary | null };
}

const PAGE = 50;

/**
 * Messages of one conversation, oldest -> newest. Refreshes on
 * `conversationUpdated` for it and on `blobReady` for any loaded attachment.
 * `loadOlder()` pages backwards.
 */
export function useMessages(id: ConversationId | null | undefined, pageSize = PAGE) {
  const [window_, setWindow] = useState(pageSize);
  const [hasMore, setHasMore] = useState(false);
  const blobsRef = useRef<Set<string>>(new Set());

  useEffect(() => setWindow(pageSize), [id, pageSize]);

  const q = useMycelQuery(
    async (c) => {
      if (!id) return [] as MessageView[];
      // Ask for one extra to learn whether older history exists.
      const list = await c.chat.messages(id, { limit: window_ + 1 });
      setHasMore(list.length > window_);
      return list.length > window_ ? list.slice(1) : list;
    },
    [id, window_],
    (e) =>
      (e.type === "conversationUpdated" && e.conversation === id) ||
      (e.type === "blobReady" && blobsRef.current.has(e.blob)),
  );

  const messages = q.data ?? [];
  blobsRef.current = useMemo(
    () => new Set(messages.flatMap((m) => m.attachments.map((a) => a.blob))),
    [messages],
  );

  const loadOlder = useCallback(() => {
    if (hasMore) setWindow((w) => w + pageSize);
  }, [hasMore, pageSize]);

  // Keep showing the previous page while a larger window loads.
  const prev = useRef<MessageView[]>([]);
  if (q.data) prev.current = q.data;
  const shown = q.data ?? (q.loading && id && prev.current[0]?.conversation === id ? prev.current : []);

  return { ...q, messages: shown, hasMore, loadOlder };
}

/**
 * Live progress of one attachment transfer: `id` is the path passed to
 * `send_message` (uploads) or the blob id (downloads). `null` until the first
 * `transferProgress` event for it; reset when `id` changes. `rate` is bytes
 * per second over the last few seconds.
 */
export function useTransfer(id: string | null | undefined): { done: number; total: number; rate: number } | null {
  const client = useMycel();
  const [state, setState] = useState<{ done: number; total: number; rate: number } | null>(null);
  useEffect(() => {
    setState(null);
    if (!id) return;
    return client.on("transferProgress", (e) => {
      if (e.id === id) setState({ done: e.done, total: e.total, rate: e.rate });
    });
  }, [client, id]);
  return state;
}

const TYPING_MS = 4000;

/**
 * Who is typing in a conversation right now. Each `typing` event shows the
 * peer for ~4 s; a peer is cleared early as soon as their message lands.
 */
export function useTyping(id: ConversationId | null | undefined): PeerId[] {
  const client = useMycel();
  const [typing, setTyping] = useState<Map<PeerId, number>>(new Map());

  useEffect(() => {
    setTyping(new Map());
    if (!id) return;
    const timers = new Map<PeerId, ReturnType<typeof setTimeout>>();
    const drop = (peer: PeerId) => {
      clearTimeout(timers.get(peer));
      timers.delete(peer);
      setTyping((m) => {
        if (!m.has(peer)) return m;
        const next = new Map(m);
        next.delete(peer);
        return next;
      });
    };
    let alive = true;
    const offTyping = client.on("typing", (e) => {
      if (e.conversation !== id) return;
      clearTimeout(timers.get(e.peer));
      timers.set(e.peer, setTimeout(() => drop(e.peer), TYPING_MS));
      setTyping((m) => new Map(m).set(e.peer, Date.now()));
    });
    const offUpdate = client.on("conversationUpdated", (e) => {
      if (e.conversation !== id || timers.size === 0) return;
      client.chat.messages(id, { limit: 1 }).then(
        ([last]) => {
          if (alive && last && timers.has(last.author)) drop(last.author);
        },
        () => {},
      );
    });
    return () => {
      alive = false;
      offTyping();
      offUpdate();
      for (const t of timers.values()) clearTimeout(t);
    };
  }, [client, id]);

  return useMemo(() => [...typing.keys()], [typing]);
}

/** How long an ended call stays in `useCalls()` (for a "Call ended" moment). */
const ENDED_MS = 4000;

/**
 * Calls on this device: loads `call_status`, then follows `callIncoming` and
 * `callUpdated` (about 10 updates a second while a call is active). Ended
 * calls drop out a few seconds after they end. Newest first.
 */
export function useCalls(): CallInfo[] {
  const client = useMycel();
  const [calls, setCalls] = useState<Map<CallId, CallInfo>>(new Map());

  useEffect(() => {
    let alive = true;
    const timers = new Map<CallId, ReturnType<typeof setTimeout>>();
    const put = (c: CallInfo) => {
      if (!alive) return;
      setCalls((m) => new Map(m).set(c.id, c));
      if (c.state === "ended" && !timers.has(c.id)) {
        timers.set(
          c.id,
          setTimeout(() => {
            setCalls((m) => {
              const next = new Map(m);
              next.delete(c.id);
              return next;
            });
          }, ENDED_MS),
        );
      }
    };
    client.calls.status().then(
      (list) => list.forEach(put),
      () => {},
    );
    const offIncoming = client.on("callIncoming", (e) => put(e.call));
    const offUpdated = client.on("callUpdated", (e) => put(e.call));
    return () => {
      alive = false;
      offIncoming();
      offUpdated();
      for (const t of timers.values()) clearTimeout(t);
    };
  }, [client]);

  return useMemo(() => [...calls.values()].sort((a, b) => b.startedAt - a.startedAt), [calls]);
}
