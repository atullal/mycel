import { createMockTransport } from "./mock.ts";
import { createHttpTransport, isHttpRuntime } from "./http.ts";
import { createTauriTransport, isTauri } from "./tauri.ts";
import { toError, type ArgsOf, type Command, type FileHost, type ResultOf, type Transport } from "./transport.ts";
import type {
  Contact,
  ConversationId,
  ConversationSummary,
  EventOf,
  EventType,
  MessageId,
  MessageView,
  MycelEvent,
  NearbyPeer,
  NetworkStatus,
  PeerId,
  Profile,
} from "./types.ts";

export interface MessagesOptions {
  /** Return at most this many messages (the newest ones before `before`). */
  limit?: number;
  /** Only messages strictly older than this one. */
  before?: MessageId;
}

export interface SendOptions {
  /** The message this one replies to. */
  replyTo?: MessageId;
  /** Local file paths to attach (e.g. from `mycel.files.pick()`). */
  attachments?: string[];
}

/** The typed Mycel client. One method per runtime command (docs/RUNTIME_API.md). */
export interface Mycel {
  readonly transport: Transport;

  profile: {
    /** `get_profile` */
    get(): Promise<Profile>;
    /** `set_name` */
    setName(name: string): Promise<Profile>;
  };

  contacts: {
    /** `list_contacts` */
    list(): Promise<Contact[]>;
    /** `add_contact`: add someone from their contact code. */
    add(code: string): Promise<Contact>;
    /** `add_nearby_contact`: fetch a nearby person's card over the LAN and add them. */
    addNearby(id: PeerId): Promise<Contact>;
    /** `remove_contact` */
    remove(id: PeerId): Promise<void>;
  };

  nearby: {
    /** `list_nearby` */
    list(): Promise<NearbyPeer[]>;
  };

  network: {
    /** `network_status` */
    status(): Promise<NetworkStatus>;
  };

  chat: {
    /** `list_conversations` (newest activity first) */
    list(): Promise<ConversationSummary[]>;
    /** `get_conversation` */
    get(id: ConversationId): Promise<ConversationSummary>;
    /** `create_conversation`: one member and no title makes a direct conversation. */
    create(title: string | null | undefined, members: PeerId[]): Promise<ConversationSummary>;
    /** `list_messages` (oldest -> newest) */
    messages(id: ConversationId, opts?: MessagesOptions): Promise<MessageView[]>;
    /** `send_message`: resolves once written locally (`delivery: "local"`). */
    send(id: ConversationId, body: string, opts?: SendOptions): Promise<MessageView>;
    /** `edit_message` (author only) */
    edit(id: ConversationId, message: MessageId, body: string): Promise<void>;
    /** `delete_message` (author only) */
    delete(id: ConversationId, message: MessageId): Promise<void>;
    /** `toggle_reaction` */
    react(id: ConversationId, message: MessageId, emoji: string): Promise<void>;
    /** `mark_read` */
    markRead(id: ConversationId): Promise<void>;
    /** `set_typing`: call while the user types; peers show it for ~4 s. */
    typing(id: ConversationId): Promise<void>;
    /** `add_members` (admins) */
    addMembers(id: ConversationId, members: PeerId[]): Promise<void>;
    /** `remove_member` (admins; or yourself, to leave) */
    removeMember(id: ConversationId, member: PeerId): Promise<void>;
    /** `add_keeper`: the keeper must be a contact. */
    addKeeper(id: ConversationId, keeper: PeerId): Promise<void>;
    /** `rename_conversation` */
    rename(id: ConversationId, title: string): Promise<void>;
    /** `fetch_attachment`: resolves to the local path; `blobReady` fires too. */
    fetchAttachment(blob: string): Promise<string>;
    /** `accept_request`: the inviter becomes a contact and you introduce yourself. */
    acceptRequest(id: ConversationId): Promise<ConversationSummary>;
    /**
     * `decline_request`: leave the conversation (it disappears from the list).
     * `block: true` also refuses every future invite from that person.
     */
    declineRequest(id: ConversationId, opts?: { block?: boolean }): Promise<void>;
  };

  /** Host file services (native dialog in Tauri, `<input type=file>` in the mock). */
  files: FileHost;

  /** Subscribe to one event type, or `"*"` for all. Returns an unsubscribe function. */
  on<T extends EventType>(type: T, handler: (event: EventOf<T>) => void): () => void;
  on(type: "*", handler: (event: MycelEvent) => void): () => void;
}

const browserFiles: FileHost = {
  async pick() {
    return [];
  },
  url(path) {
    return path;
  },
  async open(path) {
    if (typeof window !== "undefined") window.open(path, "_blank", "noopener");
  },
};

/** Build a client over any transport. */
export function createMycel(transport: Transport): Mycel {
  async function call<C extends Command>(cmd: C, args: ArgsOf<C>): Promise<ResultOf<C>> {
    try {
      return await transport.invoke(cmd, args);
    } catch (e) {
      throw toError(e);
    }
  }
  const none = {} as Record<string, never>;
  const done = () => undefined;

  function on(type: string, handler: (event: MycelEvent) => void): () => void {
    return transport.listen((event) => {
      if (type === "*" || event.type === type) handler(event);
    });
  }

  return {
    transport,
    profile: {
      get: () => call("get_profile", none),
      setName: (name) => call("set_name", { name }),
    },
    contacts: {
      list: () => call("list_contacts", none),
      add: (code) => call("add_contact", { code }),
      addNearby: (id) => call("add_nearby_contact", { id }),
      remove: (id) => call("remove_contact", { id }).then(done),
    },
    nearby: {
      list: () => call("list_nearby", none),
    },
    network: {
      status: () => call("network_status", none),
    },
    chat: {
      list: () => call("list_conversations", none),
      get: (id) => call("get_conversation", { id }),
      create: (title, members) => call("create_conversation", title ? { title, members } : { members }),
      messages: (id, opts = {}) => {
        const args: ArgsOf<"list_messages"> = { id };
        if (opts.limit != null) args.limit = opts.limit;
        if (opts.before != null) args.before = opts.before;
        return call("list_messages", args);
      },
      send: (id, body, opts = {}) => {
        const args: ArgsOf<"send_message"> = { id, body };
        if (opts.replyTo != null) args.replyTo = opts.replyTo;
        if (opts.attachments?.length) args.attachments = opts.attachments;
        return call("send_message", args);
      },
      edit: (id, message, body) => call("edit_message", { id, message, body }).then(done),
      delete: (id, message) => call("delete_message", { id, message }).then(done),
      react: (id, message, emoji) => call("toggle_reaction", { id, message, emoji }).then(done),
      markRead: (id) => call("mark_read", { id }).then(done),
      typing: (id) => call("set_typing", { id }).then(done),
      addMembers: (id, members) => call("add_members", { id, members }).then(done),
      removeMember: (id, member) => call("remove_member", { id, member }).then(done),
      addKeeper: (id, keeper) => call("add_keeper", { id, keeper }).then(done),
      rename: (id, title) => call("rename_conversation", { id, title }).then(done),
      fetchAttachment: (blob) => call("fetch_attachment", { blob }),
      acceptRequest: (id) => call("accept_request", { id }),
      declineRequest: (id, opts = {}) =>
        call("decline_request", opts.block ? { id, block: true } : { id }).then(done),
    },
    files: transport.files ?? browserFiles,
    on: on as Mycel["on"],
  };
}

/** Tauri IPC inside the host; the in-memory mock everywhere else. */
export function autoTransport(): Transport {
  if (isTauri()) return createTauriTransport();
  if (isHttpRuntime()) return createHttpTransport();
  return createMockTransport();
}

let defaultClient: Mycel | null = null;

/** The process-wide client, created on first use with `autoTransport()`. */
export function getMycel(): Mycel {
  defaultClient ??= createMycel(autoTransport());
  return defaultClient;
}

/** Replace the process-wide client (tests, custom transports). */
export function setMycel(client: Mycel): void {
  defaultClient = client;
}

/**
 * The default client. Property access is forwarded to `getMycel()`, so
 * importing this does not start a transport until it is first used.
 */
export const mycel: Mycel = new Proxy({} as Mycel, {
  get(_target, prop) {
    return Reflect.get(getMycel(), prop);
  },
});
