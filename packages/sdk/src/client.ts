import { createMockTransport } from "./mock.ts";
import { createHttpTransport, isHttpRuntime } from "./http.ts";
import { createTauriTransport, isTauri } from "./tauri.ts";
import { toError, type ArgsOf, type Command, type FileHost, type ResultOf, type Transport } from "./transport.ts";
import { parseVideoFrame, type VideoFrameData } from "./video.ts";
import type {
  CallId,
  CallInfo,
  Contact,
  ConversationId,
  ConversationSummary,
  EventOf,
  EventType,
  MessageId,
  MessageView,
  MycelEvent,
  NearbyPeer,
  NetworkMode,
  NetworkStatus,
  PeerId,
  Profile,
} from "./types.ts";

/**
 * Android only lets an app's screen ask for the microphone, so the native
 * runtime can't. The web view can: getUserMedia brings up the system prompt
 * (MainActivity's web view turns it into the app's permission), and the call
 * audio then runs natively. If the user says no, the runtime's error says
 * where to allow it.
 */
async function askForMicrophone(transport: Transport): Promise<void> {
  if (transport.kind !== "tauri" || typeof navigator === "undefined") return;
  if (!/Android/.test(navigator.userAgent) || !navigator.mediaDevices?.getUserMedia) return;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    for (const track of stream.getTracks()) track.stop();
  } catch {
    /* denied or dismissed: start_call explains */
  }
}

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
    /** `add_nearby_contact`: fetch a nearby person's card over an available direct path and add them. */
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
    /** `set_network_mode`: takes effect after a restart. */
    setMode(mode: NetworkMode): Promise<NetworkStatus>;
    /** `restart_app` (native host only; check `transport.kind === "tauri"`). */
    restart(): Promise<null>;
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
    /** Hide only on this device; no conversation operation is sent. */
    deleteLocal(id: ConversationId, message: MessageId): Promise<void>;
    /** Undo local hiding; cannot undo a Delete for everyone tombstone. */
    restoreLocal(id: ConversationId, message: MessageId): Promise<void>;
    /** Search all synchronized visible messages, newest match first. */
    search(id: ConversationId, query: string, limit?: number): Promise<MessageView[]>;
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

  /**
   * Live voice calls, 1:1 and group (up to 8 people, each connected to each
   * other). Audio is captured and played by the runtime (not the webview):
   * Opus over the same encrypted multipath connections as everything else.
   * Watch `callIncoming` / `callUpdated`, or `useCalls()`.
   */
  calls: {
    /**
     * `start_call`: ring the other person, or everyone in a group (resolves
     * while `connecting`). Joins the conversation's call instead if one is
     * ringing you or going on without you. `video: true` starts with our
     * camera on (asking for the camera the first time).
     */
    start(conversation: ConversationId, opts?: { video?: boolean }): Promise<CallInfo>;
    /** `accept_call`: answer a ringing call (asks for the microphone the first time); `video` turns our camera on. */
    accept(call: CallId, opts?: { video?: boolean }): Promise<CallInfo>;
    /** `accept_call` on a `joinable` group call: join it. */
    join(call: CallId, opts?: { video?: boolean }): Promise<CallInfo>;
    /**
     * `set_camera`: turn our camera on or off, before or during a call. The
     * first time, this waits for the user to answer the system's camera
     * prompt; if they say no it rejects, and `video.error` says where to allow it.
     */
    setCamera(call: CallId, on: boolean): Promise<CallInfo>;
    /**
     * `video_keyframe`: a video decoder lost its place; get a fresh keyframe
     * for the self-view (`"local"`), from the others (`"remote"`), or both.
     */
    requestKeyframe(call: CallId, source?: "local" | "remote"): Promise<void>;
    /**
     * Encoded video frames as they arrive: everyone's video (one stream per
     * person, `frame.peer` says whose) and our self-view. Decode them with
     * `videoCanvas` (or `useVideoCanvas` in React). Returns an unsubscribe
     * function. Without a video-capable backend nothing arrives
     * (`videoSupported` is false).
     */
    onVideo(handler: (frame: VideoFrameData) => void): () => void;
    /** The backend delivers video frames. */
    readonly videoSupported: boolean;
    /** `decline_call` (a declined group call stays `joinable` while it goes on) */
    decline(call: CallId): Promise<void>;
    /** `end_call`: hang up (a group call goes on for the others), or cancel a call that hasn't been answered. */
    end(call: CallId): Promise<void>;
    /** `set_muted` */
    setMuted(call: CallId, muted: boolean): Promise<CallInfo>;
    /** `call_status`: live calls, plus ones that ended in the last few seconds. */
    status(): Promise<CallInfo[]>;
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
  // one transport subscription for video, shared by every viewer
  const videoHandlers = new Set<(frame: VideoFrameData) => void>();
  let stopVideo: (() => void) | null = null;

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
      setMode: (mode) => call("set_network_mode", { mode }),
      restart: () => call("restart_app", none),
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
      deleteLocal: (id, message) => call("delete_message_local", { id, message }).then(done),
      restoreLocal: (id, message) => call("restore_message_local", { id, message }).then(done),
      search: (id, query, limit) => call("search_messages", limit == null ? { id, query } : { id, query, limit }),
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
    calls: {
      start: (conversation, opts) =>
        askForMicrophone(transport).then(() => call("start_call", { conversation, video: opts?.video ?? false })),
      accept: (id, opts) =>
        askForMicrophone(transport).then(() => call("accept_call", { call: id, video: opts?.video ?? false })),
      join: (id, opts) =>
        askForMicrophone(transport).then(() => call("accept_call", { call: id, video: opts?.video ?? false })),
      setCamera: (id, on) => call("set_camera", { call: id, on }),
      requestKeyframe: (id, source) => call("video_keyframe", source ? { call: id, source } : { call: id }).then(done),
      onVideo: (handler) => {
        videoHandlers.add(handler);
        if (!stopVideo && transport.video) {
          stopVideo = transport.video((buf) => {
            const f = parseVideoFrame(buf);
            if (!f) return;
            for (const h of [...videoHandlers]) {
              try {
                h(f);
              } catch (err) {
                console.error("[mycel] video handler failed", err);
              }
            }
          });
        }
        return () => {
          videoHandlers.delete(handler);
          if (videoHandlers.size === 0 && stopVideo) {
            stopVideo();
            stopVideo = null;
          }
        };
      },
      videoSupported: !!transport.video,
      decline: (id) => call("decline_call", { call: id }).then(done),
      end: (id) => call("end_call", { call: id }).then(done),
      setMuted: (id, muted) => call("set_muted", { call: id, muted }),
      status: () => call("call_status", none),
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
