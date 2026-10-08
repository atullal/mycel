import type {
  Contact,
  ConversationId,
  ConversationSummary,
  MessageId,
  MessageView,
  MycelEvent,
  NearbyPeer,
  NetworkStatus,
  PeerId,
  Profile,
} from "./types.ts";

/**
 * The command table from docs/RUNTIME_API.md: command name -> [args, result].
 * Command names are snake_case; arg names are camelCase.
 */
export interface Commands {
  get_profile: [Record<string, never>, Profile];
  set_name: [{ name: string }, Profile];
  add_contact: [{ code: string }, Contact];
  add_nearby_contact: [{ id: PeerId }, Contact];
  remove_contact: [{ id: PeerId }, null];
  list_contacts: [Record<string, never>, Contact[]];
  list_nearby: [Record<string, never>, NearbyPeer[]];
  network_status: [Record<string, never>, NetworkStatus];
  list_conversations: [Record<string, never>, ConversationSummary[]];
  get_conversation: [{ id: ConversationId }, ConversationSummary];
  create_conversation: [{ title?: string | null; members: PeerId[] }, ConversationSummary];
  list_messages: [
    { id: ConversationId; limit?: number | null; before?: MessageId | null },
    MessageView[],
  ];
  send_message: [
    {
      id: ConversationId;
      body: string;
      replyTo?: MessageId | null;
      attachments?: string[] | null;
    },
    MessageView,
  ];
  edit_message: [{ id: ConversationId; message: MessageId; body: string }, null];
  delete_message: [{ id: ConversationId; message: MessageId }, null];
  toggle_reaction: [{ id: ConversationId; message: MessageId; emoji: string }, null];
  mark_read: [{ id: ConversationId }, null];
  set_typing: [{ id: ConversationId }, null];
  add_members: [{ id: ConversationId; members: PeerId[] }, null];
  remove_member: [{ id: ConversationId; member: PeerId }, null];
  add_keeper: [{ id: ConversationId; keeper: PeerId }, null];
  rename_conversation: [{ id: ConversationId; title: string }, null];
  fetch_attachment: [{ blob: string }, string];
  accept_request: [{ id: ConversationId }, ConversationSummary];
  decline_request: [{ id: ConversationId; block?: boolean | null }, null];
}

export type Command = keyof Commands;
export type ArgsOf<C extends Command> = Commands[C][0];
export type ResultOf<C extends Command> = Commands[C][1];

/** Host services that are not runtime commands (native file pickers etc). */
export interface FileHost {
  /** Let the user choose files to attach. Resolves to paths, or [] if cancelled. */
  pick(): Promise<string[]>;
  /** A URL the webview can load for a local file path (images, previews). */
  url(path: string): string;
  /** Open a local file with the system's default application. */
  open(path: string): Promise<void>;
  /**
   * Turn browser `File`s (pasted images, HTML drag-and-drop) into paths that
   * can be passed in `attachments`. Streams them to the runtime, any size.
   */
  stage?(files: File[]): Promise<string[]>;
  /**
   * Native drag-and-drop of files onto the window, with real paths (the
   * Tauri host; there HTML5 drop events carry no files). Returns an
   * unsubscribe function.
   */
  onDragDrop?(handler: (event: FileDragEvent) => void): () => void;
}

/** A native drag of files over the window. */
export type FileDragEvent = { type: "over" } | { type: "leave" } | { type: "drop"; paths: string[] };

/**
 * How the SDK talks to a Mycel runtime. In the host this is Tauri IPC; in a
 * plain browser it is the in-memory mock.
 */
export interface Transport {
  /** Which backend this is (for diagnostics and dev banners). */
  readonly kind: "tauri" | "mock" | (string & {});
  /** Invoke one runtime command. Rejects with a human-readable error string. */
  invoke<C extends Command>(cmd: C, args: ArgsOf<C>): Promise<ResultOf<C>>;
  /** Receive every runtime event. Returns an unsubscribe function. */
  listen(handler: (event: MycelEvent) => void): () => void;
  /** Native file access, if the transport provides it. */
  readonly files?: FileHost;
}

/** Normalise whatever a transport rejected with into an Error with a readable message. */
export function toError(e: unknown): Error {
  if (e instanceof Error) return e;
  if (typeof e === "string") return new Error(e);
  try {
    return new Error(JSON.stringify(e));
  } catch {
    return new Error(String(e));
  }
}
