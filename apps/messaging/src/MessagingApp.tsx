import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useCalls, useContacts, useConversations, useMycel, useProfile } from "@mycel/sdk/react";
import { IMMERSIVE_ATTRIBUTE, isConversation, threadKeyOf, type Contact } from "@mycel/sdk";
import { ConversationList } from "./ConversationList.tsx";
import { ChatView } from "./ChatView.tsx";
import { NewConversationDialog } from "./NewConversation.tsx";
import { MembersPanel } from "./MembersPanel.tsx";
import { CallBar, IncomingCall, VideoStage, hasVideo, isLive, visibleCalls } from "./Calls.tsx";
import { errorText } from "./ui.tsx";
import { PANEL_OVER_CHAT, PHONE_LAYOUT, conversationInView, videoLayout } from "./layout.ts";
import { useMediaQuery } from "./useMediaQuery.ts";
import "./messaging.css";
import "./search.css";

export interface MessagingAppProps {
  /** Open this conversation first (otherwise the last one viewed). */
  initialConversation?: string;
  /** Ask the host to show its Contacts panel (used by empty states). */
  onOpenContacts?: () => void;
  /** Host panels can cover the mounted chat; covered chats are not being read. */
  visible?: boolean;
  /** Host notification routing; a token allows opening the same chat twice. */
  openRequest?: { id: string; token: number } | null;
  onVisibleConversationChange?: (id: string | null) => void;
}

const LAST_KEY = "mycel.messaging.lastConversation";

function readLast(): string | null {
  try {
    return localStorage.getItem(LAST_KEY);
  } catch {
    return null;
  }
}

function writeLast(id: string | null) {
  try {
    if (id) localStorage.setItem(LAST_KEY, id);
    else localStorage.removeItem(LAST_KEY);
  } catch {
    /* storage unavailable: nothing to remember */
  }
}

export function MessagingApp({ initialConversation, onOpenContacts, visible = true, openRequest, onVisibleConversationChange }: MessagingAppProps) {
  const { conversations, loading } = useConversations();
  const { contacts } = useContacts();
  const { profile } = useProfile();
  const [selected, setSelected] = useState<string | null>(initialConversation ?? readLast());
  const [composing, setComposing] = useState(false);
  const [membersOpen, setMembersOpen] = useState(false);

  const contactsById = useMemo(() => new Map<string, Contact>(contacts.map((c) => [c.id, c])), [contacts]);

  // Voice calls: one incoming ring at a time, one call in progress (plus
  // group calls going on without you, which you may join).
  const mycel = useMycel();
  const calls = visibleCalls(useCalls());
  const ringing = calls.find((c) => c.direction === "incoming" && c.state === "ringing") ?? null;
  const barCall = calls.find((c) => isLive(c) && c !== ringing) ?? calls.find((c) => c.state === "ended") ?? null;
  const liveCall = calls.find((c) => isLive(c) && c !== ringing) ?? null;
  const [videoMinimized, setVideoMinimized] = useState(false);
  useEffect(() => setVideoMinimized(false), [liveCall?.id]);
  const phoneLayout = useMediaQuery(PHONE_LAYOUT);
  const panelOverChat = useMediaQuery(PANEL_OVER_CHAT);
  const videoCall = liveCall && hasVideo(liveCall) ? liveCall : null;
  const stageLayout = videoCall ? videoLayout(phoneLayout, videoMinimized) : null;
  // Only a phone's full-screen call covers the app (and makes it inert).
  const videoExpanded = stageLayout === "expanded";
  const [callError, setCallError] = useState<string | null>(null);
  const startCall = useCallback(
    async (conversation: string, video = false) => {
      setCallError(null);
      try {
        await mycel.calls.start(conversation, { video });
      } catch (e) {
        setCallError(errorText(e));
      }
    },
    [mycel],
  );

  // Once the first list arrives, drop a remembered selection that no longer
  // exists. (Only then: a just-created conversation can be selected before the
  // list has refreshed to include it.)
  const validated = useRef(false);
  useEffect(() => {
    if (loading || validated.current) return;
    validated.current = true;
    if (selected && !conversations.some((c) => isConversation(c, selected))) setSelected(null);
  }, [loading, conversations, selected]);

  const select = useCallback((id: string | null) => {
    setSelected(id);
    writeLast(id);
  }, []);

  // Phones (and narrow windows) show either the list or one conversation:
  // one history entry while a conversation is open lets Android's back
  // button (and a browser's) return to the list instead of leaving the app.
  const historyEntry = useRef(false);
  useEffect(() => {
    if (selected && !historyEntry.current) {
      historyEntry.current = true;
      history.pushState({ mycelConversation: true }, "");
    } else if (!selected && historyEntry.current) {
      // closed in the app (the back arrow): drop the entry too
      historyEntry.current = false;
      history.back();
    }
  }, [selected]);
  useEffect(() => {
    const onPop = () => {
      if (!historyEntry.current) return;
      historyEntry.current = false;
      select(null);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [select]);

  const current = conversations.find((c) => isConversation(c, selected)) ?? null;
  // A late-arriving duplicate may choose a different canonical space. Keep
  // the current person selected without discarding the underlying histories.
  useEffect(() => {
    if (current && selected !== current.id) select(current.id);
  }, [current?.id, selected, select]);
  useEffect(() => {
    if (!openRequest) return;
    setComposing(false);
    setMembersOpen(false);
    setVideoMinimized(true);
    select(openRequest.id);
  }, [openRequest?.token, openRequest?.id, select]);
  const inView = conversationInView({ hostVisible: visible, composing, videoLayout: stageLayout, membersOpen, panelOverChat });
  const visibleConversation = inView ? current?.id ?? null : null;
  useEffect(() => {
    onVisibleConversationChange?.(visibleConversation);
    return () => onVisibleConversationChange?.(null);
  }, [visibleConversation, onVisibleConversationChange]);
  const currentCall = current
    ? (calls.find((c) => c.conversation === current.id && (isLive(c) || c.state === "joinable")) ?? null)
    : null;

  return (
    <div
      inert={videoExpanded}
      className={`mx-root${current ? " has-selection" : ""}${membersOpen && current ? " members-open" : ""}`}
      // An open conversation has its own back button: on a phone the host
      // can give its app bar's room to the chat.
      {...(current ? { [IMMERSIVE_ATTRIBUTE]: "" } : {})}
    >
      <ConversationList
        conversations={conversations}
        loading={loading}
        selected={selected}
        onSelect={select}
        onCompose={() => setComposing(true)}
      />
      <main className="mx-main">
        <CallBar call={barCall} onOpen={select} error={callError} onDismissError={() => setCallError(null)} />
        {videoCall && stageLayout && (
          <VideoStage
            key={videoCall.id}
            call={videoCall}
            layout={stageLayout}
            onMinimize={() => {
              setVideoMinimized(true);
              if (!current) select(videoCall.conversation);
            }}
            onRestore={() => setVideoMinimized(false)}
            onOpenChat={() => {
              select(videoCall.conversation);
              setVideoMinimized(true);
            }}
          />
        )}
        {current ? (
          <ChatView
            key={threadKeyOf(current)}
            summary={current}
            me={profile?.id}
            contactsById={contactsById}
            membersOpen={membersOpen}
            onToggleMembers={() => setMembersOpen((o) => !o)}
            onBack={() => select(null)}
            inCall={liveCall?.conversation === current.id}
            callsBusy={liveCall != null}
            onCall={() => void startCall(current.id)}
            onVideoCall={() => void startCall(current.id, true)}
            call={currentCall}
            meName={profile?.name}
            visible={visibleConversation === current.id}
          />
        ) : (
          <NoSelection
            hasConversations={conversations.length > 0}
            hasContacts={contacts.length > 0}
            loading={loading}
            onCompose={() => setComposing(true)}
            onOpenContacts={onOpenContacts}
          />
        )}
      </main>
      {current && membersOpen && (
        <MembersPanel
          key={threadKeyOf(current)}
          conversationId={current.id}
          contacts={contacts}
          onClose={() => setMembersOpen(false)}
          onLeft={() => setMembersOpen(false)}
        />
      )}
      {ringing && <IncomingCall key={ringing.id} call={ringing} onAnswered={select} />}
      {composing && (
        <NewConversationDialog
          onClose={() => setComposing(false)}
          onCreated={(id) => {
            setComposing(false);
            select(id);
          }}
          onOpenContacts={onOpenContacts}
        />
      )}
    </div>
  );
}

function NoSelection({
  hasConversations,
  hasContacts,
  loading,
  onCompose,
  onOpenContacts,
}: {
  hasConversations: boolean;
  hasContacts: boolean;
  loading: boolean;
  onCompose: () => void;
  onOpenContacts?: () => void;
}) {
  if (loading) return <div className="mx-empty" />;
  return (
    <div className="mx-empty">
      <HyphaeMark />
      {hasConversations ? (
        <>
          <h2>Pick a conversation</h2>
          <p>Messages are encrypted on this device and travel directly between the people in each chat.</p>
        </>
      ) : hasContacts ? (
        <>
          <h2>No conversations yet</h2>
          <p>Start a chat with one person, or a group with several. It works on your local network even without internet.</p>
          <button className="mx-btn mx-btn-primary" onClick={onCompose}>
            Start a conversation
          </button>
        </>
      ) : (
        <>
          <h2>Add someone to talk to</h2>
          <p>Swap contact codes with a friend, or add someone who's on the same network as you.</p>
          {onOpenContacts && (
            <button className="mx-btn mx-btn-primary" onClick={onOpenContacts}>
              Add a contact
            </button>
          )}
        </>
      )}
    </div>
  );
}

/** Quiet illustration for empty states: threads branching from one point. */
export function HyphaeMark() {
  return (
    <svg className="mx-hyphae" width="120" height="84" viewBox="0 0 120 84" fill="none" aria-hidden="true">
      <path d="M60 78 C 58 60, 46 52, 30 44 S 10 30, 8 16" />
      <path d="M60 78 C 62 58, 72 48, 86 40 S 108 26, 112 10" />
      <path d="M60 78 C 60 60, 60 40, 58 20" />
      <path d="M30 44 C 34 34, 40 28, 42 18" />
      <path d="M86 40 C 82 30, 80 24, 82 14" />
      <circle cx="8" cy="16" r="4" />
      <circle cx="112" cy="10" r="4" />
      <circle cx="58" cy="20" r="4" />
      <circle cx="42" cy="18" r="3" />
      <circle cx="82" cy="14" r="3" />
      <circle cx="60" cy="78" r="5" className="mx-hyphae-root" />
    </svg>
  );
}
