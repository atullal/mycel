import { useCallback, useEffect, useState, type ReactNode } from "react";
import { MessagingApp } from "@mycel/messaging";
import { useConversations, useMycel, useNearby, useNetwork, useProfile } from "@mycel/sdk/react";
import { Glyph, MycelMark } from "./icons.tsx";
import { ProfilePanel } from "./panels/ProfilePanel.tsx";
import { ContactsPanel } from "./panels/ContactsPanel.tsx";
import { NearbyPanel } from "./panels/NearbyPanel.tsx";
import { NetworkPanel } from "./panels/NetworkPanel.tsx";
import { Avatar } from "./panels/common.tsx";
import { useNativeNotifications } from "./notifications.ts";
import { NoticeBanner } from "./Notices.tsx";

type PanelId = "profile" | "contacts" | "nearby" | "network";

const APPS: { id: string; name: string; glyph: keyof typeof Glyph }[] = [{ id: "messaging", name: "Messages", glyph: "Chat" }];

const PANELS: Record<PanelId, string> = {
  profile: "Profile",
  contacts: "Contacts",
  nearby: "Nearby",
  network: "Network",
};

export function App() {
  const mycel = useMycel();
  const [panel, setPanel] = useState<PanelId | null>(null);
  const { profile } = useProfile();
  const { conversations } = useConversations();
  const { nearby } = useNearby();
  const { status } = useNetwork();
  const demo = mycel.transport.kind === "mock";
  const [openRequest, setOpenRequest] = useState<{ id: string; token: number } | null>(null);
  const openNotification = useCallback((id: string) => {
    setPanel(null);
    setOpenRequest((previous) => ({ id, token: (previous?.token ?? 0) + 1 }));
  }, []);
  const notifications = useNativeNotifications(!!profile && !demo, openNotification);

  useEffect(() => {
    document.title = profile ? `${profile.name} — Mycel` : "Mycel";
  }, [profile]);

  useEffect(() => {
    if (!panel) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !document.querySelector("dialog[open]")) setPanel(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [panel]);

  // Message requests are not unread messages: they get a quieter dot instead.
  const unread = conversations.reduce((n, c) => n + (c.active && !c.request ? c.unread : 0), 0);
  const requests = conversations.filter((c) => c.request).length;
  const newNearby = nearby.filter((n) => !n.isContact).length;
  const online = status?.onlinePeers.length ?? 0;
  const toggle = (p: PanelId) => setPanel((cur) => (cur === p ? null : p));

  return (
    <div className="host">
      <nav className="rail" aria-label="Mycel">
        <div className="rail-mark" title="Mycel">
          <MycelMark size={30} />
        </div>

        <ul className="rail-apps" aria-label="Apps">
          {APPS.map((a) => {
            const G = Glyph[a.glyph];
            return (
              <li key={a.id}>
                <button className="rail-app is-active" onClick={() => setPanel(null)} aria-current="page" title={a.name}>
                  <span className="rail-app-icon">
                    <G />
                    {a.id === "messaging" && unread > 0 && <span className="rail-count">{unread > 9 ? "9+" : unread}</span>}
                    {a.id === "messaging" && unread === 0 && requests > 0 && (
                      <span className="rail-request-dot" title={`${requests} message request${requests > 1 ? "s" : ""}`} />
                    )}
                  </span>
                  <span className="rail-app-name">{a.name}</span>
                </button>
              </li>
            );
          })}
        </ul>

        <div className="rail-host" role="group" aria-label="You and your network">
          {demo && (
            <span className="rail-demo" title="Running in a browser with simulated people. Open the Mycel app to use the real network.">
              Demo
            </span>
          )}
          <RailButton label="Nearby" active={panel === "nearby"} onClick={() => toggle("nearby")}>
            <Glyph.Radar />
            {newNearby > 0 && <span className="rail-count is-nearby">{newNearby}</span>}
          </RailButton>
          <RailButton label="Contacts" active={panel === "contacts"} onClick={() => toggle("contacts")}>
            <Glyph.Contacts />
          </RailButton>
          <RailButton
            label={`Network: ${online} online`}
            active={panel === "network"}
            onClick={() => toggle("network")}
          >
            <Glyph.Network />
            <span className={`rail-dot${online > 0 ? " is-on" : ""}`} />
          </RailButton>
          <button
            className={`rail-me${panel === "profile" ? " is-active" : ""}`}
            onClick={() => toggle("profile")}
            title={profile ? `${profile.name} (profile)` : "Profile"}
            aria-label="Profile"
            aria-pressed={panel === "profile"}
          >
            {profile ? <Avatar id={profile.id} name={profile.name} size={34} /> : <span className="rail-me-blank" />}
          </button>
        </div>
      </nav>

      <div className="stage">
        <NoticeBanner onOpenNetwork={() => setPanel("network")} />
        <div className="stage-app" inert={panel ? true : undefined}>
          <MessagingApp
            onOpenContacts={() => setPanel("contacts")}
            visible={!panel}
            openRequest={openRequest}
            onVisibleConversationChange={notifications.setVisibleConversation}
          />
        </div>

        {panel && (
          <>
            <div className="scrim" onClick={() => setPanel(null)} aria-hidden="true" />
            <aside className="sheet" aria-label={PANELS[panel]} key={panel}>
              <header className="sheet-head">
                <h2>{PANELS[panel]}</h2>
                <button className="sheet-close" onClick={() => setPanel(null)} aria-label="Close">
                  <Glyph.Close />
                </button>
              </header>
              <div className="sheet-body">
                {panel === "profile" && <ProfilePanel notifications={notifications} />}
                {panel === "contacts" && <ContactsPanel onShowNearby={() => setPanel("nearby")} />}
                {panel === "nearby" && <NearbyPanel />}
                {panel === "network" && <NetworkPanel />}
              </div>
            </aside>
          </>
        )}
      </div>
    </div>
  );
}

function RailButton({
  label,
  active,
  onClick,
  children,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button className={`rail-btn${active ? " is-active" : ""}`} onClick={onClick} title={label} aria-label={label} aria-pressed={active}>
      {children}
    </button>
  );
}
