import { useState } from "react";
import { isMobile } from "@mycel/sdk";
import { useProfile } from "@mycel/sdk/react";
import { Glyph } from "../icons.tsx";
import { applyTheme, readTheme, type ThemeChoice } from "../theme.ts";
import { Qr } from "./Qr.tsx";
import { Avatar, errorText, shortId } from "./common.tsx";
import { notificationStatus, type NotificationPermission } from "../notificationStatus.ts";

interface NotificationsState {
  native: boolean;
  permission: NotificationPermission;
  error: string | null;
  checkPermission: () => Promise<void>;
}

export function ProfilePanel({ notifications }: { notifications?: NotificationsState }) {
  const { profile, setName, error: loadError } = useProfile();
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [theme, setTheme] = useState<ThemeChoice>(readTheme());

  if (!profile) return loadError ? <p className="p-error">{errorText(loadError)}</p> : null;

  const save = async () => {
    const name = editing?.trim();
    if (!name || name === profile.name) return setEditing(null);
    try {
      await setName(name);
      setEditing(null);
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(profile.contactCode);
    } catch {
      // Clipboard API unavailable: fall back to selecting the text.
      const el = document.getElementById("contact-code");
      if (el) window.getSelection()?.selectAllChildren(el);
      return;
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const pickTheme = (t: ThemeChoice) => {
    setTheme(t);
    applyTheme(t);
  };

  return (
    <div className="p-profile">
      <div className="p-me">
        <Avatar id={profile.id} name={profile.name} size={64} />
        {editing !== null ? (
          <form
            className="p-name-form"
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <input
              autoFocus
              value={editing}
              onChange={(e) => setEditing(e.target.value)}
              onKeyDown={(e) => e.key === "Escape" && (e.stopPropagation(), setEditing(null))}
              aria-label="Your name"
              maxLength={60}
            />
            <button className="h-btn h-btn-primary">Save</button>
          </form>
        ) : (
          <div className="p-name">
            <h3>{profile.name}</h3>
            <button className="h-link" onClick={() => setEditing(profile.name)}>
              <Glyph.Pencil /> Change name
            </button>
          </div>
        )}
        {error && <p className="p-error">{error}</p>}
        <p className="p-device" title={profile.id}>
          This device: <code>{shortId(profile.id)}</code>
        </p>
      </div>

      <section className="p-card">
        <h4>Your contact code</h4>
        <p className="p-help">
          Share it so people can add you. Show the QR code to someone in the room, or send the text another way.
        </p>
        <div className="p-qr">
          <Qr value={profile.contactCode} label={`QR code for ${profile.name}'s contact code`} />
        </div>
        <div className="p-code">
          <code id="contact-code">{profile.contactCode}</code>
          <button className={`h-btn h-btn-quiet${copied ? " is-done" : ""}`} onClick={copy} aria-live="polite">
            {copied ? <Glyph.Check /> : <Glyph.Copy />}
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </section>

      {notifications?.native && <NotificationsCard notifications={notifications} />}

      <section className="p-card">
        <h4>Appearance</h4>
        <div className="p-seg" role="radiogroup" aria-label="Theme">
          {(["system", "light", "dark"] as const).map((t) => (
            <button key={t} role="radio" aria-checked={theme === t} className={theme === t ? "is-on" : ""} onClick={() => pickTheme(t)}>
              {t === "system" ? "Match system" : t === "light" ? "Light" : "Dark"}
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}

function NotificationsCard({ notifications }: { notifications: NotificationsState }) {
  const status = notificationStatus(notifications.permission);
  return (
    <section className="p-card" aria-label="Notifications">
      <h4>Notifications</h4>
      <p className="p-help" role="status">
        {status.text}
      </p>
      {isMobile() && (
        <p className="p-help">Alerts arrive while Mycel is connected. Your phone may pause the connection when Mycel is in the background.</p>
      )}
      {status.button && (
        <button className="h-btn h-btn-quiet" onClick={() => void notifications.checkPermission()}>
          {status.button}
        </button>
      )}
      {notifications.error && (
        <p className="p-error" role="alert">
          {notifications.error}
        </p>
      )}
    </section>
  );
}
