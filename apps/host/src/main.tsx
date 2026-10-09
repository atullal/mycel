import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { applyTheme, readTheme } from "./theme.ts";
import "./theme.css";
import "./host.css";

applyTheme(readTheme());
followAndroidInsets();
followIOSKeyboard();

/**
 * Android draws the app under the status and navigation bars (and resizes it
 * above the keyboard); MainActivity reports the bars' size, which theme.css
 * folds into the --safe-* paddings, and whether the keyboard is up. iOS
 * reports the bars through env() instead.
 */
function followAndroidInsets() {
  type Insets = { top: number; right: number; bottom: number; left: number; keyboard?: boolean };
  const apply = (i: Insets) => {
    for (const side of ["top", "right", "bottom", "left"] as const) {
      document.documentElement.style.setProperty(`--android-inset-${side}`, `${i[side] ?? 0}px`);
    }
    // While typing, the phone layout drops its bottom tab bar (host.css).
    document.documentElement.classList.toggle("keyboard-open", !!i.keyboard);
  };
  const bridge = (window as { MycelAndroid?: { insets(): string } }).MycelAndroid;
  if (bridge) {
    try {
      apply(JSON.parse(bridge.insets()) as Insets);
    } catch {
      /* not ready yet: the event below follows */
    }
  }
  window.addEventListener("mycel-insets", (e) => apply((e as CustomEvent<Insets>).detail));
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

/**
 * iPhone and iPad: the on-screen keyboard shrinks the visual viewport and
 * WebKit scrolls the page to keep the focused field in sight, which pushes
 * the conversation's header off the top. Fit the app into the space above
 * the keyboard instead, and drop the tab bar while typing (as on Android).
 * A hardware keyboard leaves the viewport alone, and so does this.
 */
function followIOSKeyboard() {
  const vv = window.visualViewport;
  const ua = navigator.userAgent;
  const ios = /iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
  if (!vv || !ios) return;
  const root = document.documentElement;
  const update = () => {
    const open = vv.height < window.innerHeight - 120;
    root.classList.toggle("keyboard-open", open);
    root.style.height = open ? `${vv.height}px` : "";
    if (open) window.scrollTo(0, 0);
  };
  vv.addEventListener("resize", update);
  vv.addEventListener("scroll", () => {
    if (root.classList.contains("keyboard-open")) window.scrollTo(0, 0);
  });
}
