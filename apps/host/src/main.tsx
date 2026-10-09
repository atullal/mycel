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
  // The height with no keyboard. (WKWebView shrinks innerHeight with the
  // keyboard too, so it can't be the yardstick while typing.)
  let full = window.innerHeight;
  const typing = () => {
    const el = document.activeElement as HTMLElement | null;
    return !!el && (el.tagName === "TEXTAREA" || el.tagName === "INPUT" || el.isContentEditable);
  };
  const update = () => {
    if (!typing()) full = window.innerHeight; // rotation, split view
    const open = typing() && vv.height < full - 120;
    root.classList.toggle("keyboard-open", open);
    // iOS pans the visual viewport over the page instead of resizing it:
    // size the app to what's visible and move it to where that is.
    const app = document.getElementById("root");
    root.style.height = open ? `${vv.height}px` : "";
    if (app) app.style.transform = open && vv.offsetTop > 0 ? `translateY(${vv.offsetTop}px)` : "";
    if (!open && window.scrollY !== 0) window.scrollTo(0, 0);
  };
  vv.addEventListener("resize", update);
  vv.addEventListener("scroll", update);
  window.addEventListener("focusin", update);
  window.addEventListener("focusout", () => setTimeout(update, 50));
}
