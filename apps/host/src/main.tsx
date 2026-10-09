import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { applyTheme, readTheme } from "./theme.ts";
import "./theme.css";
import "./host.css";

applyTheme(readTheme());
followAndroidInsets();

/**
 * Android draws the app under the status and navigation bars (and resizes it
 * above the keyboard); MainActivity reports the bars' size, which theme.css
 * folds into the --safe-* paddings. iOS reports them through env() instead.
 */
function followAndroidInsets() {
  type Insets = { top: number; right: number; bottom: number; left: number };
  const apply = (i: Insets) => {
    for (const side of ["top", "right", "bottom", "left"] as const) {
      document.documentElement.style.setProperty(`--android-inset-${side}`, `${i[side] ?? 0}px`);
    }
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
