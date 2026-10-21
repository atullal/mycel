/**
 * What `background_status` reports (src-tauri/src/background.rs): how Mycel
 * keeps receiving while it's in the background on this device.
 */
export interface BackgroundStatus {
  platform: "android" | "ios" | "desktop";
  /** "always": keeps running in the background; "slow": the OS suspends Mycel and lends it time now and then. */
  mode: "always" | "slow";
  /** Android: exempt from battery optimisation. */
  batteryUnrestricted: boolean | null;
  /** Android: background use restricted by the user in Settings. */
  backgroundRestricted: boolean | null;
  /** Android: the app standby bucket. */
  standbyBucket: string | null;
  /** Android: the phone's manufacturer (lower case). */
  manufacturer: string | null;
  /** When the last background catch-up finished (ms since the epoch). */
  lastCatchUp: number | null;
}

/** What the Profile panel's "In the background" card says, and its button. */
export interface BackgroundCopy {
  /** The one-line state. */
  text: string;
  /** Why, and what to expect. */
  details: string[];
  /** A vendor-specific settings tip (Android), if one applies. */
  tip: string | null;
  /** "Allow" button: asks the system (Android's battery prompt). */
  button: string | null;
}

/**
 * Where vendor battery managers hide the switch, from dontkillmyapp.com and
 * vendor docs. Menu names change between versions: a hint, not a promise.
 * The full list is in docs/USER_GUIDE.md.
 */
const VENDOR_TIPS: Record<string, string> = {
  samsung:
    "On Samsung phones, also open Settings › Battery › Background usage limits and add Mycel to “Never sleeping apps”.",
  xiaomi:
    "On Xiaomi, Redmi and POCO phones, also turn on Autostart for Mycel and set its Battery saver to “No restrictions” (Settings › Apps › Mycel).",
  huawei:
    "On Huawei and Honor phones, also open Settings › Battery › App launch, set Mycel to “Manage manually” and turn on all three switches.",
  oneplus:
    "On OnePlus, OPPO and realme phones, also allow Mycel's background activity and auto-launch (Settings › Apps › Mycel › Battery), and lock it in Recents.",
};
const VENDOR_ALIASES: Record<string, string> = {
  redmi: "xiaomi",
  poco: "xiaomi",
  honor: "huawei",
  oppo: "oneplus",
  realme: "oneplus",
};

export function vendorTip(manufacturer: string | null): string | null {
  if (!manufacturer) return null;
  const name = manufacturer.trim().toLowerCase();
  return VENDOR_TIPS[VENDOR_ALIASES[name] ?? name] ?? null;
}

function since(ms: number, now: number): string {
  const minutes = Math.max(0, Math.round((now - ms) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  return hours < 24 ? `${hours} h ago` : `${Math.round(hours / 24)} d ago`;
}

export function backgroundCopy(status: BackgroundStatus, now = Date.now()): BackgroundCopy {
  if (status.platform === "ios") {
    const details = [
      "iPhone and iPad pause Mycel soon after you leave it. Mycel has no push server, so nothing can wake it the moment someone sends you a message.",
      "Instead, Mycel checks in when iOS lends it time (a few times a day if you use it often, more while charging), and over Bluetooth when someone running Mycel is nearby. Messages wait safely on the sender's device, or on devices that carry them, until then.",
      "Swiping Mycel away in the app switcher stops these checks until you open it again.",
    ];
    if (status.lastCatchUp) details.push(`Last background check: ${since(status.lastCatchUp, now)}.`);
    return {
      text: "Slow mode: new messages may wait until you open Mycel.",
      details,
      tip: null,
      button: null,
    };
  }
  if (status.platform === "android") {
    const details: string[] = [];
    let text: string;
    let button: string | null = null;
    if (status.backgroundRestricted) {
      text = "Android is stopping Mycel in the background.";
      details.push("Background use is restricted for Mycel. Open Settings › Apps › Mycel › Battery and choose “Unrestricted”.");
    } else if (status.batteryUnrestricted) {
      text = "Mycel stays connected in the background.";
      details.push("Messages and calls arrive while Mycel isn't open, with no push server. The “Mycel is connected” notification shows it's running.");
    } else {
      text = "Your phone may pause Mycel to save battery.";
      details.push(
        "Mycel has no push server to wake it: it receives messages by staying connected to the people and devices around you. Battery optimisation can pause that connection, so messages arrive late, or when you next open Mycel.",
        "Allowing Mycel to run in the background keeps it connected. It costs some battery, and you can change it back in Settings.",
      );
      button = "Allow background use";
    }
    if (status.standbyBucket === "restricted") {
      details.push("Android put Mycel in its most restricted group because it wasn't opened for a while. Opening Mycel now and then lifts it.");
    }
    // Vendor battery managers stop apps even when Android allows them.
    return { text, details, tip: vendorTip(status.manufacturer), button };
  }
  return {
    text: "Mycel receives messages whenever it's open on this computer.",
    details: [],
    tip: null,
    button: null,
  };
}
