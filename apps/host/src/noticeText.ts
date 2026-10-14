// What the host's banner says for each runtime notice (`list_notices`).
// Plain functions, tested in tests/noticeText.test.ts.
import type { Notice } from "@mycel/sdk";

export interface NoticeView {
  /** The same while it's the same notice (the banner hides it at once when dismissed). */
  key: string;
  text: string;
  /** Still going on: shown until it clears, with no dismiss button. */
  ongoing: boolean;
  /** Offer a way to fix it: "network" opens the Network panel. */
  action: "network" | null;
}

export function noticeView(notice: Notice): NoticeView {
  switch (notice.kind) {
    case "identityReplaced":
      return {
        key: `identityReplaced:${notice.keptIn}`,
        text:
          "Your previous Mycel identity isn't available on this device, so a new one was started. " +
          `Share your new contact code with your contacts. The old data is kept in ${notice.keptIn}.`,
        ongoing: false,
        action: null,
      };
    case "networkModeReset":
      return {
        key: "networkModeReset",
        text: "Mycel couldn't read your network setting, so it was set to Local only. You can change it in Network.",
        ongoing: false,
        action: "network",
      };
    case "recordsSetAside":
      return {
        key: `recordsSetAside:${notice.count}`,
        text:
          `${notice.count} damaged stored ${notice.count === 1 ? "record was" : "records were"} set aside (kept, not deleted). ` +
          "Some history may be missing until the people in those chats sync it again.",
        ongoing: false,
        action: null,
      };
    case "storageFailing":
      return {
        key: "storageFailing",
        text:
          `Saving on this device is failing (${withoutPaths(notice.error)}). ` +
          "New messages can't be sent until it recovers; Mycel keeps trying.",
        ongoing: true,
        action: null,
      };
  }
}

/**
 * An error message without file paths: the banner names what went wrong
 * ("No space left on device"), not where this device keeps its data. A word
 * is a path when it starts like one (`/`, `~/`, `C:\`) or has two or more
 * separators; a path with spaces spans several words, which become one "…".
 */
export function withoutPaths(text: string): string {
  const isPath = (word: string) =>
    /^(?:~?\/|[A-Za-z]:[\\/]|\\\\)/.test(word) || (word.match(/[\\/]/g)?.length ?? 0) >= 2;
  const out: string[] = [];
  let pathOpen: string | null = null; // punctuation before the path being replaced
  for (const word of text.split(" ")) {
    const [, open = "", core = "", close = ""] = /^(['"`(]*)(.*?)(['"`),;:.]*)$/s.exec(word) ?? [];
    if (!isPath(core)) {
      out.push(word);
      pathOpen = null;
    } else if (pathOpen === null) {
      pathOpen = open;
      out.push(`${open}…${close}`);
    } else {
      out[out.length - 1] = `${pathOpen}…${close}`;
    }
  }
  return out.join(" ");
}
