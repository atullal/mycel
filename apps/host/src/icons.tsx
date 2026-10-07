import type { ReactNode } from "react";

function Svg({ children, size = 22 }: { children: ReactNode; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

/** The Mycel mark: three hyphae from one root. */
export function MycelMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <rect width="64" height="64" rx="18" fill="var(--accent)" />
      <g fill="none" stroke="var(--accent-ink)" strokeWidth="3.4" strokeLinecap="round">
        <path d="M32 52 C31 42 24 36 16 30 S9 20 10 13" />
        <path d="M32 52 C33 41 40 35 48 30 S55 19 54 12" />
        <path d="M32 52 C32 40 32 28 31 16" />
      </g>
      <g fill="var(--accent-ink)">
        <circle cx="10" cy="13" r="3.8" />
        <circle cx="54" cy="12" r="3.8" />
        <circle cx="31" cy="16" r="3.8" />
        <circle cx="32" cy="52" r="4.8" />
      </g>
    </svg>
  );
}

export const Glyph = {
  Chat: () => (
    <Svg>
      <path d="M4.5 6.5a2.5 2.5 0 0 1 2.5-2.5h10a2.5 2.5 0 0 1 2.5 2.5v7a2.5 2.5 0 0 1-2.5 2.5h-6l-4.5 3.5V16a2.5 2.5 0 0 1-2-2.5z" />
      <path d="M8.5 9h7M8.5 12h4.5" />
    </Svg>
  ),
  Doc: () => (
    <Svg>
      <path d="M14 3.5H7.5A2 2 0 0 0 5.5 5.5v13a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2V8z" />
      <path d="M14 3.5V8h4.5M8.8 12.5h6.4M8.8 16h4.2" />
    </Svg>
  ),
  News: () => (
    <Svg>
      <path d="M4 5.5h12.5v12a2 2 0 0 0 2 2H6a2 2 0 0 1-2-2z" />
      <path d="M16.5 9.5H20v8a2 2 0 0 1-2 2M7.5 9h5.5M7.5 12.5h5.5M7.5 16h3.5" />
    </Svg>
  ),
  Dice: () => (
    <Svg>
      <rect x="4" y="4" width="16" height="16" rx="3.5" />
      <path d="M8.5 8.5h.01M15.5 8.5h.01M12 12h.01M8.5 15.5h.01M15.5 15.5h.01" strokeWidth={2.6} />
    </Svg>
  ),
  Radar: () => (
    <Svg>
      <circle cx="12" cy="12" r="2" />
      <path d="M8 16a5.6 5.6 0 0 1 0-8M16 8a5.6 5.6 0 0 1 0 8M5.2 18.8a9.6 9.6 0 0 1 0-13.6M18.8 5.2a9.6 9.6 0 0 1 0 13.6" />
    </Svg>
  ),
  Contacts: () => (
    <Svg>
      <path d="M6 3.5h11.5a1.5 1.5 0 0 1 1.5 1.5v14a1.5 1.5 0 0 1-1.5 1.5H6z" />
      <path d="M6 3.5a1.5 1.5 0 0 0-1.5 1.5v14A1.5 1.5 0 0 0 6 20.5" />
      <circle cx="12.3" cy="10" r="2.4" />
      <path d="M8.8 16.2a3.6 3.6 0 0 1 7 0" />
    </Svg>
  ),
  Network: () => (
    <Svg>
      <circle cx="12" cy="12" r="2.2" />
      <circle cx="5" cy="6" r="1.6" />
      <circle cx="19" cy="7" r="1.6" />
      <circle cx="7" cy="19" r="1.6" />
      <circle cx="18.5" cy="18" r="1.6" />
      <path d="M10.3 10.6C8.6 9.8 7 8.5 6.1 7.2M13.8 10.8c1.6-.7 3.2-1.8 4.1-2.6M10.6 13.8C9.4 15.4 8.4 16.8 7.9 17.6M13.7 13.5c1.5 1.1 3 2.6 3.7 3.3" />
    </Svg>
  ),
  Close: () => (
    <Svg size={20}>
      <path d="M6 6l12 12M18 6L6 18" />
    </Svg>
  ),
  Copy: () => (
    <Svg size={18}>
      <rect x="8" y="8" width="12" height="12" rx="2.5" />
      <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
    </Svg>
  ),
  Check: () => (
    <Svg size={18}>
      <path d="M5 12.5l4.5 4.5L19 7.5" />
    </Svg>
  ),
  Pencil: () => (
    <Svg size={16}>
      <path d="M16.5 4.5a2.1 2.1 0 0 1 3 3L8.5 18.5l-4 1 1-4z" />
    </Svg>
  ),
};
