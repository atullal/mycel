import { useRef } from "react";
import "./search-field.css";

/**
 * A search box for filtering lists on this device (contacts, people nearby,
 * conversations). Styled with the host's design tokens; pass `className` to
 * place it. Pair it with `matchesSearch` from `@mycel/sdk`.
 */
export function SearchField({
  value,
  onChange,
  label,
  placeholder = label,
  autoFocus,
  className = "",
}: {
  value: string;
  onChange: (value: string) => void;
  /** Accessible name of the field (and its placeholder unless one is given). */
  label: string;
  placeholder?: string;
  autoFocus?: boolean;
  className?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <div className={`mycel-search-field ${className}`} role="search" aria-label={label}>
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
        <circle cx="10.5" cy="10.5" r="6.5" />
        <path d="m16 16 5 5" />
      </svg>
      <input
        ref={input}
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={label}
        placeholder={placeholder}
        autoFocus={autoFocus}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
      />
      {value && (
        <button
          type="button"
          aria-label={`Clear ${label.toLowerCase()}`}
          onClick={() => {
            onChange("");
            input.current?.focus();
          }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
            <path d="m6 6 12 12M18 6 6 18" />
          </svg>
        </button>
      )}
    </div>
  );
}
