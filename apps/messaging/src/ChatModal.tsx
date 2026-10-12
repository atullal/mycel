import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Icon } from "./ui.tsx";

/** Native modal focus isolation also keeps the underlying chat inert on iOS. */
export function ChatModal({ title, onClose, children, className = "" }: {
  title: string; onClose: () => void; children: ReactNode; className?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const el = dialog.current!;
    el.showModal();
    return () => el.close();
  }, []);
  return createPortal(
    <dialog ref={dialog} className={`mx-chat-modal ${className}`} aria-label={title}
      onCancel={(e) => { e.preventDefault(); onClose(); }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="mx-modal-body">
        <header><strong>{title}</strong><button className="mx-icon-btn" onClick={onClose} aria-label={`Close ${title}`}><Icon.X /></button></header>
        {children}
      </div>
    </dialog>, document.body,
  );
}
