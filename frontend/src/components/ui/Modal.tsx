"use client";

import * as React from "react";

import { Button } from "./Button";

/** Native modal semantics keep keyboard focus and background interaction isolated. */
export function Modal({
  title,
  children,
  onClose,
}: {
  title: React.ReactNode;
  children: React.ReactNode;
  onClose: () => void;
}) {
  const dialog = React.useRef<HTMLDialogElement>(null);
  const titleId = React.useId();

  React.useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    const opener = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    element.showModal();
    document.body.style.overflow = "hidden";
    return () => {
      element.close();
      document.body.style.overflow = previousOverflow;
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  }, []);

  return (
    <dialog
      ref={dialog}
      aria-labelledby={titleId}
      aria-modal="true"
      className="m-auto max-h-[90dvh] w-[calc(100%_-_2rem)] max-w-2xl overflow-y-auto rounded-xl border border-line bg-surface p-6 text-fg shadow-xl backdrop:bg-black/60"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className="mb-5 flex items-center justify-between gap-4">
        <h2 id={titleId} className="text-lg font-semibold">{title}</h2>
        <Button type="button" variant="ghost" size="sm" onClick={onClose} aria-label="Close dialog">
          Close
        </Button>
      </div>
      {children}
    </dialog>
  );
}
