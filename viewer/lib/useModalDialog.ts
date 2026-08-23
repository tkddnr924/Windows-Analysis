"use client";

import { useEffect, useRef } from "react";

const FOCUSABLE = [
  "button:not([disabled])",
  "[href]",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

// Dialogs can be nested (for example, a full code view opened from the shared
// evidence drawer). Document-level keyboard handlers receive the same Escape
// event, so the stack is the single authority for which dialog may close it.
// Keep this at module scope because nested dialog components do not share a
// React parent state contract.
const modalStack: symbol[] = [];

/**
 * Keeps overlay dialogs self-contained: keyboard focus stays inside, Escape
 * closes the dialog, background scrolling is suspended, and the invoking
 * control regains focus after close. Docked inspectors deliberately do not
 * use this hook because they are part of the page, not modal UI.
 */
export function useModalDialog(onClose: () => void, active = true) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const modalId = useRef<symbol | null>(null);
  const onCloseRef = useRef(onClose);
  if (!modalId.current) modalId.current = Symbol("modal-dialog");

  // A parent may re-render while a nested dialog is open. Updating the close
  // callback must not unregister/re-register it and accidentally make it the
  // top-most dialog in the stack.
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!active) return;
    const id = modalId.current!;
    modalStack.push(id);
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const focusInitial = () => {
      const dialog = dialogRef.current;
      if (!dialog) return;
      const preferred = dialog.querySelector<HTMLElement>("[data-dialog-autofocus]");
      const first = dialog.querySelector<HTMLElement>(FOCUSABLE);
      (preferred ?? first ?? dialog).focus();
    };
    const frame = window.requestAnimationFrame(focusInitial);

    const onKeyDown = (event: KeyboardEvent) => {
      if (modalStack[modalStack.length - 1] !== id) return;
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const targets = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE))
        .filter((element) => !element.hasAttribute("disabled") && element.offsetParent !== null);
      if (targets.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = targets[0];
      const last = targets[targets.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      window.cancelAnimationFrame(frame);
      document.removeEventListener("keydown", onKeyDown);
      const stackIndex = modalStack.lastIndexOf(id);
      if (stackIndex >= 0) modalStack.splice(stackIndex, 1);
      document.body.style.overflow = previousOverflow;
      if (previousFocus?.isConnected) previousFocus.focus();
    };
  }, [active]);

  return dialogRef;
}
