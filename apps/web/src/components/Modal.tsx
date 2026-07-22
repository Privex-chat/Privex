// Reusable, theme-aware dialog to replace window.confirm/prompt (which can't be
// styled and look out of place). Closes on Escape or a backdrop click; the panel
// itself swallows the click so only the backdrop dismisses.
import { useEffect } from "react";

export function Modal({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-overlay p-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-sm rounded-2xl border border-divider bg-elevated p-5 shadow-xl">
        {title && <h2 className="text-base font-semibold text-text-primary">{title}</h2>}
        <div className={title ? "mt-3" : ""}>{children}</div>
      </div>
    </div>
  );
}

/** Yes/no confirmation. `danger` styles the confirm button as destructive. */
export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  danger = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  message?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Modal open={open} onClose={onCancel} title={title}>
      {message && <div className="text-sm text-text-secondary">{message}</div>}
      <div className="mt-5 flex justify-end gap-2">
        <button
          onClick={onCancel}
          className="rounded-lg border border-border-strong px-4 py-2 text-sm text-text-secondary transition-colors hover:bg-raised"
        >
          {cancelLabel}
        </button>
        <button
          onClick={onConfirm}
          className={
            "rounded-lg px-4 py-2 text-sm font-medium text-white transition-colors " +
            (danger ? "bg-danger-bg hover:bg-danger-hover" : "bg-accent hover:bg-accent-hover")
          }
        >
          {confirmLabel}
        </button>
      </div>
    </Modal>
  );
}
