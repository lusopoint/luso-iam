import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

/*
 * Confirm dialog. Imperative promise-based API so callers don't have to
 * thread state through every component that issues a destructive action.
 *
 *   const confirm = useConfirm();
 *   if (await confirm({ title: "Delete user?", danger: true })) { ... }
 *
 * One <ConfirmProvider> mounted near the root holds the queue. Multiple
 * concurrent confirms aren't supported by design — admin tools should
 * never produce that situation, and resolving it cleanly is more
 * complexity than it's worth.
 */

interface ConfirmRequest {
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Use red button styling for destructive actions (delete, revoke, etc). */
  danger?: boolean;
}

type ConfirmFn = (req: ConfirmRequest) => Promise<boolean>;

const Ctx = createContext<ConfirmFn | null>(null);

export function useConfirm(): ConfirmFn {
  const v = useContext(Ctx);
  if (!v) throw new Error("useConfirm must be used inside <ConfirmProvider>");
  return v;
}

interface PendingState {
  req: ConfirmRequest;
  resolve: (ok: boolean) => void;
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingState | null>(null);

  const confirm = useCallback<ConfirmFn>(
    (req) =>
      new Promise<boolean>((resolve) => {
        setPending({ req, resolve });
      }),
    [],
  );

  const settle = useCallback(
    (ok: boolean) => {
      if (!pending) return;
      pending.resolve(ok);
      setPending(null);
    },
    [pending],
  );

  // Auto-focus the confirm button and trap Esc to cancel. The dialog
  // itself uses role="dialog" + aria-modal so screen readers announce it.
  const confirmBtn = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!pending) return;
    confirmBtn.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") settle(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pending, settle]);

  return (
    <Ctx.Provider value={confirm}>
      {children}
      {pending && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="confirm-title"
          className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 p-3 backdrop-blur-sm
                     sm:items-center"
          // Click outside cancels — but only on the backdrop, not on the
          // inner card. Using a stopPropagation on the card is the
          // simplest way to keep this honest.
          onClick={() => settle(false)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-sm overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl
                       dark:border-slate-800 dark:bg-slate-900"
          >
            <div className="p-4">
              <h2 id="confirm-title" className="text-base font-semibold text-slate-900 dark:text-slate-100">
                {pending.req.title}
              </h2>
              {pending.req.message && (
                <p className="mt-1.5 text-sm text-slate-600 dark:text-slate-400">
                  {pending.req.message}
                </p>
              )}
            </div>
            <div className="flex flex-col-reverse gap-2 border-t border-slate-100 p-3 sm:flex-row sm:justify-end dark:border-slate-800">
              <button
                onClick={() => settle(false)}
                className="btn-secondary"
              >
                {pending.req.cancelLabel ?? "Cancel"}
              </button>
              <button
                ref={confirmBtn}
                onClick={() => settle(true)}
                className={pending.req.danger ? "btn-danger" : "btn-primary"}
              >
                {pending.req.confirmLabel ?? "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </Ctx.Provider>
  );
}
