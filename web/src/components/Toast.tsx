import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

/*
 * Toast notifications. A single ToastProvider mounted near the root holds
 * the queue; pages call useToast() to push success / error / info messages.
 *
 * The design priorities, in order:
 *  - Reachable. The viewport sits at top-right on desktop and top-center
 *    on mobile so a thumb can dismiss without crossing the screen.
 *  - Non-blocking. Toasts auto-dismiss after a few seconds; the timer
 *    pauses on hover (useful when reading a longer error).
 *  - Honest. Errors are red, success is emerald — colour matches the
 *    badges used elsewhere in the SPA so the visual language is consistent.
 *  - Polite by default. Each toast carries `role="status"` for success
 *    and `role="alert"` for errors so screen readers announce them.
 *
 * Implementation note: we keep this hand-rolled rather than pulling in
 * react-hot-toast or sonner. The whole module is < 150 lines and our
 * needs are bounded.
 */

type ToastKind = "success" | "error" | "info";

interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  /** Optional sub-line shown beneath the main message in a smaller weight. */
  detail?: string;
  /** Time-to-live in ms. 0 means "sticky — only dismissible by user click." */
  ttl: number;
}

interface ToastContextValue {
  push: (t: Omit<Toast, "id">) => void;
  success: (message: string, detail?: string) => void;
  error: (message: string, detail?: string) => void;
  info: (message: string, detail?: string) => void;
}

const Ctx = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const v = useContext(Ctx);
  if (!v) {
    // Hard error: forgetting to wrap the tree in ToastProvider is a bug,
    // not a runtime condition. Easier to find now than via a silent no-op.
    throw new Error("useToast must be used inside <ToastProvider>");
  }
  return v;
}

const DEFAULT_TTL = 4000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  // nextId is a ref because incrementing it shouldn't trigger renders.
  const nextId = useRef(1);

  const remove = useCallback((id: number) => {
    setItems((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = nextId.current++;
    setItems((prev) => [...prev, { ...t, id }]);
  }, []);

  // Convenience wrappers so callers don't have to remember kind names.
  const value = useMemo<ToastContextValue>(
    () => ({
      push,
      success: (message, detail) => push({ kind: "success", message, detail, ttl: DEFAULT_TTL }),
      error:   (message, detail) => push({ kind: "error",   message, detail, ttl: 7000 }),
      info:    (message, detail) => push({ kind: "info",    message, detail, ttl: DEFAULT_TTL }),
    }),
    [push],
  );

  return (
    <Ctx.Provider value={value}>
      {children}
      <Viewport items={items} onDismiss={remove} />
    </Ctx.Provider>
  );
}

// ─── Viewport ──────────────────────────────────────────────────────────────

function Viewport({
  items,
  onDismiss,
}: {
  items: Toast[];
  onDismiss: (id: number) => void;
}) {
  return (
    <div
      // Top-center on mobile, top-right on desktop. fixed inset so we
      // sit above any modal stack; pointer-events-none on the container
      // so toasts don't block clicks outside their own surface.
      className="pointer-events-none fixed inset-x-0 top-0 z-50 flex flex-col items-center gap-2 px-3 pt-3
                 sm:inset-x-auto sm:right-3 sm:items-end"
      aria-live="polite"
    >
      {items.map((t) => (
        <ToastItem key={t.id} toast={t} onDismiss={() => onDismiss(t.id)} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const [paused, setPaused] = useState(false);
  // Track when the toast was opened; restart the timer when the user
  // un-hovers so reading time isn't lost when they look away.
  const startRef = useRef<number>(Date.now());
  const remainingRef = useRef<number>(toast.ttl);

  useEffect(() => {
    if (toast.ttl === 0 || paused) return;
    startRef.current = Date.now();
    const handle = window.setTimeout(onDismiss, remainingRef.current);
    return () => {
      window.clearTimeout(handle);
      // Decrement remaining time when paused so resume picks up where it left off.
      remainingRef.current = Math.max(
        0,
        remainingRef.current - (Date.now() - startRef.current),
      );
    };
  }, [paused, toast.ttl, onDismiss]);

  const kindClasses = classesForKind(toast.kind);

  return (
    <div
      role={toast.kind === "error" ? "alert" : "status"}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      className={`pointer-events-auto w-full max-w-sm rounded-lg border px-3 py-2 shadow-sm
                  backdrop-blur-sm transition ${kindClasses}`}
    >
      <div className="flex items-start gap-2">
        <Icon kind={toast.kind} />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">{toast.message}</p>
          {toast.detail && (
            <p className="mt-0.5 text-xs opacity-80">{toast.detail}</p>
          )}
        </div>
        <button
          onClick={onDismiss}
          aria-label="Dismiss"
          className="shrink-0 rounded p-0.5 text-current opacity-60 hover:opacity-100"
        >
          <svg viewBox="0 0 20 20" className="h-4 w-4" fill="currentColor" aria-hidden>
            <path d="M5.7 5.7a1 1 0 0 1 1.4 0L10 8.6l2.9-2.9a1 1 0 1 1 1.4 1.4L11.4 10l2.9 2.9a1 1 0 0 1-1.4 1.4L10 11.4l-2.9 2.9a1 1 0 0 1-1.4-1.4L8.6 10 5.7 7.1a1 1 0 0 1 0-1.4Z" />
          </svg>
        </button>
      </div>
    </div>
  );
}

function classesForKind(k: ToastKind): string {
  switch (k) {
    case "success":
      return "border-emerald-200 bg-emerald-50/95 text-emerald-900 dark:border-emerald-900/50 dark:bg-emerald-950/80 dark:text-emerald-100";
    case "error":
      return "border-red-200 bg-red-50/95 text-red-900 dark:border-red-900/50 dark:bg-red-950/80 dark:text-red-100";
    case "info":
      return "border-slate-200 bg-white/95 text-slate-900 dark:border-slate-800 dark:bg-slate-900/90 dark:text-slate-100";
  }
}

function Icon({ kind }: { kind: ToastKind }) {
  const cls = "h-5 w-5 shrink-0";
  switch (kind) {
    case "success":
      return (
        <svg viewBox="0 0 20 20" className={cls} fill="currentColor" aria-hidden>
          <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.7-9.3a1 1 0 0 0-1.4-1.4L9 10.6 7.7 9.3a1 1 0 0 0-1.4 1.4l2 2a1 1 0 0 0 1.4 0l4-4Z" clipRule="evenodd" />
        </svg>
      );
    case "error":
      return (
        <svg viewBox="0 0 20 20" className={cls} fill="currentColor" aria-hidden>
          <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm1-11a1 1 0 1 0-2 0v4a1 1 0 1 0 2 0V7Zm-1 8a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z" clipRule="evenodd" />
        </svg>
      );
    case "info":
      return (
        <svg viewBox="0 0 20 20" className={cls} fill="currentColor" aria-hidden>
          <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm-.5-9a.5.5 0 0 0-.5.5v4a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-4a.5.5 0 0 0-.5-.5h-1ZM10 7.5a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" clipRule="evenodd" />
        </svg>
      );
  }
}
