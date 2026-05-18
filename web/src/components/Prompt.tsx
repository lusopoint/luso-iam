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
 * Prompt dialog. Companion to Confirm — same imperative promise-based API,
 * but with a text input. Returns the entered string on confirm, or null on
 * cancel.
 *
 *   const pwd = await prompt({
 *     title: "New password",
 *     inputType: "password",
 *     placeholder: "≥ 12 chars",
 *   });
 *   if (pwd === null) return;
 *
 * Validation lives in the call site, not here — we wouldn't be able to
 * type a generic validator across the call sites that wouldn't end up
 * being a config blob anyway. The dialog supports a `validate` callback
 * for inline feedback (returns null when valid, a string error otherwise).
 */

interface PromptRequest {
  title: string;
  message?: string;
  inputLabel?: string;
  inputType?: "text" | "password" | "email" | "url";
  placeholder?: string;
  /** Pre-filled value. Most callers leave this empty. */
  initialValue?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Returns null when valid, otherwise an error message shown below the input. */
  validate?: (value: string) => string | null;
  /** Use red button styling for destructive actions. */
  danger?: boolean;
}

type PromptFn = (req: PromptRequest) => Promise<string | null>;

const Ctx = createContext<PromptFn | null>(null);

export function usePrompt(): PromptFn {
  const v = useContext(Ctx);
  if (!v) throw new Error("usePrompt must be used inside <PromptProvider>");
  return v;
}

interface PendingState {
  req: PromptRequest;
  resolve: (v: string | null) => void;
}

export function PromptProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingState | null>(null);
  const [value, setValue] = useState("");
  const [touched, setTouched] = useState(false);

  const ask = useCallback<PromptFn>(
    (req) =>
      new Promise<string | null>((resolve) => {
        setValue(req.initialValue ?? "");
        setTouched(false);
        setPending({ req, resolve });
      }),
    [],
  );

  const settle = useCallback(
    (result: string | null) => {
      if (!pending) return;
      pending.resolve(result);
      setPending(null);
      setValue("");
      setTouched(false);
    },
    [pending],
  );

  // Auto-focus and Esc-to-cancel. The input ref drives focus; keydown
  // is window-scoped because the input itself may not have focus yet
  // when the dialog opens.
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!pending) return;
    // Defer focus one tick so the input has mounted.
    const t = window.setTimeout(() => inputRef.current?.focus(), 0);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") settle(null);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.clearTimeout(t);
      window.removeEventListener("keydown", onKey);
    };
  }, [pending, settle]);

  // Compute validation only after the user has interacted, so the
  // dialog doesn't open already-yelling-at-them.
  const validationError =
    pending && touched && pending.req.validate ? pending.req.validate(value) : null;
  const submitDisabled = pending?.req.validate
    ? pending.req.validate(value) !== null
    : value.length === 0;

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (submitDisabled) {
      setTouched(true);
      return;
    }
    settle(value);
  }

  return (
    <Ctx.Provider value={ask}>
      {children}
      {pending && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="prompt-title"
          className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 p-3 backdrop-blur-sm
                     sm:items-center"
          onClick={() => settle(null)}
        >
          <form
            onClick={(e) => e.stopPropagation()}
            onSubmit={onSubmit}
            className="w-full max-w-sm overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl
                       dark:border-slate-800 dark:bg-slate-900"
          >
            <div className="p-4">
              <h2 id="prompt-title" className="text-base font-semibold text-slate-900 dark:text-slate-100">
                {pending.req.title}
              </h2>
              {pending.req.message && (
                <p className="mt-1.5 text-sm text-slate-600 dark:text-slate-400">
                  {pending.req.message}
                </p>
              )}

              <div className="mt-3">
                {pending.req.inputLabel && (
                  <label className="label" htmlFor="prompt-input">{pending.req.inputLabel}</label>
                )}
                <input
                  id="prompt-input"
                  ref={inputRef}
                  type={pending.req.inputType ?? "text"}
                  className="input"
                  placeholder={pending.req.placeholder}
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  onBlur={() => setTouched(true)}
                  // autocomplete off for passwords — these are admin-set
                  // for someone else, not the operator's own credentials.
                  autoComplete={pending.req.inputType === "password" ? "new-password" : "off"}
                  spellCheck={false}
                />
                {validationError && (
                  <p className="mt-1 text-xs text-red-600 dark:text-red-400">{validationError}</p>
                )}
              </div>
            </div>
            <div className="flex flex-col-reverse gap-2 border-t border-slate-100 p-3 sm:flex-row sm:justify-end dark:border-slate-800">
              <button
                type="button"
                onClick={() => settle(null)}
                className="btn-secondary"
              >
                {pending.req.cancelLabel ?? "Cancel"}
              </button>
              <button
                type="submit"
                disabled={submitDisabled && touched}
                className={pending.req.danger ? "btn-danger" : "btn-primary"}
              >
                {pending.req.confirmLabel ?? "OK"}
              </button>
            </div>
          </form>
        </div>
      )}
    </Ctx.Provider>
  );
}
