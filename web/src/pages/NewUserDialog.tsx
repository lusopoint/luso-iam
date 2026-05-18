import { useEffect, useRef, useState } from "react";

import CopyButton from "../components/CopyButton";
import { ApiError, api } from "../lib/api";
import type { CreateUserRequest, CreateUserResponse } from "../lib/types";

/*
 * NewUserDialog: modal-style form for creating a user.
 *
 * Two states, in order:
 *   1. Form — operator fills in email + options. Password is optional;
 *      a "Generate" toggle is on by default.
 *   2. Result — when the server returns a generated password, we show
 *      it in a banner with a Copy button. The result panel must be
 *      dismissed explicitly (it isn't auto-cleared) so the operator
 *      doesn't lose the one-time secret.
 *
 * Lives next to the Users page rather than as a top-level component
 * because its state machine (form → result) only makes sense in the
 * context of the user list refresh.
 */

interface Props {
  open: boolean;
  onClose: () => void;
  /** Called when a user is successfully created, so the list refreshes. */
  onCreated: () => void;
}

export default function NewUserDialog({ open, onClose, onCreated }: Props) {
  // Esc cancels (only when no result is being shown — once we've created
  // the user, dismissing must be a deliberate click so the password isn't
  // accidentally lost).
  const [form, setForm] = useState<CreateUserRequest>({
    email: "",
    display_name: "",
    username: "",
    is_admin: false,
    email_verified: true,
  });
  const [generatePassword, setGeneratePassword] = useState(true);
  const [manualPassword, setManualPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CreateUserResponse | null>(null);

  // Reset everything when the dialog opens fresh. Doing this on `open`
  // rather than on mount lets us reuse the component instance across
  // multiple opens without stale fields.
  useEffect(() => {
    if (!open) return;
    setForm({
      email: "",
      display_name: "",
      username: "",
      is_admin: false,
      email_verified: true,
    });
    setGeneratePassword(true);
    setManualPassword("");
    setError(null);
    setResult(null);
  }, [open]);

  // Esc-to-cancel, but only during the form step.
  useEffect(() => {
    if (!open || result) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, result, onClose]);

  const firstField = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (open && !result) firstField.current?.focus();
  }, [open, result]);

  if (!open) return null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const body: CreateUserRequest = {
        email: form.email.trim(),
        // Empty strings → omit, so optional columns stay NULL.
        display_name: form.display_name?.trim() || undefined,
        username: form.username?.trim() || undefined,
        is_admin: form.is_admin,
        email_verified: form.email_verified,
      };
      if (!generatePassword) {
        body.password = manualPassword;
      }
      const res = await api.createUser(body);
      setResult(res);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      // Mobile: bottom-sheet feel; desktop: centered modal.
      className="fixed inset-0 z-40 flex items-end justify-center bg-black/40 p-3 backdrop-blur-sm sm:items-center"
      onClick={() => {
        // Backdrop dismisses, but ONLY when we're not showing the
        // generated password — losing it on a stray click is bad UX.
        if (!result) onClose();
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="new-user-title"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-lg overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl
                   dark:border-slate-800 dark:bg-slate-900"
      >
        {result ? (
          <ResultPanel result={result} onDismiss={onClose} />
        ) : (
          <form onSubmit={submit}>
            <div className="border-b border-slate-100 px-4 py-3 dark:border-slate-800">
              <h2 id="new-user-title" className="text-base font-semibold text-slate-900 dark:text-slate-100">
                New user
              </h2>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                The user will sign in with this email and the password below.
              </p>
            </div>

            <div className="space-y-3 p-4">
              <Field label="Email" required>
                <input
                  ref={firstField}
                  className="input"
                  type="email"
                  required
                  autoComplete="off"
                  placeholder="alice@example.com"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                />
              </Field>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Field label="Display name">
                  <input
                    className="input"
                    type="text"
                    autoComplete="off"
                    placeholder="Alice Smith"
                    value={form.display_name ?? ""}
                    onChange={(e) => setForm({ ...form, display_name: e.target.value })}
                  />
                </Field>
                <Field label="Username">
                  <input
                    className="input"
                    type="text"
                    autoComplete="off"
                    placeholder="alice"
                    value={form.username ?? ""}
                    onChange={(e) => setForm({ ...form, username: e.target.value })}
                  />
                </Field>
              </div>

              <div>
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={generatePassword}
                    onChange={(e) => setGeneratePassword(e.target.checked)}
                  />
                  <span>
                    <span className="font-medium text-slate-700 dark:text-slate-300">Generate a strong password</span>
                    <span className="block text-xs text-slate-500 dark:text-slate-400">
                      Shown once after creation. Tell the user out-of-band.
                    </span>
                  </span>
                </label>

                {!generatePassword && (
                  <div className="mt-2">
                    <input
                      className="input"
                      type="password"
                      autoComplete="new-password"
                      placeholder="≥ 12 characters"
                      value={manualPassword}
                      onChange={(e) => setManualPassword(e.target.value)}
                      minLength={12}
                      required
                    />
                  </div>
                )}
              </div>

              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.is_admin ?? false}
                  onChange={(e) => setForm({ ...form, is_admin: e.target.checked })}
                />
                <span className="font-medium text-slate-700 dark:text-slate-300">Grant admin privileges</span>
              </label>

              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={form.email_verified ?? true}
                  onChange={(e) => setForm({ ...form, email_verified: e.target.checked })}
                />
                <span>
                  <span className="font-medium text-slate-700 dark:text-slate-300">Mark email as verified</span>
                  <span className="block text-xs text-slate-500 dark:text-slate-400">
                    Skip the (future) email-verification flow. Default on for admin-created accounts.
                  </span>
                </span>
              </label>

              {error && (
                <div className="rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-300">
                  {error}
                </div>
              )}
            </div>

            <div className="flex flex-col-reverse gap-2 border-t border-slate-100 p-3 sm:flex-row sm:justify-end dark:border-slate-800">
              <button type="button" onClick={onClose} disabled={busy} className="btn-secondary">
                Cancel
              </button>
              <button type="submit" disabled={busy} className="btn-primary">
                {busy ? "Creating…" : "Create user"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

// ─── Result panel ─────────────────────────────────────────────────────────

function ResultPanel({ result, onDismiss }: { result: CreateUserResponse; onDismiss: () => void }) {
  const u = result.user;
  return (
    <>
      <div className="border-b border-slate-100 px-4 py-3 dark:border-slate-800">
        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
          User created
        </h2>
        <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
          {u.email || u.username || u.id}
        </p>
      </div>
      <div className="space-y-3 p-4">
        {result.generated_password && (
          <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 dark:border-amber-700/50 dark:bg-amber-950/40">
            <h3 className="text-sm font-semibold text-amber-900 dark:text-amber-200">
              Temporary password
            </h3>
            <p className="mt-1 text-xs text-amber-800/80 dark:text-amber-300/80">
              This is the only time you'll see this. Copy it now and share it
              with the user through a private channel.
            </p>
            <div className="mt-2 flex items-start gap-2 rounded bg-white p-2 dark:bg-slate-900">
              <code className="min-w-0 flex-1 break-all font-mono text-xs text-slate-900 dark:text-slate-100">
                {result.generated_password}
              </code>
              <CopyButton value={result.generated_password} toastOnSuccess label="" className="shrink-0" />
            </div>
          </div>
        )}
        <dl className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
          <Pair label="User ID" value={<code className="font-mono text-xs">{u.id}</code>} />
          <Pair label="Status" value={u.status} />
          {u.is_admin && <Pair label="Admin" value="yes" />}
          <Pair label="Email verified" value={u.email_verified ? "yes" : "no"} />
        </dl>
      </div>
      <div className="flex justify-end border-t border-slate-100 p-3 dark:border-slate-800">
        <button onClick={onDismiss} className="btn-primary">Done</button>
      </div>
    </>
  );
}

// ─── Small bits ────────────────────────────────────────────────────────────

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="label">
        {label}
        {required && <span className="ml-0.5 text-red-500">*</span>}
      </span>
      {children}
    </label>
  );
}

function Pair({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="text-slate-800 dark:text-slate-200">{value}</dd>
    </div>
  );
}
