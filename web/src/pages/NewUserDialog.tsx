import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Checkbox,
  CodeBlock,
  Dialog,
  Input,
  useToast,
} from "@lusopoint/luso-ui";

import { ApiError, api } from "../lib/api";
import type { CreateUserRequest, CreateUserResponse } from "../lib/types";

interface Props {
  open: boolean;
  onClose: () => void;
  // called when a user is successfully created, so the list refreshes
  onCreated: () => void;
}

const EMPTY: CreateUserRequest = {
  email: "",
  display_name: "",
  username: "",
  is_admin: false,
  email_verified: true,
};

const NewUserDialog = ({ open, onClose, onCreated }: Props) => {
  const toast = useToast();
  const [form, setForm] = useState<CreateUserRequest>(EMPTY);
  const [generatePassword, setGeneratePassword] = useState(true);
  const [manualPassword, setManualPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CreateUserResponse | null>(null);

  // reset everything when the dialog opens fresh, doing this on `open`
  // rather than on mount lets us reuse the component instance across
  // multiple opens without stale fields
  useEffect(() => {
    if (!open) return;
    setForm(EMPTY);
    setGeneratePassword(true);
    setManualPassword("");
    setError(null);
    setResult(null);
  }, [open]);

  // Esc to cancel, but only during the form step
  useEffect(() => {
    if (!open || result) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, result, onClose]);

  const submit = async () => {
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

  const valid =
    form.email.trim() !== "" && (generatePassword || manualPassword.length >= 12);

  const requestClose = () => {
    if (result) return;
    onClose();
  };

  if (result) {
    const u = result.user;
    return (
      <Dialog
        isOpen={open}
        onClose={requestClose}
        title="User created"
        footer={<Button onClick={onClose}>Done</Button>}
      >
        <div className="space-y-4">
          <p className="font-semibold text-on-surface">{u.email || u.username || u.id}</p>

          {result.generated_password && (
            <Alert variant="warning" title="Temporary password">
              <p>
                This is the only time you'll see this. Copy it now and share it with the
                user through a private channel.
              </p>
              <CodeBlock
                value={result.generated_password}
                inline
                className="mt-2"
                onCopied={() => toast.success("Copied to clipboard")}
              />
            </Alert>
          )}

          <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Pair label="User ID" value={<code className="font-mono text-xs">{u.id}</code>} />
            <Pair label="Status" value={u.status} />
            {u.is_admin && <Pair label="Admin" value="yes" />}
            <Pair label="Email verified" value={u.email_verified ? "yes" : "no"} />
          </dl>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      isOpen={open}
      onClose={requestClose}
      title="New user"
      className="max-w-lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || !valid}>
            {busy ? "Creating…" : "Create user"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-xs text-on-surface-variant">
          The user will sign in with this email and the password below.
        </p>

        {error && <Alert variant="error">{error}</Alert>}

        <Input
          label="Email *"
          type="email"
          required
          autoComplete="off"
          placeholder="alice@example.com"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
        />

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Input
            label="Display name"
            autoComplete="off"
            placeholder="Alice Smith"
            value={form.display_name ?? ""}
            onChange={(e) => setForm({ ...form, display_name: e.target.value })}
          />
          <Input
            label="Username"
            autoComplete="off"
            placeholder="alice"
            value={form.username ?? ""}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
          />
        </div>

        <div className="space-y-3">
          <Checkbox
            label="Generate a strong password"
            description="Shown once after creation. Tell the user out-of-band."
            checked={generatePassword}
            onChange={(e) => setGeneratePassword(e.target.checked)}
          />

          {!generatePassword && (
            <Input
              type="password"
              autoComplete="new-password"
              placeholder="≥ 12 characters"
              value={manualPassword}
              onChange={(e) => setManualPassword(e.target.value)}
              error={
                manualPassword.length > 0 && manualPassword.length < 12
                  ? "Must be at least 12 characters."
                  : undefined
              }
            />
          )}
        </div>

        <Checkbox
          label="Grant admin privileges"
          checked={form.is_admin ?? false}
          onChange={(e) => setForm({ ...form, is_admin: e.target.checked })}
        />

        <Checkbox
          label="Mark email as verified"
          description="Skip the (future) email-verification flow. Default on for admin-created accounts."
          checked={form.email_verified ?? true}
          onChange={(e) => setForm({ ...form, email_verified: e.target.checked })}
        />
      </div>
    </Dialog>
  );
}

const Pair = ({ label, value }: { label: string; value: React.ReactNode }) => (
  <div>
    <dt className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant">
      {label}
    </dt>
    <dd className="mt-0.5 text-sm text-on-surface">{value}</dd>
  </div>
);

export default NewUserDialog
