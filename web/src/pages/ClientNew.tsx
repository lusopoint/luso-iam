import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import PageHeader from "../components/PageHeader";
import { ScopesEditor } from "../components/ScopesEditor";
import { SecretBanner } from "./Clients";
import { ApiError, api } from "../lib/api";
import type { CreateClientRequest, OIDCClient } from "../lib/types";

/*
 * Register a new OIDC client. The form mirrors the createClient endpoint
 * exactly — required fields are validated client-side for nicer feedback,
 * but the server is the source of truth.
 *
 * Public clients (SPAs, mobile apps) get no secret; PKCE is forced on
 * server-side for them regardless of the checkbox. Confidential clients
 * receive a one-time plaintext secret in the response and may opt out of
 * PKCE via the "Require PKCE" toggle.
 */

export default function ClientNew() {
  const navigate = useNavigate();

  const [form, setForm] = useState<CreateClientRequest>({
    id: "",
    name: "",
    redirect_uris: [""],
    allowed_scopes: ["openid", "profile", "email"],
    allowed_grant_types: ["authorization_code", "refresh_token"],
    is_public: false,
    require_pkce: true,
    require_consent: false,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ client: OIDCClient; secret?: string } | null>(null);

  function updateField<K extends keyof CreateClientRequest>(k: K, v: CreateClientRequest[K]) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  function setRedirect(i: number, v: string) {
    setForm((f) => {
      const next = [...f.redirect_uris];
      next[i] = v;
      return { ...f, redirect_uris: next };
    });
  }

  function addRedirect() {
    setForm((f) => ({ ...f, redirect_uris: [...f.redirect_uris, ""] }));
  }

  function removeRedirect(i: number) {
    setForm((f) => ({ ...f, redirect_uris: f.redirect_uris.filter((_, j) => j !== i) }));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const cleaned: CreateClientRequest = {
        ...form,
        redirect_uris: form.redirect_uris.map((u) => u.trim()).filter(Boolean),
      };
      const res = await api.createClient(cleaned);
      setCreated({ client: res.client, secret: res.secret });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    return (
      <>
        <PageHeader
          title="Client registered"
          subtitle={`"${created.client.name}" is ready to use.`}
          actions={<Link to="/clients" className="btn-secondary">Back to clients</Link>}
        />
        {created.secret ? (
          <SecretBanner
            title={`Client secret for "${created.client.id}"`}
            secret={created.secret}
            onDismiss={() => navigate("/clients")}
          />
        ) : (
          <div className="card p-4 text-sm">
            <p>This is a public client. No secret was issued.</p>
          </div>
        )}
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Register OIDC client"
        actions={<Link to="/clients" className="btn-secondary">Cancel</Link>}
      />

      <form onSubmit={submit} className="card max-w-2xl p-5 space-y-5">
        {error && (
          <div className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/40 dark:text-red-300">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="id">Client ID</label>
            <input
              id="id"
              className="input font-mono"
              value={form.id}
              onChange={(e) => updateField("id", e.target.value)}
              placeholder="my-app"
              required
            />
            <p className="hint">Stable identifier; no whitespace, no slashes.</p>
          </div>
          <div>
            <label className="label" htmlFor="name">Display name</label>
            <input
              id="name"
              className="input"
              value={form.name}
              onChange={(e) => updateField("name", e.target.value)}
              placeholder="My App"
              required
            />
          </div>
        </div>

        <div>
          <label className="label">Redirect URIs</label>
          <div className="space-y-2">
            {form.redirect_uris.map((u, i) => (
              <div key={i} className="flex gap-2">
                <input
                  className="input"
                  value={u}
                  onChange={(e) => setRedirect(i, e.target.value)}
                  placeholder="https://app.example.com/callback"
                />
                {form.redirect_uris.length > 1 && (
                  <button type="button" onClick={() => removeRedirect(i)} className="btn-secondary">
                    Remove
                  </button>
                )}
              </div>
            ))}
            <button type="button" onClick={addRedirect} className="btn-secondary">
              + Add another
            </button>
          </div>
          <p className="hint">Absolute http or https URLs. At least one required.</p>
        </div>

        <div>
          <label className="label">Allowed scopes</label>
          <ScopesEditor
            value={form.allowed_scopes ?? []}
            onChange={(next) => updateField("allowed_scopes", next)}
          />
          <p className="hint">Scopes this client may request. Include <span className="font-mono">offline_access</span> to allow refresh tokens.</p>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Checkbox
            label="Public client (no secret)"
            hint="SPAs and mobile apps. PKCE is mandatory."
            checked={form.is_public}
            onChange={(v) =>
              // Public clients always require PKCE (the server enforces this
              // too). Keep the form payload consistent by forcing the flag
              // on when public is selected.
              setForm((f) => ({ ...f, is_public: v, require_pkce: v ? true : f.require_pkce }))
            }
          />
          <Checkbox
            label="Require PKCE (S256)"
            hint={
              form.is_public
                ? "Always required for public clients."
                : "Recommended. Disable only for confidential clients that can't send a code_challenge (e.g. some server-to-server flows)."
            }
            checked={form.is_public ? true : (form.require_pkce ?? false)}
            disabled={form.is_public}
            onChange={(v) => updateField("require_pkce", v)}
          />
          <Checkbox
            label="Require user consent"
            hint="Show a consent screen on first authorization."
            checked={form.require_consent}
            onChange={(v) => updateField("require_consent", v)}
          />
        </div>

        <div className="flex justify-end gap-2">
          <Link to="/clients" className="btn-secondary">Cancel</Link>
          <button type="submit" disabled={busy} className="btn-primary">
            {busy ? "Registering…" : "Register client"}
          </button>
        </div>
      </form>
    </>
  );
}

function Checkbox({ label, hint, checked, onChange, disabled }: {
  label: string; hint?: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean;
}) {
  return (
    <label className={`flex items-start gap-2 text-sm ${disabled ? "opacity-60" : ""}`}>
      <input
        type="checkbox"
        className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        <span className="font-medium text-slate-800 dark:text-slate-200">{label}</span>
        {hint && <span className="block text-xs text-slate-500 dark:text-slate-400">{hint}</span>}
      </span>
    </label>
  );
}
