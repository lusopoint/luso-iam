import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import PageHeader from "../components/PageHeader";
import { ScopesEditor } from "../components/ScopesEditor";
import { ErrorState, Loading } from "../components/States";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import type { OIDCClient } from "../lib/types";

/*
 * ClientDetail: view and edit a registered OIDC client.
 *
 * The server's PATCH endpoint accepts a subset of fields — name,
 * redirect_uris, allowed_scopes, allowed_grant_types, require_pkce,
 * require_consent, enabled. The client_id and is_public are identity- and
 * security-defining and are intentionally NOT editable here (matching the
 * API). To change those, delete and re-register.
 */

const GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials"];

export default function ClientDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const toast = useToast();

  const [client, setClient] = useState<OIDCClient | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState(false);

  // editable form fields
  const [name, setName] = useState("");
  const [redirectURIs, setRedirectURIs] = useState<string[]>([""]);
  const [scopes, setScopes] = useState<string[]>([]);
  const [grantTypes, setGrantTypes] = useState<string[]>([]);
  const [requirePKCE, setRequirePKCE] = useState(false);
  const [requireConsent, setRequireConsent] = useState(false);
  const [enabled, setEnabled] = useState(true);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    api
      .getClient(id, ctrl.signal)
      .then((c) => {
        setClient(c);
        setName(c.name);
        setRedirectURIs(c.redirect_uris.length ? c.redirect_uris : [""]);
        setScopes(c.allowed_scopes);
        setGrantTypes(c.allowed_grant_types);
        setRequirePKCE(c.require_pkce);
        setRequireConsent(c.require_consent);
        setEnabled(c.enabled);
        setError(null);
      })
      .catch((e) => {
        if (ctrl.signal.aborted) return;
        setError(
          e instanceof ApiError
            ? e
            : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(e) }),
        );
      })
      .finally(() => setLoading(false));
    return () => ctrl.abort();
  }, [id]);

  function setRedirect(i: number, v: string) {
    setRedirectURIs((prev) => {
      const next = [...prev];
      next[i] = v;
      return next;
    });
  }
  function addRedirect() {
    setRedirectURIs((prev) => [...prev, ""]);
  }
  function removeRedirect(i: number) {
    setRedirectURIs((prev) => prev.filter((_, idx) => idx !== i));
  }

  function toggleGrant(g: string, on: boolean) {
    setGrantTypes((prev) => (on ? [...new Set([...prev, g])] : prev.filter((x) => x !== g)));
  }

  async function save() {
    setSaving(true);
    try {
      const cleanRedirects = redirectURIs.map((u) => u.trim()).filter(Boolean);
      const updated = await api.updateClient(id, {
        name,
        redirect_uris: cleanRedirects,
        allowed_scopes: scopes,
        allowed_grant_types: grantTypes,
        require_pkce: requirePKCE,
        require_consent: requireConsent,
        enabled,
      });
      setClient(updated);
      toast.success("Client updated.");
    } catch (e) {
      toast.error("Update failed.", e instanceof ApiError ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <Loading />;
  if (error) return <ErrorState error={error} />;
  if (!client) return <ErrorState error={new Error("Client not found.")} />;

  // public clients always require PKCE; the toggle reflects and locks that
  const pkceLocked = client.is_public;

  return (
    <div className="space-y-6">
      <PageHeader
        title={client.name || client.id}
        subtitle={`${client.id} · ${client.is_public ? "public" : "confidential"}`}
        actions={
          <Link to="/clients" className="btn-secondary">
            Back to clients
          </Link>
        }
      />

      <div className="card space-y-5 p-6">
        <div>
          <label className="label" htmlFor="name">
            Display name
          </label>
          <input
            id="name"
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>

        <div>
          <label className="label">Redirect URIs</label>
          <div className="space-y-2">
            {redirectURIs.map((u, i) => (
              <div key={i} className="flex gap-2">
                <input
                  className="input flex-1"
                  value={u}
                  onChange={(e) => setRedirect(i, e.target.value)}
                  placeholder="https://app.example.com/callback"
                />
                {redirectURIs.length > 1 && (
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => removeRedirect(i)}
                    aria-label="Remove redirect URI"
                  >
                    ×
                  </button>
                )}
              </div>
            ))}
            <button type="button" className="btn-secondary" onClick={addRedirect}>
              + Add another
            </button>
          </div>
          <p className="hint">Exact-match; at least one required.</p>
        </div>

        <div>
          <label className="label">Allowed scopes</label>
          <ScopesEditor value={scopes} onChange={setScopes} />
          <p className="hint">
            Include <span className="font-mono">offline_access</span> to allow refresh tokens.
          </p>
        </div>

        <div>
          <label className="label">Grant types</label>
          <div className="flex flex-wrap gap-4">
            {GRANT_TYPES.map((g) => (
              <label key={g} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                  checked={grantTypes.includes(g)}
                  onChange={(e) => toggleGrant(g, e.target.checked)}
                />
                <span className="font-mono">{g}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <label className={`flex items-start gap-2 text-sm ${pkceLocked ? "opacity-60" : ""}`}>
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
              checked={pkceLocked ? true : requirePKCE}
              disabled={pkceLocked}
              onChange={(e) => setRequirePKCE(e.target.checked)}
            />
            <span>
              <span className="font-medium text-slate-800 dark:text-slate-200">Require PKCE (S256)</span>
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                {pkceLocked ? "Always required for public clients." : "Recommended for confidential clients."}
              </span>
            </span>
          </label>

          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
              checked={requireConsent}
              onChange={(e) => setRequireConsent(e.target.checked)}
            />
            <span>
              <span className="font-medium text-slate-800 dark:text-slate-200">Require consent</span>
              <span className="block text-xs text-slate-500 dark:text-slate-400">Show a consent screen.</span>
            </span>
          </label>

          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>
              <span className="font-medium text-slate-800 dark:text-slate-200">Enabled</span>
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                Disabled clients are rejected at authorization.
              </span>
            </span>
          </label>
        </div>

        <div className="flex justify-end">
          <button className="btn-primary" onClick={save} disabled={saving}>
            {saving ? "Saving…" : "Save changes"}
          </button>
        </div>
      </div>
    </div>
  );
}
