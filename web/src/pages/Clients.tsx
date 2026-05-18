import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { useConfirm } from "../components/Confirm";
import CopyButton from "../components/CopyButton";
import PageHeader from "../components/PageHeader";
import { EmptyState, ErrorState, Loading } from "../components/States";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import type { OIDCClient } from "../lib/types";
import { formatDateTime } from "../lib/util";

/*
 * OIDC clients list. The list endpoint returns all clients regardless
 * of enabled state (the SPA filters visually, the API doesn't), so an
 * admin can see and re-enable a disabled client without a separate view.
 *
 * Rotating the secret happens inline: clicking "Rotate secret" prompts
 * for confirmation, calls the API, and shows the plaintext exactly once.
 */

export default function Clients() {
  const toast = useToast();
  const confirm = useConfirm();
  const [clients, setClients] = useState<OIDCClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [rotated, setRotated] = useState<{ id: string; secret: string } | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    api.listClients(ctrl.signal)
      .then((res) => {
        setClients(res.clients);
        setLoading(false);
      })
      .catch((err) => {
        if (ctrl.signal.aborted) return;
        setError(err instanceof ApiError ? err : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }));
        setLoading(false);
      });
    return () => ctrl.abort();
  }, []);

  async function rotate(id: string) {
    const ok = await confirm({
      title: `Rotate the secret for "${id}"?`,
      message: "All integrations using the old secret will fail until they're updated with the new one. This takes effect immediately.",
      confirmLabel: "Rotate",
      danger: true,
    });
    if (!ok) return;
    try {
      const res = await api.rotateClientSecret(id);
      setRotated({ id, secret: res.secret });
      toast.success("Secret rotated.", "Copy the new value before leaving this page.");
    } catch (err) {
      toast.error("Could not rotate secret.", err instanceof ApiError ? err.message : String(err));
    }
  }

  async function remove(id: string) {
    const ok = await confirm({
      title: `Delete client "${id}"?`,
      message: "This is a soft delete — tokens already issued continue to validate until they expire.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok) return;
    try {
      await api.deleteClient(id);
      setClients((cs) => cs.filter((c) => c.id !== id));
      toast.success(`Deleted client "${id}".`);
    } catch (err) {
      toast.error("Could not delete client.", err instanceof ApiError ? err.message : String(err));
    }
  }

  return (
    <>
      <PageHeader
        title="OIDC clients"
        subtitle="Registered relying parties for OAuth 2.0 / OpenID Connect."
        actions={<Link to="/clients/new" className="btn-primary">Register client</Link>}
      />

      {loading && <Loading />}
      {error && <ErrorState error={error} />}
      {!loading && !error && clients.length === 0 && (
        <EmptyState
          title="No OIDC clients registered yet."
          description="Register your first client to start issuing tokens."
          action={<Link to="/clients/new" className="btn-primary">Register client</Link>}
        />
      )}

      {rotated && (
        <SecretBanner
          title={`New secret for "${rotated.id}"`}
          secret={rotated.secret}
          onDismiss={() => setRotated(null)}
        />
      )}

      {!loading && !error && clients.length > 0 && (
        <>
          {/* Mobile: stacked cards. Each card surfaces name+id, type/PKCE
              badges, status, and the same Rotate/Delete actions as the
              desktop row. We omit grants and full redirect URI list to
              keep the card scannable — operators can tap into the JSON
              from a desktop session if they need that depth. */}
          <ul className="space-y-2 md:hidden">
            {clients.map((c) => (
              <li key={c.id} className="card p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                      {c.name}
                    </p>
                    <code className="block truncate text-xs text-slate-500 dark:text-slate-400">
                      {c.id}
                    </code>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    {c.enabled ? <span className="badge-green">enabled</span> : <span className="badge-red">disabled</span>}
                    {c.is_public ? <span className="badge-slate">public</span> : <span className="badge-brand">confidential</span>}
                  </div>
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                  {c.require_pkce && <span className="badge-green">PKCE</span>}
                  <span>{c.redirect_uris.length} redirect{c.redirect_uris.length === 1 ? "" : "s"}</span>
                  <span>·</span>
                  <span>{formatDateTime(c.created_at)}</span>
                </div>
                <div className="mt-3 flex justify-end gap-3 text-sm">
                  {!c.is_public && (
                    <button onClick={() => rotate(c.id)} className="text-brand-600 hover:underline dark:text-brand-100">
                      Rotate secret
                    </button>
                  )}
                  <button onClick={() => remove(c.id)} className="text-red-600 hover:underline">
                    Delete
                  </button>
                </div>
              </li>
            ))}
          </ul>

          {/* Desktop: full table. Hidden under md. */}
          <div className="hidden md:block">
            <div className="card overflow-x-auto">
              <table className="w-full">
                <thead className="bg-slate-50 dark:bg-slate-950/40">
                  <tr>
                    <th className="table-th">Client</th>
                    <th className="table-th">Type</th>
                    <th className="table-th">Grants</th>
                    <th className="table-th">Redirect URIs</th>
                    <th className="table-th">Status</th>
                    <th className="table-th">Created</th>
                    <th className="table-th text-right pr-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {clients.map((c) => (
                    <tr key={c.id} className="table-row">
                      <td className="table-td">
                        <div className="font-medium text-slate-900 dark:text-slate-100">{c.name}</div>
                        <code className="text-xs text-slate-500 dark:text-slate-400">{c.id}</code>
                      </td>
                      <td className="table-td">
                        {c.is_public ? <span className="badge-slate">public</span> : <span className="badge-brand">confidential</span>}
                        {c.require_pkce && <span className="badge-green ml-1">PKCE</span>}
                      </td>
                      <td className="table-td text-xs">
                        {c.allowed_grant_types.map((g) => (
                          <span key={g} className="badge-slate mr-1 mb-1">{g}</span>
                        ))}
                      </td>
                      <td className="table-td text-xs">
                        {c.redirect_uris.slice(0, 2).map((u) => (
                          <div key={u} className="truncate max-w-xs" title={u}>{u}</div>
                        ))}
                        {c.redirect_uris.length > 2 && (
                          <div className="text-slate-400">+ {c.redirect_uris.length - 2} more</div>
                        )}
                      </td>
                      <td className="table-td">
                        {c.enabled ? <span className="badge-green">enabled</span> : <span className="badge-red">disabled</span>}
                      </td>
                      <td className="table-td">{formatDateTime(c.created_at)}</td>
                      <td className="table-td text-right pr-3">
                        {!c.is_public && (
                          <button onClick={() => rotate(c.id)} className="text-xs text-brand-600 hover:underline dark:text-brand-100">Rotate</button>
                        )}
                        <button onClick={() => remove(c.id)} className="ml-3 text-xs text-red-600 hover:underline">Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}

export function SecretBanner({ title, secret, onDismiss }: { title: string; secret: string; onDismiss: () => void }) {
  return (
    <div className="card mb-4 border-amber-300 bg-amber-50 p-4 dark:border-amber-700/50 dark:bg-amber-950/40">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-amber-900 dark:text-amber-200">
            {title}
          </h3>
          <p className="mt-1 text-xs text-amber-800/80 dark:text-amber-300/80">
            This is the only time you'll see this value. Copy it now.
          </p>
          <div className="mt-2 flex items-start gap-2 rounded bg-white p-2 dark:bg-slate-900">
            <code className="min-w-0 flex-1 break-all font-mono text-xs text-slate-900 dark:text-slate-100">
              {secret}
            </code>
            {/* CopyButton handles the secure-context fallback and shows a
                "Copied" flash; toast-on-success is on so the confirmation
                is also visible after focus moves elsewhere. */}
            <CopyButton value={secret} toastOnSuccess label="" className="shrink-0" />
          </div>
        </div>
        <button className="btn-secondary self-end sm:self-start" onClick={onDismiss}>Dismiss</button>
      </div>
    </div>
  );
}
