import { useEffect, useState } from "react";

import { useConfirm } from "../components/Confirm";
import PageHeader from "../components/PageHeader";
import { EmptyState, ErrorState, Loading } from "../components/States";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import type { CASService, CreateCASServiceRequest } from "../lib/types";
import { formatDateTime } from "../lib/util";

/*
 * CAS service registry. CAS-protocol applications need to be registered
 * here before /cas/login will issue tickets for them — see the prefix
 * match in FindCASServiceForURL.
 *
 * Add and delete are inline; updates flip the enabled flag only — full
 * editing is rare and intentionally not exposed in the SPA (use PATCH
 * via API for niche cases like changing released_attributes).
 */

export default function CASServices() {
  const toast = useToast();
  const confirm = useConfirm();
  const [services, setServices] = useState<CASService[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<ApiError | null>(null);
  const [adding, setAdding]     = useState(false);

  useEffect(() => { refresh(); }, []);

  function refresh() {
    setLoading(true);
    api.listCASServices()
      .then((r) => { setServices(r.services); setError(null); setLoading(false); })
      .catch((err) => {
        setError(err instanceof ApiError ? err : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }));
        setLoading(false);
      });
  }

  async function toggle(s: CASService) {
    try {
      const updated = await api.updateCASService(s.id, { enabled: !s.enabled });
      setServices((list) => list.map((x) => x.id === s.id ? updated : x));
      toast.success(updated.enabled ? `Enabled "${s.name}".` : `Disabled "${s.name}".`);
    } catch (err) {
      toast.error("Could not update service.", err instanceof ApiError ? err.message : String(err));
    }
  }

  async function remove(s: CASService) {
    const ok = await confirm({
      title: `Delete "${s.name}"?`,
      message: "Active CAS tickets will continue to validate until they expire (typically 60s).",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok) return;
    try {
      await api.deleteCASService(s.id);
      setServices((list) => list.filter((x) => x.id !== s.id));
      toast.success(`Deleted "${s.name}".`);
    } catch (err) {
      toast.error("Could not delete service.", err instanceof ApiError ? err.message : String(err));
    }
  }

  return (
    <>
      <PageHeader
        title="CAS services"
        subtitle="Applications allowed to use the CAS authentication protocol."
        actions={!adding && (
          <button onClick={() => setAdding(true)} className="btn-primary">Register service</button>
        )}
      />

      {adding && <AddForm onCancel={() => setAdding(false)} onCreated={() => { setAdding(false); refresh(); }} />}

      {loading && <Loading />}
      {error && <ErrorState error={error} />}
      {!loading && !error && services.length === 0 && !adding && (
        <EmptyState
          title="No CAS services registered."
          description="Register your first service to enable CAS-protocol logins."
          action={<button onClick={() => setAdding(true)} className="btn-primary">Register service</button>}
        />
      )}

      {!loading && !error && services.length > 0 && (
        <>
          {/* Mobile: cards with the most important fields surfaced inline. */}
          <ul className="space-y-2 md:hidden">
            {services.map((s) => (
              <li key={s.id} className="card p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                      {s.name}
                    </p>
                    {s.description && (
                      <p className="truncate text-xs text-slate-500 dark:text-slate-400">
                        {s.description}
                      </p>
                    )}
                  </div>
                  {s.enabled ? <span className="badge-green shrink-0">enabled</span> : <span className="badge-red shrink-0">disabled</span>}
                </div>
                <code className="mt-2 block break-all rounded bg-slate-50 px-2 py-1 text-xs text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  {s.service_url_pattern}
                </code>
                {s.released_attributes.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {s.released_attributes.map((a) => (
                      <span key={a} className="badge-slate">{a}</span>
                    ))}
                  </div>
                )}
                <div className="mt-3 flex items-center justify-between text-sm">
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    {formatDateTime(s.created_at)}
                  </span>
                  <div className="flex gap-3">
                    <button onClick={() => toggle(s)} className="text-brand-600 hover:underline dark:text-brand-100">
                      {s.enabled ? "Disable" : "Enable"}
                    </button>
                    <button onClick={() => remove(s)} className="text-red-600 hover:underline">
                      Delete
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>

          {/* Desktop: table. */}
          <div className="hidden md:block">
            <div className="card overflow-x-auto">
              <table className="w-full">
                <thead className="bg-slate-50 dark:bg-slate-950/40">
                  <tr>
                    <th className="table-th">Name</th>
                    <th className="table-th">URL pattern</th>
                    <th className="table-th">Released attributes</th>
                    <th className="table-th">Status</th>
                    <th className="table-th">Created</th>
                    <th className="table-th text-right pr-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {services.map((s) => (
                    <tr key={s.id} className="table-row">
                      <td className="table-td">
                        <div className="font-medium text-slate-900 dark:text-slate-100">{s.name}</div>
                        {s.description && (
                          <div className="text-xs text-slate-500 dark:text-slate-400">{s.description}</div>
                        )}
                      </td>
                      <td className="table-td">
                        <code className="text-xs">{s.service_url_pattern}</code>
                      </td>
                      <td className="table-td text-xs">
                        {s.released_attributes.length === 0 ? (
                          <span className="text-slate-400">username only</span>
                        ) : s.released_attributes.map((a) => (
                          <span key={a} className="badge-slate mr-1 mb-1">{a}</span>
                        ))}
                      </td>
                      <td className="table-td">
                        {s.enabled ? <span className="badge-green">enabled</span> : <span className="badge-red">disabled</span>}
                      </td>
                      <td className="table-td">{formatDateTime(s.created_at)}</td>
                      <td className="table-td text-right pr-3">
                        <button onClick={() => toggle(s)} className="text-xs text-brand-600 hover:underline dark:text-brand-100">
                          {s.enabled ? "Disable" : "Enable"}
                        </button>
                        <button onClick={() => remove(s)} className="ml-3 text-xs text-red-600 hover:underline">
                          Delete
                        </button>
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

function AddForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const [form, setForm] = useState<CreateCASServiceRequest>({
    name: "",
    service_url_pattern: "",
    description: "",
    released_attributes: [],
  });
  const [attrsRaw, setAttrsRaw] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.createCASService({
        ...form,
        released_attributes: attrsRaw
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      });
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="card mb-4 max-w-2xl p-4 space-y-3">
      {error && (
        <div className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/40 dark:text-red-300">
          {error}
        </div>
      )}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="cas-name">Name</label>
          <input
            id="cas-name"
            className="input"
            required
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="Wiki"
          />
        </div>
        <div>
          <label className="label" htmlFor="cas-url">Service URL pattern</label>
          <input
            id="cas-url"
            className="input font-mono"
            required
            value={form.service_url_pattern}
            onChange={(e) => setForm((f) => ({ ...f, service_url_pattern: e.target.value }))}
            placeholder="https://wiki.example.com/"
          />
          <p className="hint">Trailing slash is treated as a prefix match.</p>
        </div>
      </div>

      <div>
        <label className="label" htmlFor="cas-attrs">Released attributes</label>
        <input
          id="cas-attrs"
          className="input"
          value={attrsRaw}
          onChange={(e) => setAttrsRaw(e.target.value)}
          placeholder="email, display_name (comma-separated; leave empty for username-only)"
        />
      </div>

      <div>
        <label className="label" htmlFor="cas-desc">Description (optional)</label>
        <input
          id="cas-desc"
          className="input"
          value={form.description}
          onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
        />
      </div>

      <div className="flex justify-end gap-2 pt-1">
        <button type="button" onClick={onCancel} className="btn-secondary">Cancel</button>
        <button type="submit" disabled={busy} className="btn-primary">
          {busy ? "Registering…" : "Register"}
        </button>
      </div>
    </form>
  );
}
