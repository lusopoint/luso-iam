import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import PageHeader from "../components/PageHeader";
import { ErrorState, Loading } from "../components/States";
import { ApiError, api } from "../lib/api";
import type { AuditEvent } from "../lib/types";
import { relativeTime } from "../lib/util";

/*
 * Dashboard: a one-page overview. Three counter cards (users, clients,
 * services) and the 10 most recent audit events. The point is to give
 * an admin landing on /admin a "everything is fine, here's what just
 * happened" snapshot without making them dig.
 */

interface Counters {
  users?: number;
  clients?: number;
  services?: number;
}

export default function Dashboard() {
  const [counters, setCounters] = useState<Counters>({});
  const [recent, setRecent] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const ctrl = new AbortController();
    // Issue all four queries in parallel; settle them together so the
    // page doesn't reflow as each one arrives.
    Promise.all([
      api.listUsers({ limit: 1 }, ctrl.signal),
      api.listClients(ctrl.signal),
      api.listCASServices(ctrl.signal),
      api.listAudit({ limit: 10 }, ctrl.signal),
    ])
      .then(([u, c, s, a]) => {
        setCounters({
          users: u.total,
          clients: c.clients.length,
          services: s.services.length,
        });
        setRecent(a.events);
        setLoading(false);
      })
      .catch((err) => {
        if (ctrl.signal.aborted) return;
        setError(err instanceof ApiError ? err : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }));
        setLoading(false);
      });
    return () => ctrl.abort();
  }, []);

  if (loading) return <Loading />;
  if (error) return <ErrorState error={error} />;

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle="At-a-glance view of the IAM environment."
      />

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Users"        value={counters.users ?? 0}    to="/users" />
        <StatCard label="OIDC clients" value={counters.clients ?? 0}  to="/clients" />
        <StatCard label="CAS services" value={counters.services ?? 0} to="/cas-services" />
      </div>

      <div className="card overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">
            Recent events
          </h2>
          <Link to="/audit" className="text-xs text-brand-600 hover:underline dark:text-brand-100">
            View all →
          </Link>
        </div>
        {recent.length === 0 ? (
          <p className="px-4 py-6 text-center text-sm text-slate-500 dark:text-slate-400">
            No events recorded yet.
          </p>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {recent.map((e) => (
              <li key={e.id} className="flex items-center justify-between px-4 py-2 text-sm">
                <span className="font-mono text-slate-700 dark:text-slate-200">{e.event_type}</span>
                <span className="text-slate-500 dark:text-slate-400">{relativeTime(e.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}

function StatCard({ label, value, to }: { label: string; value: number; to: string }) {
  return (
    <Link
      to={to}
      className="card flex flex-col gap-1 p-4 transition hover:border-brand-500 dark:hover:border-brand-500"
    >
      <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</span>
      <span className="text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-100">{value}</span>
    </Link>
  );
}
