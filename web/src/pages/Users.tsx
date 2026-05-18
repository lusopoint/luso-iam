import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import PageHeader from "../components/PageHeader";
import { EmptyState, ErrorState, Loading } from "../components/States";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import type { AdminUser } from "../lib/types";
import { cx, formatDateTime } from "../lib/util";
import NewUserDialog from "./NewUserDialog";

/*
 * Users list. Server-side pagination + filters: matches the
 * /admin/v1/users query string (search, status, limit, offset). We keep
 * a local filter state and refetch on commit (Enter or status change).
 *
 * The "New user" button opens NewUserDialog as a modal; on success it
 * fires a refetch so the new row appears at the top of the list.
 */

const PAGE_SIZE = 25;

export default function Users() {
  const toast = useToast();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [offset, setOffset] = useState(0);

  const [users, setUsers] = useState<AdminUser[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [newOpen, setNewOpen] = useState(false);

  // Bumping refetchTick re-runs the effect — we use this instead of putting
  // `search` directly in the deps so typing doesn't fire a request per keystroke.
  const [refetchTick, setRefetchTick] = useState(0);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    api
      .listUsers(
        { search, status: statusFilter, limit: PAGE_SIZE, offset },
        ctrl.signal,
      )
      .then((res) => {
        setUsers(res.users);
        setTotal(res.total);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (ctrl.signal.aborted) return;
        setError(err instanceof ApiError ? err : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }));
        setLoading(false);
      });
    return () => ctrl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, offset, refetchTick]);

  const onSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setOffset(0);
    setRefetchTick((n) => n + 1);
  };

  return (
    <>
      <PageHeader
        title="Users"
        subtitle={`${total} ${total === 1 ? "user" : "users"} in total.`}
        actions={
          <button onClick={() => setNewOpen(true)} className="btn-primary">
            New user
          </button>
        }
      />

      <NewUserDialog
        open={newOpen}
        onClose={() => setNewOpen(false)}
        onCreated={() => {
          // Refetch from offset 0 so the new user is visible immediately.
          setOffset(0);
          setRefetchTick((n) => n + 1);
          toast.success("User created.");
        }}
      />

      <div className="card mb-4 p-3">
        <form onSubmit={onSearchSubmit} className="flex flex-wrap items-end gap-3">
          <div className="grow basis-64">
            <label className="label" htmlFor="search">Search</label>
            <input
              id="search"
              className="input"
              placeholder="email or username"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div>
            <label className="label" htmlFor="status">Status</label>
            <select
              id="status"
              className="input"
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setOffset(0); }}
            >
              <option value="">Any</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
              <option value="pending">Pending</option>
            </select>
          </div>
          <button type="submit" className="btn-primary">Search</button>
        </form>
      </div>

      {loading && <Loading />}
      {error && <ErrorState error={error} />}
      {!loading && !error && users.length === 0 && (
        <EmptyState
          title="No users match these filters."
          description="Try clearing the search or status filter."
        />
      )}
      {!loading && !error && users.length > 0 && (
        <>
          {/* Mobile: stacked card list. Each card is a tap target that
              navigates to the user detail page. Touch-friendly spacing. */}
          <ul className="space-y-2 md:hidden">
            {users.map((u) => (
              <li key={u.id} className="card p-3">
                <Link to={`/users/${u.id}`} className="block">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-slate-900 dark:text-slate-100">
                        {u.email || u.username || u.id.slice(0, 8)}
                      </p>
                      {u.display_name && (
                        <p className="truncate text-xs text-slate-500 dark:text-slate-400">
                          {u.display_name}
                        </p>
                      )}
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      <StatusBadge status={u.status} />
                      {u.is_admin && <span className="badge-brand">admin</span>}
                    </div>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
                    <span>Last&nbsp;login&nbsp;{formatDateTime(u.last_login_at)}</span>
                    <span>·</span>
                    <span>Joined&nbsp;{formatDateTime(u.created_at)}</span>
                  </div>
                </Link>
              </li>
            ))}
          </ul>

          {/* Desktop: traditional table. Hidden under md. */}
          <div className="hidden md:block">
            <div className="card overflow-hidden">
              <table className="w-full">
                <thead className="bg-slate-50 dark:bg-slate-950/40">
                  <tr>
                    <th className="table-th">Email / Username</th>
                    <th className="table-th">Status</th>
                    <th className="table-th">Admin</th>
                    <th className="table-th">Last login</th>
                    <th className="table-th">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} className="table-row hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="table-td">
                        <Link to={`/users/${u.id}`} className="text-brand-600 hover:underline dark:text-brand-100">
                          {u.email || u.username || u.id.slice(0, 8)}
                        </Link>
                        {u.display_name && (
                          <div className="text-xs text-slate-500 dark:text-slate-400">{u.display_name}</div>
                        )}
                      </td>
                      <td className="table-td"><StatusBadge status={u.status} /></td>
                      <td className="table-td">{u.is_admin ? <span className="badge-brand">admin</span> : <span className="text-slate-400">—</span>}</td>
                      <td className="table-td">{formatDateTime(u.last_login_at)}</td>
                      <td className="table-td">{formatDateTime(u.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <Pagination total={total} offset={offset} setOffset={setOffset} />
        </>
      )}
    </>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls = status === "active" ? "badge-green" : status === "disabled" ? "badge-red" : "badge-amber";
  return <span className={cls}>{status}</span>;
}

function Pagination({ total, offset, setOffset }: { total: number; offset: number; setOffset: (n: number) => void }) {
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(offset + PAGE_SIZE, total);
  const canPrev = offset > 0;
  const canNext = end < total;
  return (
    <div className="mt-3 flex items-center justify-between text-sm text-slate-500 dark:text-slate-400">
      <span>Showing {start}–{end} of {total}</span>
      <div className="flex gap-2">
        <button
          className={cx("btn-secondary", !canPrev && "pointer-events-none opacity-40")}
          disabled={!canPrev}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          ← Previous
        </button>
        <button
          className={cx("btn-secondary", !canNext && "pointer-events-none opacity-40")}
          disabled={!canNext}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next →
        </button>
      </div>
    </div>
  );
}
