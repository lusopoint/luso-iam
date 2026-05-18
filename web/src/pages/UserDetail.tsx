import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { useConfirm } from "../components/Confirm";
import PageHeader from "../components/PageHeader";
import { usePrompt } from "../components/Prompt";
import { ErrorState, Loading } from "../components/States";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import type { AdminSession, AdminUser } from "../lib/types";
import { formatDateTime, relativeTime, shortID } from "../lib/util";

/*
 * UserDetail: shows the user's profile, active sessions, and provides the
 * admin actions defined by the API (lock, unlock, toggle admin, force
 * password reset, revoke all sessions, soft delete).
 *
 * Each mutation calls the matching API endpoint and refreshes only the
 * data it can affect — keeps the UI snappy without a global state library.
 * Success/failure feedback flows through the toast system; destructive
 * actions are gated by the confirm modal.
 */

export default function UserDetail() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const prompt = usePrompt();

  const [user, setUser] = useState<AdminUser | null>(null);
  const [sessions, setSessions] = useState<AdminSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const ctrl = new AbortController();
    Promise.all([api.getUser(id, ctrl.signal), api.listUserSessions(id, ctrl.signal)])
      .then(([u, s]) => {
        setUser(u);
        setSessions(s.sessions);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (ctrl.signal.aborted) return;
        setError(err instanceof ApiError ? err : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }));
        setLoading(false);
      });
    return () => ctrl.abort();
  }, [id]);

  async function run<T>(label: string, op: () => Promise<T>, onOk?: (v: T) => void) {
    setBusy(label);
    try {
      const v = await op();
      onOk?.(v);
      toast.success(`${label} succeeded.`);
    } catch (err) {
      toast.error(`${label} failed.`, err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  if (loading) return <Loading />;
  if (error)   return <ErrorState error={error} />;
  if (!user)   return <ErrorState error={new Error("User not found.")} />;

  return (
    <>
      <PageHeader
        title={user.email || user.username || user.id}
        subtitle={`User ${user.id}`}
        actions={
          <Link to="/users" className="btn-secondary">← Back to users</Link>
        }
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="card p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-200">Profile</h2>
          <dl className="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
            <Row label="Status">{user.status}</Row>
            <Row label="Admin">{user.is_admin ? "Yes" : "No"}</Row>
            <Row label="Email">{user.email || "—"}</Row>
            <Row label="Username">{user.username || "—"}</Row>
            <Row label="Display name">{user.display_name || "—"}</Row>
            <Row label="Email verified">{user.email_verified ? "Yes" : "No"}</Row>
            <Row label="Last login">{formatDateTime(user.last_login_at)}</Row>
            <Row label="Created">{formatDateTime(user.created_at)}</Row>
          </dl>
        </div>

        <div className="card p-4">
          <h2 className="mb-3 text-sm font-semibold text-slate-700 dark:text-slate-200">Admin actions</h2>
          <div className="flex flex-wrap gap-2">
            {user.status === "active" ? (
              <button className="btn-secondary" disabled={!!busy} onClick={() => run("Lock", () => api.lockUser(id), setUser)}>
                Lock account
              </button>
            ) : (
              <button className="btn-secondary" disabled={!!busy} onClick={() => run("Unlock", () => api.unlockUser(id), setUser)}>
                Unlock account
              </button>
            )}

            <button
              className="btn-secondary"
              disabled={!!busy}
              onClick={() => run("Toggle admin", () => api.updateUser(id, { is_admin: !user.is_admin }), setUser)}
            >
              {user.is_admin ? "Remove admin" : "Make admin"}
            </button>

            <button
              className="btn-secondary"
              disabled={!!busy}
              onClick={async () => {
                const pwd = await prompt({
                  title: "Reset password",
                  message: "The user will need to be told the new password out-of-band. All their active sessions are revoked after the reset.",
                  inputLabel: "New password",
                  inputType: "password",
                  placeholder: "≥ 12 characters",
                  confirmLabel: "Reset password",
                  danger: true,
                  // The server enforces this; mirroring client-side just
                  // gives faster feedback (no round-trip to learn it's too short).
                  validate: (v) => v.length >= 12 ? null : "Must be at least 12 characters.",
                });
                if (pwd === null) return;
                run("Password reset", () => api.resetUserPassword(id, pwd));
              }}
            >
              Reset password
            </button>

            <button
              className="btn-secondary"
              disabled={!!busy || sessions.length === 0}
              onClick={async () => {
                const ok = await confirm({
                  title: "Revoke all active sessions?",
                  message: `This signs the user out of ${sessions.length} active session${sessions.length === 1 ? "" : "s"} immediately.`,
                  confirmLabel: "Revoke",
                  danger: true,
                });
                if (!ok) return;
                run("Revoke sessions", () => api.revokeUserSessions(id), () => setSessions([]));
              }}
            >
              Revoke sessions ({sessions.length})
            </button>

            <button
              className="btn-danger"
              disabled={!!busy}
              onClick={async () => {
                const ok = await confirm({
                  title: "Delete this user?",
                  message: "Soft delete — their data is retained but they can no longer sign in. Active sessions will also be revoked.",
                  confirmLabel: "Delete",
                  danger: true,
                });
                if (!ok) return;
                run("Delete", () => api.deleteUser(id), () => navigate("/users"));
              }}
            >
              Delete user
            </button>
          </div>
        </div>
      </div>

      <div className="card mt-4 overflow-hidden">
        <div className="border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">
            Active sessions
          </h2>
        </div>
        {sessions.length === 0 ? (
          <p className="px-4 py-6 text-center text-sm text-slate-500 dark:text-slate-400">
            No active sessions.
          </p>
        ) : (
          <table className="w-full">
            <thead className="bg-slate-50 dark:bg-slate-950/40">
              <tr>
                <th className="table-th">Session</th>
                <th className="table-th">ACR / AMR</th>
                <th className="table-th">IP</th>
                <th className="table-th">User-Agent</th>
                <th className="table-th">Last seen</th>
                <th className="table-th">Expires</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id} className="table-row">
                  <td className="table-td font-mono text-xs">{shortID(s.id)}</td>
                  <td className="table-td">
                    <span className="badge-slate">acr {s.acr}</span>{" "}
                    <span className="text-xs text-slate-500">{s.amr.join(", ")}</span>
                  </td>
                  <td className="table-td">{s.ip_address || "—"}</td>
                  <td className="table-td max-w-xs truncate text-xs text-slate-500" title={s.user_agent || ""}>
                    {s.user_agent || "—"}
                  </td>
                  <td className="table-td">{relativeTime(s.last_seen_at)}</td>
                  <td className="table-td">{formatDateTime(s.expires_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="text-slate-800 dark:text-slate-200">{children}</dd>
    </>
  );
}
