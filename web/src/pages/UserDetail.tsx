import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { useConfirm } from "../components/Confirm";
import PageHeader from "../components/PageHeader";
import { usePrompt } from "../components/Prompt";
import { ErrorState, Loading } from "../components/States";
import { useToast } from "../components/Toast";
import { ApiError, api } from "../lib/api";
import type { AdminSession, AdminUser, MFAMethod, UserFederationIdentity } from "../lib/types";
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
  // MFA state — kept separate from sessions because the panel is
  // independently refreshable: deleting one method shouldn't refetch
  // the session list and vice versa.
  const [mfaMethods, setMfaMethods] = useState<MFAMethod[]>([]);
  const [backupCount, setBackupCount] = useState<number>(0);
  // Federation state — same independence rationale as MFA. Lives next
  // to the MFA panel in the UI.
  const [federationLinks, setFederationLinks] = useState<UserFederationIdentity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // Refetch just the MFA section. Used after delete operations so the
  // panel reflects reality without reloading the whole page.
  async function refreshMFA() {
    try {
      const m = await api.listUserMFA(id);
      setMfaMethods(m.methods);
      setBackupCount(m.backup_codes_unused);
    } catch {
      // Best-effort — if this fails, the inline panel just shows
      // stale data. The next page navigation refetches everything.
    }
  }

  async function refreshFederation() {
    try {
      const f = await api.listUserFederation(id);
      setFederationLinks(f.identities);
    } catch {
      // Same best-effort policy as refreshMFA.
    }
  }

  useEffect(() => {
    if (!id) return;
    const ctrl = new AbortController();
    Promise.all([
      api.getUser(id, ctrl.signal),
      api.listUserSessions(id, ctrl.signal),
      api.listUserMFA(id, ctrl.signal),
      api.listUserFederation(id, ctrl.signal),
    ])
      .then(([u, s, m, f]) => {
        setUser(u);
        setSessions(s.sessions);
        setMfaMethods(m.methods);
        setBackupCount(m.backup_codes_unused);
        setFederationLinks(f.identities);
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

      {/* ── MFA & recovery ──────────────────────────────────────────────
          Recovery flows live here. The story:
            - Lost a single device         → "Remove" that method
            - Lost everything, no codes    → "Remove all methods" (typed confirmation)
          After either, the user signs in (with backup codes, federation,
          or a password reset), then re-enrolls from /mfa/enroll. */}
      <div className="card mt-4">
        <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">
            MFA &amp; recovery
          </h2>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {backupCount} backup code{backupCount === 1 ? "" : "s"} unused
          </span>
        </div>

        {mfaMethods.length === 0 ? (
          <p className="px-4 py-6 text-center text-sm text-slate-500 dark:text-slate-400">
            No enrolled methods. The user will sign in with their password only.
          </p>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {mfaMethods.map((m) => (
              <li key={m.id} className="flex items-center gap-3 px-4 py-2.5">
                <span className={m.method === "totp" ? "badge-brand" : "badge-green"}>
                  {m.method}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm text-slate-800 dark:text-slate-200">
                    {m.name || (m.method === "totp" ? "Authenticator app" : "Passkey")}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {m.confirmed_at ? "Confirmed" : "Pending enrollment"}
                    {" · "}
                    {m.last_used_at ? `last used ${relativeTime(m.last_used_at)}` : "never used"}
                    {" · "}
                    added {formatDateTime(m.created_at)}
                  </p>
                </div>
                <button
                  className="text-xs text-red-600 hover:underline"
                  disabled={!!busy}
                  onClick={async () => {
                    const ok = await confirm({
                      title: "Remove this method?",
                      message: `Removing "${m.name || m.method}" means the user can no longer sign in with it. They can re-enroll from /mfa/enroll after their next login.`,
                      confirmLabel: "Remove",
                      danger: true,
                    });
                    if (!ok) return;
                    setBusy("Remove MFA");
                    try {
                      await api.deleteUserMFAMethod(id, m.id);
                      await refreshMFA();
                      toast.success("Method removed.");
                    } catch (err) {
                      toast.error("Could not remove method.", err instanceof ApiError ? err.message : String(err));
                    } finally {
                      setBusy(null);
                    }
                  }}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        )}

        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-100 px-4 py-3 dark:border-slate-800">
          <span className="mr-auto text-xs text-slate-500 dark:text-slate-400">
            Last-resort recovery for users with no codes:
          </span>
          <button
            className="btn-danger"
            disabled={!!busy || (mfaMethods.length === 0 && backupCount === 0)}
            onClick={async () => {
              // Typed confirmation: the user has to spell out the email
              // before we delete every second factor + every backup code.
              // This is the nuclear option — guarding it with friction
              // is the right trade.
              const expected = (user?.email || user?.username || id).toLowerCase();
              const typed = await prompt({
                title: "Remove ALL MFA methods?",
                message:
                  "This deletes every enrolled second factor AND every unused backup code. The user reverts to password-only login until they re-enroll. " +
                  `Type ${expected} to confirm.`,
                inputLabel: "Confirm identifier",
                placeholder: expected,
                confirmLabel: "Remove everything",
                danger: true,
                validate: (v) => v.trim().toLowerCase() === expected ? null : "Doesn't match.",
              });
              if (typed === null) return;
              setBusy("Remove all MFA");
              try {
                await api.deleteAllUserMFA(id);
                await refreshMFA();
                toast.success("All MFA methods and backup codes removed.");
              } catch (err) {
                toast.error("Could not remove methods.", err instanceof ApiError ? err.message : String(err));
              } finally {
                setBusy(null);
              }
            }}
          >
            Remove all MFA methods
          </button>
        </div>
      </div>

      {/* ── Federation / Upstream SSO ──────────────────────────────────
          Per-user linked identities. Read + unlink only. Removing the
          last identity for a user with no password credential is
          refused server-side (409 would_lock_out) — the SPA reflects
          that as a friendlier "Set a password first" toast. */}
      <div className="card mt-4">
        <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3 dark:border-slate-800">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">
            Federated identities
          </h2>
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {federationLinks.length === 0
              ? "no providers linked"
              : `${federationLinks.length} provider${federationLinks.length === 1 ? "" : "s"} linked`}
          </span>
        </div>

        {federationLinks.length === 0 ? (
          <p className="px-4 py-6 text-center text-sm text-slate-500 dark:text-slate-400">
            This user has no upstream provider links. They sign in with their password (or MFA).
          </p>
        ) : (
          <ul className="divide-y divide-slate-100 dark:divide-slate-800">
            {federationLinks.map((link) => (
              <li key={link.id} className="flex items-start gap-3 px-4 py-2.5">
                <span className="badge-slate shrink-0">{link.display_name}</span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm text-slate-800 dark:text-slate-200">
                    {link.email || link.provider_name || link.sub}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    <span className="font-mono">sub: {link.sub.length > 30 ? link.sub.slice(0, 27) + "…" : link.sub}</span>
                    {" · "}
                    linked {formatDateTime(link.created_at)}
                    {link.updated_at !== link.created_at &&
                      ` · last login ${relativeTime(link.updated_at)}`}
                  </p>
                </div>
                <button
                  className="shrink-0 text-xs text-red-600 hover:underline"
                  disabled={!!busy}
                  onClick={async () => {
                    const ok = await confirm({
                      title: `Unlink ${link.display_name}?`,
                      message:
                        `The user will no longer be able to sign in via ${link.display_name}. ` +
                        "They can re-link on a future sign-in if they choose to.",
                      confirmLabel: "Unlink",
                      danger: true,
                    });
                    if (!ok) return;
                    setBusy("Unlink");
                    try {
                      await api.unlinkUserFederation(id, link.id);
                      await refreshFederation();
                      toast.success(`Unlinked ${link.display_name}.`);
                    } catch (err) {
                      // Server returns 409 with code "would_lock_out"
                      // when removing this link would leave the user
                      // with no way to sign in (no password + no other
                      // federation). Translate that to a friendlier
                      // message — the admin should reset the password
                      // first, then retry.
                      if (err instanceof ApiError && err.code === "would_lock_out") {
                        toast.error(
                          "Can't unlink — user would be locked out.",
                          "Reset their password first, then retry the unlink.",
                        );
                      } else {
                        toast.error(
                          "Could not unlink.",
                          err instanceof ApiError ? err.message : String(err),
                        );
                      }
                    } finally {
                      setBusy(null);
                    }
                  }}
                >
                  Unlink
                </button>
              </li>
            ))}
          </ul>
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
