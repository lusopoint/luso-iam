import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  EmptyState,
  Loading,
  PageHeader,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  useConfirm,
  usePrompt,
  useToast,
} from '@lusopoint/luso-ui'
import { KeyRound, Link2Off, ShieldOff, Trash2 } from 'lucide-react'
import { ErrorState } from '../components/States.tsx'
import { StatusBadge } from './Users.tsx'
import { ApiError, api } from '../lib/api.ts'
import type {
  AdminSession,
  AdminUser,
  MFAMethod,
  UserFederationIdentity,
} from '../lib/types.ts'
import { formatDateTime, relativeTime, shortID } from '../lib/util.ts'

const UserDetail = () => {
  const { id = '' } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const toast = useToast()
  const confirm = useConfirm()
  const prompt = usePrompt()

  const [user, setUser] = useState<AdminUser | null>(null)
  const [sessions, setSessions] = useState<AdminSession[]>([])
  // MFA state kept separate from sessions because the panel is refreshed independent
  const [mfaMethods, setMfaMethods] = useState<MFAMethod[]>([])
  const [backupCount, setBackupCount] = useState<number>(0)
  // federation state same independence rationale as MFA to the MFA panel in the ui
  const [federationLinks, setFederationLinks] = useState<
    UserFederationIdentity[]
  >([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  // refetch just the MFA section, used after delete operations so the
  // panel reflects reality without reloading the whole page
  const refreshMFA = async () => {
    try {
      const m = await api.listUserMFA(id)
      setMfaMethods(m.methods)
      setBackupCount(m.backup_codes_unused)
    } catch {
      // if this fails, the inline panel just shows stale data
      // the next page navigation refetches everything
      // TODO: maybe we should console err
    }
  }

  const refreshFederation = async () => {
    try {
      const f = await api.listUserFederation(id)
      setFederationLinks(f.identities)
    } catch {
      // same
    }
  }

  useEffect(() => {
    if (!id) return
    const ctrl = new AbortController()
    Promise.all([
      api.getUser(id, ctrl.signal),
      api.listUserSessions(id, ctrl.signal),
      api.listUserMFA(id, ctrl.signal),
      api.listUserFederation(id, ctrl.signal),
    ])
      .then(([u, s, m, f]) => {
        setUser(u)
        setSessions(s.sessions)
        setMfaMethods(m.methods)
        setBackupCount(m.backup_codes_unused)
        setFederationLinks(f.identities)
        setError(null)
        setLoading(false)
      })
      .catch(err => {
        if (ctrl.signal.aborted) return
        setError(
          err instanceof ApiError
            ? err
            : new ApiError({
                type: 'about:blank',
                title: 'Error',
                status: 0,
                detail: String(err),
              }),
        )
        setLoading(false)
      })
    return () => ctrl.abort()
  }, [id])

  async function run<T>(
    label: string,
    op: () => Promise<T>,
    onOk?: (v: T) => void,
  ) {
    setBusy(label)
    try {
      const v = await op()
      onOk?.(v)
      toast.success(`${label} succeeded.`)
    } catch (err) {
      toast.error(
        `${label} failed.`,
        err instanceof ApiError ? err.message : String(err),
      )
    } finally {
      setBusy(null)
    }
  }

  if (loading) return <Loading label="Loading user..." />
  if (error) return <ErrorState error={error} />
  if (!user) return <ErrorState error={new Error('User not found.')} />

  return (
    <>
      <PageHeader
        breadcrumbs={[
          { label: 'Users', href: '/users' },
          { label: user.email || user.username || 'User' },
        ]}
        title={user.email || user.username || user.id}
        subtitle={`User ${user.id}`}
        actions={
          <Link to="/users">
            <Button variant="outline">Back to users</Button>
          </Link>
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card noHover>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[9rem_minmax(0,1fr)] gap-y-3 text-sm">
              <Field label="Status">
                <StatusBadge status={user.status} />
              </Field>
              <Field label="Admin">
                {user.is_admin ? (
                  <Badge status="in_progress" label="admin" />
                ) : (
                  'No'
                )}
              </Field>
              <Field label="Email">{user.email || '-'}</Field>
              <Field label="Username">{user.username || '-'}</Field>
              <Field label="Display name">{user.display_name || '-'}</Field>
              <Field label="Email verified">
                {user.email_verified ? 'Yes' : 'No'}
              </Field>
              <Field label="Last login">
                {formatDateTime(user.last_login_at)}
              </Field>
              <Field label="Created">{formatDateTime(user.created_at)}</Field>
            </dl>
          </CardContent>
        </Card>

        <Card noHover>
          <CardHeader>
            <CardTitle>Admin actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {user.status === 'active' ? (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={Boolean(busy)}
                  onClick={() => run('Lock', () => api.lockUser(id), setUser)}
                >
                  Lock account
                </Button>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={Boolean(busy)}
                  onClick={() =>
                    run('Unlock', () => api.unlockUser(id), setUser)
                  }
                >
                  Unlock account
                </Button>
              )}

              <Button
                variant="outline"
                size="sm"
                disabled={!!busy}
                onClick={() =>
                  run(
                    'Toggle admin',
                    () => api.updateUser(id, { is_admin: !user.is_admin }),
                    setUser,
                  )
                }
              >
                {user.is_admin ? 'Remove admin' : 'Make admin'}
              </Button>

              <Button
                variant="outline"
                size="sm"
                className="gap-2"
                disabled={!!busy}
                onClick={async () => {
                  const pwd = await prompt({
                    title: 'Reset password',
                    message:
                      'The user will need to be told the new password out-of-band. All their active sessions are revoked after the reset.',
                    inputLabel: 'New password',
                    inputType: 'password',
                    placeholder: '≥ 12 characters',
                    confirmLabel: 'Reset password',
                    danger: true,
                    // the server enforces this mirroring client side just
                    // gives faster feedback (no round trip to learn it's too short)
                    validate: v =>
                      v.length >= 12 ? null : 'Must be at least 12 characters.',
                  })
                  if (pwd === null) return
                  run('Password reset', () => api.resetUserPassword(id, pwd))
                }}
              >
                <KeyRound size={14} />
                Reset password
              </Button>

              <Button
                variant="outline"
                size="sm"
                disabled={!!busy || sessions.length === 0}
                onClick={async () => {
                  const ok = await confirm({
                    title: 'Revoke all active sessions?',
                    message: `This signs the user out of ${sessions.length} active session${sessions.length === 1 ? '' : 's'} immediately.`,
                    confirmLabel: 'Revoke',
                    danger: true,
                  })
                  if (!ok) return
                  run(
                    'Revoke sessions',
                    () => api.revokeUserSessions(id),
                    () => setSessions([]),
                  )
                }}
              >
                Revoke sessions ({sessions.length})
              </Button>

              <Button
                variant="destructive"
                size="sm"
                className="gap-2"
                disabled={!!busy}
                onClick={async () => {
                  const ok = await confirm({
                    title: 'Delete this user?',
                    message:
                      'Soft delete, their data is retained but they can no longer sign in. Active sessions will also be revoked.',
                    confirmLabel: 'Delete',
                    danger: true,
                  })
                  if (!ok) return
                  run(
                    'Delete',
                    () => api.deleteUser(id),
                    () => navigate('/users'),
                  )
                }}
              >
                <Trash2 size={14} />
                Delete user
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card noHover className="mt-6 overflow-hidden">
        <CardHeader>
          <CardTitle>Active sessions</CardTitle>
        </CardHeader>
        {sessions.length === 0 ? (
          <CardContent>
            <EmptyState title="No active sessions" />
          </CardContent>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Session</TableHead>
                <TableHead>ACR / AMR</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>User-Agent</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Expires</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.map(s => (
                <TableRow key={s.id}>
                  <TableCell className="font-mono text-xs">
                    {shortID(s.id)}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Badge status="pending" label={`acr ${s.acr}`} />
                      <span className="text-xs text-on-surface-variant">
                        {s.amr.join(', ')}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>{s.ip_address || '-'}</TableCell>
                  <TableCell
                    className="max-w-xs truncate text-xs text-on-surface-variant"
                    title={s.user_agent || ''}
                  >
                    {s.user_agent || '-'}
                  </TableCell>
                  <TableCell>{relativeTime(s.last_seen_at)}</TableCell>
                  <TableCell>{formatDateTime(s.expires_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {/* Recovery flows live here,
          The story:
            - Lost a single device         -> "Remove" that method
            - Lost everything, no codes    -> "Remove all methods" (typed confirmation)
          After either, the user signs in (with backup codes, federation
          or a password reset), then re-enrolls from /mfa/enroll */}
      <Card noHover className="mt-6">
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle>MFA &amp; recovery</CardTitle>
          <span className="text-xs font-medium text-on-surface-variant">
            {backupCount} backup code{backupCount === 1 ? '' : 's'} unused
          </span>
        </CardHeader>

        <CardContent>
          {mfaMethods.length === 0 ? (
            <EmptyState
              title="No enrolled methods"
              description="The user will sign in with their password only."
            />
          ) : (
            <ul className="divide-y divide-border">
              {mfaMethods.map(m => (
                <li key={m.id} className="flex items-center gap-3 py-3">
                  <Badge
                    status={m.method === 'totp' ? 'in_progress' : 'operational'}
                    label={m.method}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-semibold text-on-surface">
                      {m.name ||
                        (m.method === 'totp' ? 'Authenticator app' : 'Passkey')}
                    </p>
                    <p className="text-xs text-on-surface-variant">
                      {m.confirmed_at ? 'Confirmed' : 'Pending enrollment'}
                      {' · '}
                      {m.last_used_at
                        ? `last used ${relativeTime(m.last_used_at)}`
                        : 'never used'}
                      {' · '}
                      added {formatDateTime(m.created_at)}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-error hover:bg-error/10"
                    disabled={!!busy}
                    onClick={async () => {
                      const ok = await confirm({
                        title: 'Remove this method?',
                        message: `Removing "${m.name || m.method}" means the user can no longer sign in with it. They can re-enroll from /mfa/enroll after their next login.`,
                        confirmLabel: 'Remove',
                        danger: true,
                      })
                      if (!ok) return
                      setBusy('Remove MFA')
                      try {
                        await api.deleteUserMFAMethod(id, m.id)
                        await refreshMFA()
                        toast.success('Method removed.')
                      } catch (err) {
                        toast.error(
                          'Could not remove method.',
                          err instanceof ApiError ? err.message : String(err),
                        )
                      } finally {
                        setBusy(null)
                      }
                    }}
                  >
                    Remove
                  </Button>
                </li>
              ))}
            </ul>
          )}

          <div className="mt-4 flex flex-wrap items-center justify-end gap-3 border-t border-border pt-4">
            <span className="mr-auto text-xs text-on-surface-variant">
              Last-resort recovery for users with no codes:
            </span>
            <Button
              variant="destructive"
              size="sm"
              className="gap-2"
              disabled={
                !!busy || (mfaMethods.length === 0 && backupCount === 0)
              }
              onClick={async () => {
                // typed confirmation, type out the email again
                const expected = (
                  user?.email ||
                  user?.username ||
                  id
                ).toLowerCase()
                const typed = await prompt({
                  title: 'Remove ALL MFA methods?',
                  message:
                    'This deletes every enrolled second factor AND every unused backup code. The user reverts to password-only login until they re-enroll. ' +
                    `Type ${expected} to confirm.`,
                  inputLabel: 'Confirm identifier',
                  placeholder: expected,
                  confirmLabel: 'Remove everything',
                  danger: true,
                  validate: v =>
                    v.trim().toLowerCase() === expected
                      ? null
                      : "Doesn't match.",
                })
                if (typed === null) return
                setBusy('Remove all MFA')
                try {
                  await api.deleteAllUserMFA(id)
                  await refreshMFA()
                  toast.success('All MFA methods and backup codes removed.')
                } catch (err) {
                  toast.error(
                    'Could not remove methods.',
                    err instanceof ApiError ? err.message : String(err),
                  )
                } finally {
                  setBusy(null)
                }
              }}
            >
              <ShieldOff size={14} />
              Remove all MFA methods
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* per-user linked identities. Read + unlink only. Removing the
          last identity for a user with no password credential is
          refused server-side (409 would_lock_out) the SPA reflects
          that as a friendlier "Set a password first" toast */}
      <Card noHover className="mt-6">
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle>Federated identities</CardTitle>
          <span className="text-xs font-medium text-on-surface-variant">
            {federationLinks.length === 0
              ? 'no providers linked'
              : `${federationLinks.length} provider${federationLinks.length === 1 ? '' : 's'} linked`}
          </span>
        </CardHeader>

        <CardContent>
          {federationLinks.length === 0 ? (
            <EmptyState
              title="No upstream links"
              description="This user has no upstream provider links. They sign in with their password (or MFA)."
            />
          ) : (
            <ul className="divide-y divide-border">
              {federationLinks.map(link => (
                <li key={link.id} className="flex items-start gap-3 py-3">
                  <Badge status="pending" label={link.display_name} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-semibold text-on-surface">
                      {link.email || link.provider_name || link.sub}
                    </p>
                    <p className="text-xs text-on-surface-variant">
                      <span className="font-mono">
                        sub:{' '}
                        {link.sub.length > 30
                          ? `${link.sub.slice(0, 27)}...`
                          : link.sub}
                      </span>
                      {' - '}
                      linked {formatDateTime(link.created_at)}
                      {link.updated_at !== link.created_at &&
                        ` · last login ${relativeTime(link.updated_at)}`}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="shrink-0 gap-2 text-error hover:bg-error/10"
                    disabled={!!busy}
                    onClick={async () => {
                      const ok = await confirm({
                        title: `Unlink ${link.display_name}?`,
                        message:
                          `The user will no longer be able to sign in via ${link.display_name}. ` +
                          'They can re-link on a future sign-in if they choose to.',
                        confirmLabel: 'Unlink',
                        danger: true,
                      })
                      if (!ok) return
                      setBusy('Unlink')
                      try {
                        await api.unlinkUserFederation(id, link.id)
                        await refreshFederation()
                        toast.success(`Unlinked ${link.display_name}.`)
                      } catch (err) {
                        // server returns 409 with code "would_lock_out"
                        // when removing this link would leave the user
                        // with no way to sign in (no password + no other
                        // federation). Translate that to a friendlier
                        // message, the admin should reset the password first, then retry
                        if (
                          err instanceof ApiError &&
                          err.code === 'would_lock_out'
                        ) {
                          toast.error(
                            "Can't unlink, user would be locked out.",
                            'Reset their password first, then retry the unlink.',
                          )
                        } else {
                          toast.error(
                            'Could not unlink.',
                            err instanceof ApiError ? err.message : String(err),
                          )
                        }
                      } finally {
                        setBusy(null)
                      }
                    }}
                  >
                    <Link2Off size={14} />
                    Unlink
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </>
  )
}

const Field = ({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) => (
  <>
    <dt className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant">
      {label}
    </dt>
    <dd className="text-sm text-on-surface">{children}</dd>
  </>
)

export default UserDetail
