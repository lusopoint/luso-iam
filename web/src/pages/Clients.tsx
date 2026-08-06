import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Alert,
  Badge,
  Button,
  Card,
  CodeBlock,
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
  useToast,
} from '@lusopoint/luso-ui'
import { Plus } from 'lucide-react'

import { ErrorState } from '../components/States'
import { ApiError, api } from '../lib/api'
import type { OIDCClient } from '../lib/types'
import { formatDateTime } from '../lib/util'

const Clients = () => {
  const toast = useToast()
  const confirm = useConfirm()
  const [clients, setClients] = useState<OIDCClient[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const [rotated, setRotated] = useState<{ id: string; secret: string } | null>(
    null,
  )

  useEffect(() => {
    const ctrl = new AbortController()
    api
      .listClients(ctrl.signal)
      .then(res => {
        setClients(res.clients)
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
  }, [])

  const rotate = async (id: string) => {
    const ok = await confirm({
      title: `Rotate the secret for "${id}"?`,
      message:
        "All integrations using the old secret will fail until they're updated with the new one. This takes effect immediately.",
      confirmLabel: 'Rotate',
      danger: true,
    })
    if (!ok) return
    try {
      const res = await api.rotateClientSecret(id)
      setRotated({ id, secret: res.secret })
      toast.success(
        'Secret rotated.',
        'Copy the new value before leaving this page.',
      )
    } catch (err) {
      toast.error(
        'Could not rotate secret.',
        err instanceof ApiError ? err.message : String(err),
      )
    }
  }

  const remove = async (id: string) => {
    const ok = await confirm({
      title: `Delete client "${id}"?`,
      message:
        'This is a soft delete: tokens already issued continue to validate until they expire.',
      confirmLabel: 'Delete',
      danger: true,
    })
    if (!ok) return
    try {
      await api.deleteClient(id)
      setClients(cs => cs.filter(c => c.id !== id))
      toast.success(`Deleted client "${id}".`)
    } catch (err) {
      toast.error(
        'Could not delete client.',
        err instanceof ApiError ? err.message : String(err),
      )
    }
  }

  const registerButton = (
    <Link to="/clients/new">
      <Button className="gap-2">
        <Plus size={16} />
        Register client
      </Button>
    </Link>
  )

  return (
    <>
      <PageHeader
        title="OIDC clients"
        subtitle="Registered relying parties for OAuth 2.0 / OpenID Connect."
        actions={registerButton}
      />

      {loading && <Loading label="Loading clients…" />}
      {error && <ErrorState error={error} />}
      {!loading && !error && clients.length === 0 && (
        <EmptyState
          title="No OIDC clients registered yet."
          description="Register your first client to start issuing tokens."
          action={registerButton}
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
              keep the card scannable, operators can tap into the JSON
              from a desktop session if they need that depth. */}
          <ul className="space-y-3 md:hidden">
            {clients.map(c => (
              <li key={c.id}>
                <Card noHover className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-bold text-on-surface">
                        {c.name}
                      </p>
                      <code className="block truncate font-mono text-xs text-on-surface-variant">
                        {c.id}
                      </code>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1">
                      <Badge
                        status={c.enabled ? 'operational' : 'critical'}
                        label={c.enabled ? 'enabled' : 'disabled'}
                      />
                      <Badge
                        status={c.is_public ? 'pending' : 'in_progress'}
                        label={c.is_public ? 'public' : 'confidential'}
                      />
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-on-surface-variant">
                    {c.require_pkce && (
                      <Badge status="operational" label="PKCE" />
                    )}
                    <span>
                      {c.redirect_uris.length} redirect
                      {c.redirect_uris.length === 1 ? '' : 's'}
                    </span>
                    <span>·</span>
                    <span>{formatDateTime(c.created_at)}</span>
                  </div>
                  <div className="mt-4 flex justify-end gap-2">
                    <Link to={`/clients/${c.id}`}>
                      <Button variant="ghost" size="sm">
                        Edit
                      </Button>
                    </Link>
                    {!c.is_public && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => rotate(c.id)}
                      >
                        Rotate secret
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => remove(c.id)}
                      className="text-error hover:bg-error/10"
                    >
                      Delete
                    </Button>
                  </div>
                </Card>
              </li>
            ))}
          </ul>

          {/* Desktop: full table. Hidden under md. */}
          <Card noHover className="hidden overflow-hidden md:block">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Client</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Grants</TableHead>
                  <TableHead>Redirect URIs</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {clients.map(c => (
                  <TableRow key={c.id}>
                    <TableCell>
                      <div className="font-bold text-on-surface">{c.name}</div>
                      <code className="font-mono text-xs text-on-surface-variant">
                        {c.id}
                      </code>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        <Badge
                          status={c.is_public ? 'pending' : 'in_progress'}
                          label={c.is_public ? 'public' : 'confidential'}
                        />
                        {c.require_pkce && (
                          <Badge status="operational" label="PKCE" />
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {c.allowed_grant_types.map(g => (
                          <Badge key={g} status="pending" label={g} />
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="max-w-xs text-xs">
                        {c.redirect_uris.slice(0, 2).map(u => (
                          <div key={u} className="truncate" title={u}>
                            {u}
                          </div>
                        ))}
                        {c.redirect_uris.length > 2 && (
                          <div className="text-on-surface-variant/60">
                            + {c.redirect_uris.length - 2} more
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        status={c.enabled ? 'operational' : 'critical'}
                        label={c.enabled ? 'enabled' : 'disabled'}
                      />
                    </TableCell>
                    <TableCell>{formatDateTime(c.created_at)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Link to={`/clients/${c.id}`}>
                          <Button variant="ghost" size="sm">
                            Edit
                          </Button>
                        </Link>
                        {!c.is_public && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => rotate(c.id)}
                          >
                            Rotate
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => remove(c.id)}
                          className="text-error hover:bg-error/10"
                        >
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </>
      )}
    </>
  )
}

/**
 * Shown exactly once, immediately after a secret is minted or rotated. The
 * plaintext is never retrievable again, so the copy affordance matters more
 * than the styling, CodeBlock handles the clipboard fallback for insecure
 * origins, and toasts on success so the confirmation survives focus moving.
 */
export const SecretBanner = ({
  title,
  secret,
  onDismiss,
}: {
  title: string
  secret: string
  onDismiss: () => void
}) => {
  const toast = useToast()

  return (
    <Alert
      variant="warning"
      title={title}
      className="mb-6 flex-col sm:flex-row"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
          <p>This is the only time you'll see this value. Copy it now.</p>
          <CodeBlock
            value={secret}
            inline
            className="mt-2"
            onCopied={() => toast.success('Copied to clipboard')}
          />
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={onDismiss}
          className="shrink-0"
        >
          Dismiss
        </Button>
      </div>
    </Alert>
  )
}

export default Clients
