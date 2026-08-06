import { useEffect, useState } from 'react'
import {
  Alert,
  Badge,
  Card,
  Loading,
  PageHeader,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@lusopoint/luso-ui'
import { ExternalLink } from 'lucide-react'

import { ErrorState } from '../components/States'
import { ApiError, api } from '../lib/api'
import type { SigningKey } from '../lib/types'

const Keys = () => {
  const [keys, setKeys] = useState<SigningKey[] | null>(null)
  const [error, setError] = useState<ApiError | null>(null)

  useEffect(() => {
    const ctrl = new AbortController()
    api
      .listKeys(ctrl.signal)
      .then(res => setKeys(res.keys))
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
      })
    return () => ctrl.abort()
  }, [])

  return (
    <>
      <PageHeader
        title="Signing keys"
        subtitle="Active keys used to sign OIDC id_tokens. Use `make rotate-key` to generate a new key file."
      />

      {error ? (
        <ErrorState error={error} />
      ) : keys === null ? (
        <Loading label="Loading keys..." />
      ) : (
        <>
          <Card noHover className="overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Key ID</TableHead>
                  <TableHead>Algorithm</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map(k => (
                  <TableRow key={k.kid}>
                    <TableCell>
                      <code className="font-mono text-xs">{k.kid}</code>
                    </TableCell>
                    <TableCell>
                      <Badge status="pending" label={k.alg} />
                    </TableCell>
                    <TableCell>
                      {k.primary ? (
                        <Badge status="operational" label="primary" />
                      ) : (
                        <Badge status="decommissioned" label="retiring" />
                      )}
                    </TableCell>
                    <TableCell>
                      <code className="font-mono text-xs text-on-surface-variant">
                        {k.source || '-'}
                      </code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>

          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Alert variant="info" title="Public JWKS">
              The full JWK set is published at
              <WellKnownLink href="/.well-known/jwks.json" />. OIDC clients
              fetch this endpoint to validate id_token signatures.
            </Alert>
            <Alert variant="info" title="Discovery">
              The OpenID provider metadata is at
              <WellKnownLink href="/.well-known/openid-configuration" />.
            </Alert>
          </div>
        </>
      )}
    </>
  )
}

const WellKnownLink = ({ href }: { href: string }) => (
  <a
    href={href}
    target="_blank"
    rel="noreferrer"
    className="inline-flex items-center gap-1 font-mono underline underline-offset-2 hover:opacity-70"
  >
    {href}
    <ExternalLink size={11} />
  </a>
)
export default Keys
