import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Alert,
  Button,
  Card,
  CardContent,
  Checkbox,
  Input,
  PageHeader,
  TagInput,
} from '@lusopoint/luso-ui'

import { ScopesEditor } from '../components/ScopesEditor'
import { SecretBanner } from './Clients'
import { validRedirectURI } from '../lib/util'
import { ApiError, api } from '../lib/api'
import type { CreateClientRequest, OIDCClient } from '../lib/types'

const ClientNew = () => {
  const navigate = useNavigate()

  const [form, setForm] = useState<CreateClientRequest>({
    id: '',
    name: '',
    redirect_uris: [],
    allowed_scopes: ['openid', 'profile', 'email'],
    allowed_grant_types: ['authorization_code', 'refresh_token'],
    is_public: false,
    require_pkce: true,
    require_consent: false,
  })
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [created, setCreated] = useState<{
    client: OIDCClient
    secret?: string
  } | null>(null)

  function updateField<K extends keyof CreateClientRequest>(
    k: K,
    v: CreateClientRequest[K],
  ) {
    setForm(f => ({ ...f, [k]: v }))
  }

  const submit = async () => {
    setError(null)
    setBusy(true)
    try {
      const res = await api.createClient(form)
      setCreated({ client: res.client, secret: res.secret })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  if (created) {
    return (
      <>
        <PageHeader
          title="Client registered"
          subtitle={`"${created.client.name}" is ready to use.`}
          actions={
            <Link to="/clients">
              <Button variant="outline">Back to clients</Button>
            </Link>
          }
        />
        {created.secret ? (
          <SecretBanner
            title={`Client secret for "${created.client.id}"`}
            secret={created.secret}
            onDismiss={() => navigate('/clients')}
          />
        ) : (
          <Alert variant="info" title="No secret issued">
            This is a public client, so it authenticates with PKCE rather than a
            secret.
          </Alert>
        )}
      </>
    )
  }

  const valid =
    form.id.trim() !== '' &&
    form.name.trim() !== '' &&
    form.redirect_uris.length > 0

  return (
    <>
      <PageHeader
        title="Register OIDC client"
        actions={
          <Link to="/clients">
            <Button variant="outline">Cancel</Button>
          </Link>
        }
      />

      <Card noHover className="max-w-2xl">
        <CardContent className="space-y-6 pt-6">
          {error && <Alert variant="error">{error}</Alert>}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <Input
                label="Client ID"
                className="font-mono"
                value={form.id}
                onChange={e => updateField('id', e.target.value)}
                placeholder="my-app"
                required
              />
              <p className="ml-1 mt-1 text-xs text-on-surface-variant">
                Stable identifier; no whitespace, no slashes.
              </p>
            </div>
            <Input
              label="Display name"
              value={form.name}
              onChange={e => updateField('name', e.target.value)}
              placeholder="My App"
              required
            />
          </div>

          {/* Was an array of <input> rows with add/remove buttons. TagInput
              gives the same thing plus dedupe and per-entry URL validation. */}
          <div>
            <TagInput
              label="Redirect URIs"
              value={form.redirect_uris}
              onChange={next => updateField('redirect_uris', next)}
              placeholder="https://app.example.com/callback"
              validate={validRedirectURI}
            />
            <p className="ml-1 mt-2 text-xs text-on-surface-variant">
              Absolute http or https URLs. At least one required.
            </p>
          </div>

          <div>
            <ScopesEditor
              value={form.allowed_scopes ?? []}
              onChange={next => updateField('allowed_scopes', next)}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Checkbox
              label="Public client (no secret)"
              description="SPAs and mobile apps. PKCE is mandatory."
              checked={form.is_public}
              onChange={e =>
                // Public clients always require PKCE (the server enforces this
                // too). Keep the form payload consistent by forcing the flag
                // on when public is selected.
                setForm(f => ({
                  ...f,
                  is_public: e.target.checked,
                  require_pkce: e.target.checked ? true : f.require_pkce,
                }))
              }
            />
            <Checkbox
              label="Require PKCE (S256)"
              description={
                form.is_public
                  ? 'Always required for public clients.'
                  : "Recommended. Disable only for confidential clients that can't send a code_challenge."
              }
              checked={form.is_public ? true : (form.require_pkce ?? false)}
              disabled={form.is_public}
              onChange={e => updateField('require_pkce', e.target.checked)}
            />
            <Checkbox
              label="Require user consent"
              description="Show a consent screen on first authorization."
              checked={form.require_consent}
              onChange={e => updateField('require_consent', e.target.checked)}
            />
          </div>

          <div className="flex justify-end gap-3">
            <Link to="/clients">
              <Button variant="ghost">Cancel</Button>
            </Link>
            <Button onClick={submit} disabled={busy || !valid}>
              {busy ? 'Registering…' : 'Register client'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </>
  )
}
export default ClientNew
