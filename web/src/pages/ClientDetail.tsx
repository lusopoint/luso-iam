import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  Button,
  Card,
  CardContent,
  Checkbox,
  Input,
  Loading,
  PageHeader,
  TagInput,
  useToast,
} from "@lusopoint/luso-ui";

import { ScopesEditor } from "../components/ScopesEditor";
import { ErrorState } from "../components/States";
import { ApiError, api } from "../lib/api";
import type { OIDCClient } from "../lib/types";
import { validRedirectURI } from "../lib/util";

const GRANT_TYPES = ["authorization_code", "refresh_token", "client_credentials"];

const ClientDetail = () => {
  const { id = "" } = useParams<{ id: string }>();
  const toast = useToast();

  const [client, setClient] = useState<OIDCClient | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState(false);

  // editable form fields
  const [name, setName] = useState("");
  const [redirectURIs, setRedirectURIs] = useState<string[]>([]);
  const [scopes, setScopes] = useState<string[]>([]);
  const [grantTypes, setGrantTypes] = useState<string[]>([]);
  const [requirePKCE, setRequirePKCE] = useState(false);
  const [requireConsent, setRequireConsent] = useState(false);
  const [enabled, setEnabled] = useState(true);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    api
      .getClient(id, ctrl.signal)
      .then((c) => {
        setClient(c);
        setName(c.name);
        setRedirectURIs(c.redirect_uris);
        setScopes(c.allowed_scopes);
        setGrantTypes(c.allowed_grant_types);
        setRequirePKCE(c.require_pkce);
        setRequireConsent(c.require_consent);
        setEnabled(c.enabled);
        setError(null);
      })
      .catch((e) => {
        if (ctrl.signal.aborted) return;
        setError(
          e instanceof ApiError
            ? e
            : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(e) }),
        );
      })
      .finally(() => setLoading(false));
    return () => ctrl.abort();
  }, [id]);

  const toggleGrant = (g: string, on: boolean) => {
    setGrantTypes((prev) => (on ? [...new Set([...prev, g])] : prev.filter((x) => x !== g)));
  }

  const save = async () => {
    setSaving(true);
    try {
      const updated = await api.updateClient(id, {
        name,
        redirect_uris: redirectURIs,
        allowed_scopes: scopes,
        allowed_grant_types: grantTypes,
        require_pkce: requirePKCE,
        require_consent: requireConsent,
        enabled,
      });
      setClient(updated);
      toast.success("Client updated.");
    } catch (e) {
      toast.error("Update failed.", e instanceof ApiError ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <Loading label="Loading client…" />;
  if (error) return <ErrorState error={error} />;
  if (!client) return <ErrorState error={new Error("Client not found.")} />;

  // public clients always require PKCE; the toggle reflects and locks that
  const pkceLocked = client.is_public;

  return (
    <>
      <PageHeader
        breadcrumbs={[{ label: "Clients", href: "/clients" }, { label: client.name || client.id }]}
        title={client.name || client.id}
        subtitle={`${client.id} · ${client.is_public ? "public" : "confidential"}`}
        actions={
          <Link to="/clients">
            <Button variant="outline">Back to clients</Button>
          </Link>
        }
      />

      <Card noHover className="max-w-2xl">
        <CardContent className="space-y-6 pt-6">
          <Input
            label="Display name"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />

          <div>
            <TagInput
              label="Redirect URIs"
              value={redirectURIs}
              onChange={setRedirectURIs}
              placeholder="https://app.example.com/callback"
              validate={validRedirectURI}
            />
            <p className="ml-1 mt-2 text-xs text-on-surface-variant">
              Exact-match; at least one required.
            </p>
          </div>

          <ScopesEditor value={scopes} onChange={setScopes} />

          <div>
            <span className="ml-1 text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant">
              Grant types
            </span>
            <div className="mt-3 flex flex-wrap gap-6">
              {GRANT_TYPES.map((g) => (
                <Checkbox
                  key={g}
                  label={g}
                  checked={grantTypes.includes(g)}
                  onChange={(e) => toggleGrant(g, e.target.checked)}
                  className="font-mono"
                />
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <Checkbox
              label="Require PKCE (S256)"
              description={
                pkceLocked
                  ? "Always required for public clients."
                  : "Recommended for confidential clients."
              }
              checked={pkceLocked ? true : requirePKCE}
              disabled={pkceLocked}
              onChange={(e) => setRequirePKCE(e.target.checked)}
            />
            <Checkbox
              label="Require consent"
              description="Show a consent screen."
              checked={requireConsent}
              onChange={(e) => setRequireConsent(e.target.checked)}
            />
            <Checkbox
              label="Enabled"
              description="Disabled clients are rejected at authorization."
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
          </div>

          <div className="flex justify-end">
            <Button onClick={save} disabled={saving || redirectURIs.length === 0}>
              {saving ? "Saving…" : "Save changes"}
            </Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
export default ClientDetail
