import { useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CodeBlock,
  EmptyState,
  Loading,
  PageHeader,
} from "@lusopoint/luso-ui";

import { ErrorState } from "../components/States";
import { ApiError, api } from "../lib/api";
import type { FederationProvider } from "../lib/types";

const Federation = () => {
  const [providers, setProviders] = useState<FederationProvider[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    api
      .listFederationProviders(ctrl.signal)
      .then((r) => setProviders(r.providers))
      .catch((err) => {
        if (ctrl.signal.aborted) return;
        setError(
          err instanceof ApiError
            ? err
            : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }),
        );
      });
    return () => ctrl.abort();
  }, []);

  return (
    <>
      <PageHeader
        title="Federation"
        subtitle="Upstream identity providers configured for sign-in. Read-only, manage credentials via environment variables."
      />

      {error ? (
        <ErrorState error={error} />
      ) : providers === null ? (
        <Loading label="Loading providers…" />
      ) : providers.length === 0 ? (
        <EmptyState
          title="No providers configured"
          description="To enable Google, GitHub, Microsoft, or any other OIDC/OAuth2 provider, set the matching environment variables (see docs) and restart the server."
        />
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {providers.map((p) => (
              <Card key={p.name} noHover>
                <CardHeader className="flex-row items-start justify-between space-y-0">
                  <div className="min-w-0">
                    <CardTitle>{p.display_name}</CardTitle>
                    <p className="mt-1 font-mono text-xs text-on-surface-variant">
                      {p.name}
                    </p>
                  </div>
                  <Badge status="operational" label="enabled" />
                </CardHeader>
                <CardContent>
                  <p className="mb-1.5 ml-1 text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant">
                    Redirect URI
                  </p>
                  <CodeBlock value={p.redirect_uri} inline />
                  <p className="mt-2 text-xs text-on-surface-variant">
                    Paste this into the provider's OAuth client console.
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>

          <Alert variant="info" title="About this page" className="mt-8">
            <p>
              Provider configuration lives in environment variables, not the database. The list
              above reflects what the server detected at boot. Credentials (client ID and secret)
              are intentionally not shown, they don't need to be visible here to verify the
              integration works.
            </p>
            <p className="mt-2">
              To add or change a provider: set the matching env vars (e.g.{" "}
              <code className="font-mono">GOOGLE_CLIENT_ID</code>,{" "}
              <code className="font-mono">GOOGLE_CLIENT_SECRET</code>), register the redirect URI
              shown above in the provider's console, and restart the server.
            </p>
          </Alert>
        </>
      )}
    </>
  );
}
export default Federation
