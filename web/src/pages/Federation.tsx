import { useEffect, useState } from "react";

import CopyButton from "../components/CopyButton";
import PageHeader from "../components/PageHeader";
import { EmptyState, ErrorState, Loading } from "../components/States";
import { ApiError, api } from "../lib/api";
import type { FederationProvider } from "../lib/types";

/*
 * Federation: read-only status of configured upstream providers.
 *
 * Why read-only: provider credentials (client ID + secret) live in env
 * vars and never touch the database. Letting admins edit them from the
 * UI would mean storing OAuth secrets at rest, with all the
 * backup/restore/leak surface that implies — for very little gain,
 * since you have to register a callback URL in the provider's console
 * anyway. The page answers a single operator question: "which providers
 * can a user actually sign in with right now?"
 *
 * The redirect URI for each provider IS exposed because it's the field
 * operators most often need to copy into the provider's console
 * (Google Cloud, GitHub Developer Settings, etc.) when wiring things up.
 */

export default function Federation() {
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
        subtitle="Upstream identity providers configured for sign-in. Read-only — manage credentials via environment variables."
      />

      {error ? (
        <ErrorState error={error} />
      ) : providers === null ? (
        <Loading />
      ) : providers.length === 0 ? (
        <EmptyState
          title="No providers configured"
          description="To enable Google, GitHub, Microsoft, or any other OIDC/OAuth2 provider, set the matching environment variables (see docs) and restart the server."
        />
      ) : (
        <>
          <ul className="space-y-2">
            {providers.map((p) => (
              <li key={p.name} className="card p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                      {p.display_name}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      slug: <code className="font-mono">{p.name}</code>
                    </p>
                  </div>
                  <span className="badge-green shrink-0">enabled</span>
                </div>
                <div className="mt-3">
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Redirect URI (paste this into the provider's OAuth client console)
                  </p>
                  <div className="mt-1 flex items-start gap-2 rounded bg-slate-50 p-2 dark:bg-slate-800">
                    <code className="min-w-0 flex-1 break-all font-mono text-xs text-slate-800 dark:text-slate-200">
                      {p.redirect_uri}
                    </code>
                    <CopyButton value={p.redirect_uri} label="" className="shrink-0" />
                  </div>
                </div>
              </li>
            ))}
          </ul>

          <div className="mt-6 card border-slate-100 bg-slate-50/60 p-4 dark:border-slate-800 dark:bg-slate-900/60">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">
              About this page
            </h3>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              Provider configuration lives in environment variables, not the database. The page
              above reflects what the server detected at boot. Credentials (client ID and secret)
              are intentionally not shown — they don't need to be visible here to verify the
              integration works.
            </p>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
              To add or change a provider: set the matching env vars (e.g. <code className="font-mono">GOOGLE_CLIENT_ID</code>,
              <code className="font-mono">GOOGLE_CLIENT_SECRET</code>), register the redirect URI
              shown above in the provider's console, and restart the server.
            </p>
          </div>
        </>
      )}
    </>
  );
}
