import { useEffect, useState } from "react";

import PageHeader from "../components/PageHeader";
import { ErrorState, Loading } from "../components/States";
import { ApiError, api } from "../lib/api";
import type { SigningKey } from "../lib/types";

/*
 * Keys: view-only signing-key status. Rotation is intentionally a P7
 * deliverable — the storage layer supports it but exposing the action
 * here is risky without first wiring multi-key validation in the OIDC
 * service. For now, surface the active key and document the bootstrap
 * pattern: a single RSA key loaded from SIGNING_KEY_PATH (or ephemeral).
 *
 * The /.well-known/jwks.json endpoint is the canonical place for the
 * full JWK set; we link to it so admins don't have to remember the URL.
 */
export default function Keys() {
  const [keys, setKeys] = useState<SigningKey[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    api
      .listKeys(ctrl.signal)
      .then((res) => setKeys(res.keys))
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
        title="Signing keys"
        subtitle="Active keys used to sign OIDC id_tokens. Use `make rotate-key` to generate a new key file."
      />

      {error ? (
        <ErrorState error={error} />
      ) : keys === null ? (
        <Loading />
      ) : (
        <>
          <div className="card overflow-hidden">
            <table className="w-full">
              <thead className="bg-slate-50 dark:bg-slate-900/40">
                <tr>
                  <th className="table-th">Key ID</th>
                  <th className="table-th">Algorithm</th>
                  <th className="table-th">Role</th>
                  <th className="table-th">Source</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.kid} className="table-row">
                    <td className="table-td">
                      <code className="font-mono text-xs">{k.kid}</code>
                    </td>
                    <td className="table-td">
                      <span className="badge-slate">{k.alg}</span>
                    </td>
                    <td className="table-td">
                      {k.primary ? (
                        <span className="badge-green">primary</span>
                      ) : (
                        <span className="badge-slate">retiring</span>
                      )}
                    </td>
                    <td className="table-td">
                      <code className="font-mono text-xs text-slate-500 dark:text-slate-400">
                        {k.source || "—"}
                      </code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <InfoCard
              title="Public JWKS"
              body={
                <>
                  The full JWK set is published at{" "}
                  <a
                    href="/.well-known/jwks.json"
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-brand-600 hover:underline dark:text-brand-100"
                  >
                    /.well-known/jwks.json
                  </a>
                  . OIDC clients fetch this endpoint to validate id_token
                  signatures.
                </>
              }
            />
            <InfoCard
              title="Discovery"
              body={
                <>
                  The OpenID provider metadata is at{" "}
                  <a
                    href="/.well-known/openid-configuration"
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-brand-600 hover:underline dark:text-brand-100"
                  >
                    /.well-known/openid-configuration
                  </a>
                  .
                </>
              }
            />
          </div>
        </>
      )}
    </>
  );
}

function InfoCard({ title, body }: { title: string; body: React.ReactNode }) {
  return (
    <div className="card p-4">
      <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">{title}</h3>
      <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{body}</p>
    </div>
  );
}
