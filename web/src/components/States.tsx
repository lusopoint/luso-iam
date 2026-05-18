import type { ReactNode } from "react";

import type { ApiError } from "../lib/api";

/**
 * Loading: tiny inline spinner. Pages call this when the initial fetch
 * hasn't resolved yet — anything heavier (skeleton screens, etc.) is
 * overkill for an admin tool.
 */
export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-4 text-sm text-slate-500 dark:text-slate-400">
      <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-slate-300 border-t-brand-500" />
      <span>{label}</span>
    </div>
  );
}

/**
 * ErrorState: renders any caught ApiError. For 401/403 we point the user
 * to the CAS login screen — the most common cause is an expired session.
 *
 * We use `next=` (a first-party same-origin redirect) rather than CAS's
 * `service=` parameter. The admin SPA is part of this server, not a
 * downstream CAS client, so it has no entry in the cas_services
 * registry — sending it as `service=` would 403 as "Service not
 * authorized". `next=` skips the registry lookup entirely.
 */
export function ErrorState({ error }: { error: ApiError | Error }) {
  if ("status" in error && (error.status === 401 || error.status === 403)) {
    const next = "/admin" + window.location.pathname + window.location.search;
    return (
      <div className="card p-4 text-sm">
        <p className="mb-2 font-medium text-slate-800 dark:text-slate-200">
          You need to sign in as an admin.
        </p>
        <p className="mb-3 text-slate-500 dark:text-slate-400">
          {error.message || "Admin session required."}
        </p>
        <a
          href={`/cas/login?next=${encodeURIComponent(next)}`}
          className="btn-primary"
        >
          Go to sign-in
        </a>
      </div>
    );
  }
  return (
    <div className="card border-red-200 bg-red-50 p-4 text-sm text-red-800 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-300">
      <p className="font-medium">{error.message || "Something went wrong."}</p>
    </div>
  );
}

/**
 * EmptyState: shown when a list query returns zero rows. Includes an
 * optional action slot so pages can suggest the obvious next step
 * (e.g. "Register your first OIDC client").
 */
export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="card p-8 text-center">
      <h3 className="text-sm font-medium text-slate-800 dark:text-slate-200">{title}</h3>
      {description && (
        <p className="mx-auto mt-1 max-w-md text-sm text-slate-500 dark:text-slate-400">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
