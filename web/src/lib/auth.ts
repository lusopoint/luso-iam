import { useEffect, useState } from "react";

import { api, ApiError } from "./api";
import type { AdminUser } from "./types";

/*
 * useMe loads the currently authenticated admin from /admin/v1/me. The
 * three states are intentionally narrow:
 *
 *   - loading: initial fetch in flight, render nothing or a spinner
 *   - error:   not signed in OR not an admin OR network failure
 *   - user:    the authenticated admin User DTO
 *
 * The hook lives at the App level so every protected page can read it
 * via context without a per-page fetch.
 */
export interface MeState {
  loading: boolean;
  user: AdminUser | null;
  error: ApiError | null;
}

export function useMe(): MeState {
  const [state, setState] = useState<MeState>({
    loading: true,
    user: null,
    error: null,
  });

  useEffect(() => {
    const ctrl = new AbortController();
    api
      .me(ctrl.signal)
      .then((res) => setState({ loading: false, user: res.user, error: null }))
      .catch((err) => {
        if (ctrl.signal.aborted) return;
        const apiErr =
          err instanceof ApiError
            ? err
            : new ApiError({
                type: "about:blank",
                title: "Network error",
                status: 0,
                detail: String(err),
              });
        setState({ loading: false, user: null, error: apiErr });
      });
    return () => ctrl.abort();
  }, []);

  return state;
}
