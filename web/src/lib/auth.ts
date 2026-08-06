import { useEffect, useState } from 'react'
import { api, ApiError } from './api'
import type { AdminUser } from './types'

export interface MeState {
  loading: boolean
  user: AdminUser | null
  error: ApiError | null
}

export const useMe = (): MeState => {
  const [state, setState] = useState<MeState>({
    loading: true,
    user: null,
    error: null,
  })

  useEffect(() => {
    const ctrl = new AbortController()
    api
      .me(ctrl.signal)
      .then(res => setState({ loading: false, user: res.user, error: null }))
      .catch(err => {
        if (ctrl.signal.aborted) return
        const apiErr =
          err instanceof ApiError
            ? err
            : new ApiError({
                type: 'about:blank',
                title: 'Network error',
                status: 0,
                detail: String(err),
              })
        setState({ loading: false, user: null, error: apiErr })
      })
    return () => ctrl.abort()
  }, [])

  return state
}
