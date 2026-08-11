import { Button, ErrorState as UIErrorState } from '@lusopoint/luso-ui'
import type { ApiError } from '../lib/api'
export { EmptyState, Loading } from '@lusopoint/luso-ui'

// ErrorState stays local, because what to do about an error is IAM policy
// not a UI concern: a 401/403 means the admin session lapsed, and the fix is a trip through CAS
// we use `next=` (a first-party same-origin redirect) rather than CAS's `service=` parameter
export const ErrorState = ({ error }: { error: ApiError | Error }) => {
  const status = 'status' in error ? (error as ApiError).status : undefined
  if (status === 401 || status === 403) {
    console.log(window.location.pathname, window.location.search)
    const next = `/${window.location.pathname}${window.location.search}`
    return (
      <UIErrorState
        error={{
          message: error.message || 'Admin session required.',
          status,
        }}
        title="Sign-in required"
        action={
          <Button
            onClick={() => {
              window.location.href = `/cas/login?next=${encodeURIComponent(next)}`
            }}
          >
            Go to sign-in
          </Button>
        }
      />
    )
  }

  return <UIErrorState error={error} />
}
