import { useEffect } from 'react'
import { useRegisterSW } from 'virtual:pwa-register/react'

import { useToast } from '@lusopoint/luso-ui'

// PwaUpdater: mounts once near the app root, registers the service
// worker, and surfaces two lifecycle events:
// - "available offline" toast (one-shot) once the SW has cached the shell on first install
// - a persistent reload banner at the bottom of the screen when a new version is detected
//   - the user keeps editing safely until they tap reload, the toast system is not right
//     for this it auto-dismisses, and refusing it shouldn't lose the prompt
//
// auto reload is intentionally avoided, an admin tool that silently
// reloads mid-edit would lose state and confuse anyone watching the
// audit log fill up with phantom sessions
const PwaUpdater = () => {
  const toast = useToast()
  const {
    offlineReady: [offlineReady, setOfflineReady],
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW({
    onRegisteredSW(swUrl, registration) {
      // poll for updates every 15 minutes, without this the browser
      // only checks on full page reload, so admins who keep the tab
      // open for hours would never see new versions
      if (registration && swUrl) {
        setInterval(
          () => {
            registration.update().catch(() => {
              // TODO: network blip or auth challenge
            })
          },
          15 * 60 * 1000,
        )
      }
    },
  })

  useEffect(() => {
    if (offlineReady) {
      toast.info(
        'Ready to use offline.',
        'The admin shell loads without a network.',
      )
      // one shot, flip the flag so we do not re toast
      setOfflineReady(false)
    }
  }, [offlineReady, setOfflineReady, toast])

  if (!needRefresh) return null
  return (
    <UpdateBanner
      onReload={() => updateServiceWorker(true)}
      onDismiss={() => setNeedRefresh(false)}
    />
  )
}

const UpdateBanner = ({
  onReload,
  onDismiss,
}: {
  onReload: () => void
  onDismiss: () => void
}) => {
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-3 z-50 flex justify-center px-3 sm:inset-x-auto sm:right-3 sm:justify-end">
      <div
        role="status"
        aria-live="polite"
        className="pointer-events-auto flex items-center gap-3 rounded-full border border-slate-200 bg-white px-3 py-1.5 shadow-md dark:border-slate-800 dark:bg-slate-900"
      >
        <span className="text-xs font-medium text-slate-700 dark:text-slate-200">
          New version available
        </span>
        <button
          type="button"
          onClick={onReload}
          className="rounded-full bg-brand-600 px-2.5 py-0.5 text-xs font-medium text-white hover:bg-brand-700"
        >
          Reload
        </button>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss update notification"
          className="rounded-full p-0.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200"
        >
          <svg
            viewBox="0 0 20 20"
            className="h-4 w-4"
            fill="currentColor"
            aria-hidden="true"
          >
            <path d="M5.7 5.7a1 1 0 0 1 1.4 0L10 8.6l2.9-2.9a1 1 0 1 1 1.4 1.4L11.4 10l2.9 2.9a1 1 0 0 1-1.4 1.4L10 11.4l-2.9 2.9a1 1 0 0 1-1.4-1.4L8.6 10 5.7 7.1a1 1 0 0 1 0-1.4Z" />
          </svg>
        </button>
      </div>
    </div>
  )
}
export default PwaUpdater
