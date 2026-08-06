import { Navigate, Route, Routes } from 'react-router-dom'
import {
  ConfirmProvider,
  Loading,
  PromptProvider,
  ToastProvider,
} from '@lusopoint/luso-ui'

import Layout from './components/Layout'
import PwaUpdater from './components/PwaUpdater'
import { ErrorState } from './components/States'
import { useMe } from './lib/auth'
import Audit from './pages/Audit'
import ClientNew from './pages/ClientNew'
import ClientDetail from './pages/ClientDetail'
import Clients from './pages/Clients'
import Dashboard from './pages/Dashboard'
import Federation from './pages/Federation'
import Keys from './pages/Keys'
import CASServices from './pages/CASServices'
import UserDetail from './pages/UserDetail'
import Users from './pages/Users'

const App = () => {
  const me = useMe()

  if (me.loading) {
    return (
      <div className="grid min-h-screen place-items-center">
        <Loading label="Checking session…" />
      </div>
    )
  }

  if (me.error || !me.user) {
    return (
      <div className="mx-auto grid min-h-screen max-w-lg place-items-center p-6">
        <ErrorState error={me.error ?? new Error('Not signed in.')} />
      </div>
    )
  }

  return (
    <ToastProvider>
      <ConfirmProvider>
        <PromptProvider>
          <Routes>
            <Route element={<Layout me={me.user} />}>
              <Route index element={<Dashboard />} />
              <Route path="users" element={<Users />} />
              <Route path="users/:id" element={<UserDetail />} />
              <Route path="clients" element={<Clients />} />
              <Route path="clients/new" element={<ClientNew />} />
              <Route path="clients/:id" element={<ClientDetail />} />
              <Route path="cas-services" element={<CASServices />} />
              <Route path="federation" element={<Federation />} />
              <Route path="audit" element={<Audit />} />
              <Route path="keys" element={<Keys />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
          {/*
          side-effect component: registers the SW, surfaces "ready
          offline" once, and renders the reload banner when a new
          version is available. Has to live inside ToastProvider
          */}
          <PwaUpdater />
        </PromptProvider>
      </ConfirmProvider>
    </ToastProvider>
  )
}

export default App
