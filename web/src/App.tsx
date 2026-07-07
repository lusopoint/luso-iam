import { Navigate, Route, Routes } from "react-router-dom";
import { ConfirmProvider } from "./components/Confirm";
import Layout from "./components/Layout";
import { PromptProvider } from "./components/Prompt";
import PwaUpdater from "./components/PwaUpdater";
import { ErrorState, Loading } from "./components/States";
import { ToastProvider } from "./components/Toast";
import { useMe } from "./lib/auth";
import Audit from "./pages/Audit";
import ClientNew from "./pages/ClientNew";
import ClientDetail from "./pages/ClientDetail";
import Clients from "./pages/Clients";
import Dashboard from "./pages/Dashboard";
import Federation from "./pages/Federation";
import Keys from "./pages/Keys";
import CASServices from "./pages/CASServices";
import UserDetail from "./pages/UserDetail";
import Users from "./pages/Users";

/*
 * Top-level routing. The /me call gates everything — if the visitor
 * isn't an authenticated admin we show ErrorState (which surfaces a
 * Sign-In button pointing at /cas/login), not a Login page. Putting the
 * actual sign-in on the CAS UI keeps a single source of truth for
 * authentication and lets MFA, federation, etc. work transparently.
 *
 * Toast + Confirm providers wrap everything so every page can call
 * useToast() / useConfirm() without prop drilling.
 */
export default function App() {
  const me = useMe();

  if (me.loading) {
    return (
      <div className="grid min-h-screen place-items-center">
        <Loading label="Checking session…" />
      </div>
    );
  }

  if (me.error || !me.user) {
    return (
      <div className="mx-auto max-w-md p-10">
        <h1 className="mb-3 text-xl font-semibold">IAM admin</h1>
        <ErrorState
          error={me.error ?? new Error("Not signed in.")}
        />
      </div>
    );
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
          {/* Side-effect component: registers the SW, surfaces "ready
              offline" once, and renders the reload banner when a new
              version is available. Has to live inside ToastProvider. */}
          <PwaUpdater />
        </PromptProvider>
      </ConfirmProvider>
    </ToastProvider>
  );
}
