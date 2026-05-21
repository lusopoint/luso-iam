import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

import type { AdminUser } from "../lib/types";

/*
 * Layout is the persistent shell — top bar with admin identity, left
 * sidebar nav on desktop, hidden-by-default drawer on mobile. Pages
 * render via <Outlet />, so navigating never unmounts the chrome.
 *
 * Responsive strategy: a single Tailwind breakpoint (md, 768px) flips
 * between two layouts. On small screens the nav becomes a slide-in
 * drawer triggered by a hamburger; on medium-and-up the sidebar is
 * always visible and the hamburger is hidden. Body content stays the
 * same shape either way.
 */

interface LayoutProps {
  me: AdminUser;
}

const NAV_ITEMS: Array<{ to: string; label: string; end?: boolean }> = [
  { to: "/",             label: "Dashboard", end: true },
  { to: "/users",        label: "Users" },
  { to: "/clients",      label: "OIDC clients" },
  { to: "/cas-services", label: "CAS services" },
  { to: "/federation",   label: "Federation" },
  { to: "/audit",        label: "Audit log" },
  { to: "/keys",         label: "Signing keys" },
];

export default function Layout({ me }: LayoutProps) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const location = useLocation();

  // Close the drawer whenever the route changes. Otherwise the drawer
  // stays open after a tap on a nav item, which feels janky on mobile.
  useEffect(() => {
    setDrawerOpen(false);
  }, [location.pathname]);

  // Lock body scroll when the drawer is open so the background can't
  // scroll behind it. Only applies on small screens.
  useEffect(() => {
    if (!drawerOpen) return;
    const original = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = original;
    };
  }, [drawerOpen]);

  return (
    <div className="flex min-h-full">
      {/* Desktop sidebar — always rendered, hidden under md */}
      <aside className="hidden w-56 shrink-0 border-r border-slate-200 bg-white md:block dark:border-slate-800 dark:bg-slate-900">
        <SidebarContent />
      </aside>

      {/* Mobile drawer — slides in from the left when open */}
      <MobileDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)}>
        <SidebarContent />
      </MobileDrawer>

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar me={me} onHamburger={() => setDrawerOpen(true)} />
        <main className="flex-1 overflow-x-hidden px-4 py-5 sm:px-6 sm:py-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

// ─── Top bar ──────────────────────────────────────────────────────────────

function TopBar({ me, onHamburger }: { me: AdminUser; onHamburger: () => void }) {
  const label = me.display_name || me.email || me.username || me.id;
  return (
    <header className="flex items-center gap-2 border-b border-slate-200 bg-white px-3 py-2 sm:px-6 sm:py-3 dark:border-slate-800 dark:bg-slate-900">
      {/* Hamburger — only visible under md */}
      <button
        type="button"
        onClick={onHamburger}
        aria-label="Open navigation menu"
        className="-ml-1 inline-flex h-9 w-9 items-center justify-center rounded-md text-slate-600
                   hover:bg-slate-100 active:bg-slate-200 md:hidden
                   dark:text-slate-300 dark:hover:bg-slate-800 dark:active:bg-slate-700"
      >
        <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden className="h-5 w-5">
          <path d="M3 5a1 1 0 0 1 1-1h12a1 1 0 1 1 0 2H4a1 1 0 0 1-1-1Zm0 5a1 1 0 0 1 1-1h12a1 1 0 1 1 0 2H4a1 1 0 0 1-1-1Zm1 4a1 1 0 1 0 0 2h12a1 1 0 1 0 0-2H4Z" />
        </svg>
      </button>

      {/* Identity — flex-1 so the sign-out anchors to the far right */}
      <div className="min-w-0 flex-1 text-sm text-slate-500 dark:text-slate-400">
        <span className="hidden sm:inline">Signed in as </span>
        <span className="truncate font-medium text-slate-700 dark:text-slate-200">
          {label}
        </span>
        <span className="badge-brand ml-2">admin</span>
      </div>

      {/* External links — /mfa/enroll is the server-rendered security page,
          not part of the SPA, so we use a plain <a> with a full page nav. */}
      <a
        href="/mfa/enroll"
        title="Manage your second factors"
        className="hidden rounded-md px-2 py-1 text-sm text-slate-500 transition hover:bg-slate-100 hover:text-slate-800
                   sm:inline dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
      >
        Security
      </a>

      <a
        href="/cas/logout"
        className="rounded-md px-2 py-1 text-sm text-slate-500 transition hover:bg-slate-100 hover:text-slate-800
                   dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
      >
        Sign out
      </a>
    </header>
  );
}

// ─── Sidebar (shared between desktop + drawer) ────────────────────────────

function SidebarContent() {
  return (
    <nav className="px-3 py-4">
      <div className="px-2 pb-3 text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
        IAM&nbsp;admin
      </div>
      <ul className="space-y-0.5">
        {NAV_ITEMS.map((it) => (
          <li key={it.to}>
            <NavLink
              to={it.to}
              end={it.end}
              className={({ isActive }) =>
                `block rounded-md px-3 py-2 text-sm transition ${
                  isActive
                    ? "bg-brand-100 text-brand-700 dark:bg-brand-700/40 dark:text-brand-100"
                    : "text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                }`
              }
            >
              {it.label}
            </NavLink>
          </li>
        ))}
      </ul>

      {/* Personal section — lives outside the React router because the MFA
          enrollment pages are server-rendered, not part of the SPA. Plain
          <a> triggers a full navigation, which is what we want here. */}
      <div className="mt-6 px-2 pb-3 text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
        Your&nbsp;account
      </div>
      <ul className="space-y-0.5">
        <li>
          <a
            href="/mfa/enroll"
            className="block rounded-md px-3 py-2 text-sm text-slate-700 transition hover:bg-slate-100
                       dark:text-slate-300 dark:hover:bg-slate-800"
          >
            Security &amp; MFA
          </a>
        </li>
      </ul>
    </nav>
  );
}

// ─── Mobile drawer ────────────────────────────────────────────────────────

function MobileDrawer({
  open,
  onClose,
  children,
}: {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
}) {
  // We render the drawer unconditionally and toggle visibility via CSS so
  // the slide transition runs both directions. Pointer events disabled on
  // the backdrop when closed so it doesn't intercept touches.
  return (
    <div
      className={`fixed inset-0 z-40 md:hidden ${open ? "" : "pointer-events-none"}`}
      aria-hidden={!open}
    >
      {/* Backdrop */}
      <div
        onClick={onClose}
        className={`absolute inset-0 bg-black/40 transition-opacity duration-200 ${
          open ? "opacity-100" : "opacity-0"
        }`}
      />
      {/* Drawer panel */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Navigation"
        className={`absolute inset-y-0 left-0 w-64 max-w-[80%] border-r border-slate-200 bg-white
                    shadow-xl transition-transform duration-200 ease-out dark:border-slate-800 dark:bg-slate-900
                    ${open ? "translate-x-0" : "-translate-x-full"}`}
      >
        <div className="flex items-center justify-between px-3 py-2">
          <span className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
            IAM&nbsp;admin
          </span>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close navigation"
            className="inline-flex h-8 w-8 items-center justify-center rounded-md text-slate-500
                       hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800"
          >
            <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden className="h-5 w-5">
              <path d="M5.7 5.7a1 1 0 0 1 1.4 0L10 8.6l2.9-2.9a1 1 0 1 1 1.4 1.4L11.4 10l2.9 2.9a1 1 0 0 1-1.4 1.4L10 11.4l-2.9 2.9a1 1 0 0 1-1.4-1.4L8.6 10 5.7 7.1a1 1 0 0 1 0-1.4Z" />
            </svg>
          </button>
        </div>
        {/* Wrap children to drop the duplicate header inside SidebarContent */}
        <div className="-mt-3">{children}</div>
      </div>
    </div>
  );
}
