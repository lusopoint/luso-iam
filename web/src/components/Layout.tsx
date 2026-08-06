import {
  AppShell,
  Badge,
  navItemClass,
  type NavSection,
} from '@lusopoint/luso-ui'
import {
  Boxes,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Network,
  ScrollText,
  ShieldCheck,
  Users as UsersIcon,
} from 'lucide-react'
import { NavLink, Outlet } from 'react-router-dom'

import type { AdminUser } from '../lib/types'

interface LayoutProps {
  me: AdminUser
}

const ICON = { size: 18 } as const

const NAV_SECTIONS: NavSection[] = [
  {
    items: [
      {
        href: '/',
        label: 'Dashboard',
        end: true,
        icon: <LayoutDashboard {...ICON} />,
      },
    ],
  },
  {
    title: 'Identity',
    items: [
      { href: '/users', label: 'Users', icon: <UsersIcon {...ICON} /> },
      { href: '/federation', label: 'Federation', icon: <Network {...ICON} /> },
    ],
  },
  {
    title: 'Applications',
    items: [
      { href: '/clients', label: 'OIDC clients', icon: <Boxes {...ICON} /> },
      {
        href: '/cas-services',
        label: 'CAS services',
        icon: <ShieldCheck {...ICON} />,
      },
    ],
  },
  {
    title: 'Operations',
    items: [
      { href: '/audit', label: 'Audit log', icon: <ScrollText {...ICON} /> },
      { href: '/keys', label: 'Signing keys', icon: <KeyRound {...ICON} /> },
    ],
  },
  {
    title: 'Your account',
    items: [
      // the MFA enrollment pages are server-rendered, not part of the SPA
      // so this one needs a full page navigation, not a client side route
      {
        href: '/mfa/enroll',
        label: 'Security & MFA',
        icon: <ShieldCheck {...ICON} />,
        external: true,
      },
    ],
  },
]

const Layout = ({ me }: LayoutProps) => {
  const label = me.display_name || me.email || me.username || me.id

  return (
    <AppShell
      brand={
        <div className="flex items-center gap-2">
          <ShieldCheck size={22} className="text-primary" />
          <span className="text-sm font-black uppercase tracking-tightest text-on-surface">
            IAM&nbsp;Admin
          </span>
        </div>
      }
      sections={NAV_SECTIONS}
      renderNavItem={(item, { close }) =>
        item.external ? (
          <a href={item.href} onClick={close} className={navItemClass(false)}>
            {item.icon}
            <span className="flex-1 truncate">{item.label}</span>
          </a>
        ) : (
          <NavLink
            to={item.href}
            end={item.end}
            onClick={close}
            className={({ isActive }) => navItemClass(isActive)}
          >
            {item.icon}
            <span className="flex-1 truncate">{item.label}</span>
          </NavLink>
        )
      }
      identity={
        <span className="flex items-center gap-2">
          <span className="hidden sm:inline">Signed in as</span>
          <span className="truncate font-semibold text-on-surface">
            {label}
          </span>
          <Badge status="operational" label="admin" />
        </span>
      }
      actions={
        <a
          href="/cas/logout"
          className="inline-flex h-10 items-center gap-2 rounded-xl px-3 text-sm font-semibold text-on-surface-variant transition-colors hover:bg-surface-container hover:text-on-surface"
        >
          <LogOut size={16} />
          <span className="hidden sm:inline">Sign out</span>
        </a>
      }
    >
      <Outlet />
    </AppShell>
  )
}
export default Layout
