import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Badge,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  EmptyState,
  Loading,
  PageHeader,
  StatsCard,
} from '@lusopoint/luso-ui'
import {
  ArrowRight,
  Boxes,
  ShieldCheck,
  Users as UsersIcon,
} from 'lucide-react'

import { ErrorState } from '../components/States'
import { ApiError, api } from '../lib/api'
import type { AuditEvent } from '../lib/types'
import { relativeTime } from '../lib/util'

interface Counters {
  users?: number
  clients?: number
  services?: number
}

const Dashboard = () => {
  const [counters, setCounters] = useState<Counters>({})
  const [recent, setRecent] = useState<AuditEvent[]>([])
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const ctrl = new AbortController()
    // Issue all four queries in parallel; settle them together so the
    // page doesn't reflow as each one arrives.
    Promise.all([
      api.listUsers({ limit: 1 }, ctrl.signal),
      api.listClients(ctrl.signal),
      api.listCASServices(ctrl.signal),
      api.listAudit({ limit: 10 }, ctrl.signal),
    ])
      .then(([u, c, s, a]) => {
        setCounters({
          users: u.total,
          clients: c.clients.length,
          services: s.services.length,
        })
        setRecent(a.events)
        setLoading(false)
      })
      .catch(err => {
        if (ctrl.signal.aborted) return
        setError(
          err instanceof ApiError
            ? err
            : new ApiError({
                type: 'about:blank',
                title: 'Error',
                status: 0,
                detail: String(err),
              }),
        )
        setLoading(false)
      })
    return () => ctrl.abort()
  }, [])

  if (loading) return <Loading label="Loading overview…" />
  if (error) return <ErrorState error={error} />

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle="At-a-glance view of the IAM environment."
      />

      {/* StatsCard isn't a link, so each one is wrapped. The wrapper carries
          the focus ring the card handles its own hover treatment */}
      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <CounterLink to="/users">
          <StatsCard
            title="Users"
            value={counters.users ?? 0}
            icon={<UsersIcon size={18} />}
          />
        </CounterLink>
        <CounterLink to="/clients">
          <StatsCard
            title="OIDC clients"
            value={counters.clients ?? 0}
            icon={<Boxes size={18} />}
          />
        </CounterLink>
        <CounterLink to="/cas-services">
          <StatsCard
            title="CAS services"
            value={counters.services ?? 0}
            icon={<ShieldCheck size={18} />}
          />
        </CounterLink>
      </div>

      <Card noHover>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle>Recent events</CardTitle>
          <Link
            to="/audit"
            className="inline-flex items-center gap-1 text-xs font-bold uppercase tracking-widest text-primary transition-opacity hover:opacity-70"
          >
            View all
            <ArrowRight size={14} />
          </Link>
        </CardHeader>

        <CardContent>
          {recent.length === 0 ? (
            <EmptyState
              title="No events yet"
              description="Security-relevant activity sign-ins, token issuance, admin changes will appear here as it happens."
            />
          ) : (
            <ul className="divide-y divide-border">
              {recent.map(e => (
                <li
                  key={e.id}
                  className="flex items-center justify-between gap-3 py-3 text-sm"
                >
                  <Badge
                    status={statusFor(e.event_type)}
                    label={e.event_type}
                  />
                  <span className="shrink-0 text-xs font-medium text-on-surface-variant">
                    {relativeTime(e.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </>
  )
}

// map an audit event type onto a Badge status so failures read red at a glance
// Badge accepts an arbitrary string and falls back to a neutral
// treatment, so unknown event types are safe
const statusFor = (eventType: string): string => {
  if (eventType.endsWith('_failure')) return 'critical'
  if (eventType.endsWith('_success')) return 'operational'
  if (eventType.startsWith('admin_') || eventType.includes('_deleted'))
    return 'medium'
  return 'pending'
}

const CounterLink = ({
  to,
  children,
}: {
  to: string
  children: React.ReactNode
}) => (
  <Link
    to={to}
    className="rounded-2xl outline-none focus-visible:ring-1 focus-visible:ring-primary"
  >
    {children}
  </Link>
)

export default Dashboard
