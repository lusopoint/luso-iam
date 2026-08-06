import { useEffect, useMemo, useState } from 'react'
import {
  Badge,
  Button,
  Card,
  CodeBlock,
  EmptyState,
  Input,
  Loading,
  PageHeader,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@lusopoint/luso-ui'
import { ChevronLeft, ChevronRight } from 'lucide-react'

import { ErrorState } from '../components/States'
import { ApiError, api } from '../lib/api'
import type { AuditEvent } from '../lib/types'
import { formatDateTime, shortID } from '../lib/util'

const PAGE_SIZE = 50

interface Filters {
  event_type: string
  actor_id: string
  target_id: string
}

const emptyFilters: Filters = { event_type: '', actor_id: '', target_id: '' }

export const statusForEvent = (eventType: string): string => {
  if (eventType.endsWith('_failure')) return 'critical'
  if (eventType.endsWith('_success')) return 'operational'
  if (eventType.startsWith('admin_') || eventType.includes('_deleted'))
    return 'medium'
  return 'pending'
}

const Audit = () => {
  // `active` is what the query is currently using; `draft` is what the
  // form holds before the operator submits. Keeping them separate avoids
  // a fetch on every keystroke.
  const [active, setActive] = useState<Filters>(emptyFilters)
  const [draft, setDraft] = useState<Filters>(emptyFilters)

  const [offset, setOffset] = useState(0)
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    const ctrl = new AbortController()
    setLoading(true)
    api
      .listAudit(
        {
          event_type: active.event_type || undefined,
          actor_id: active.actor_id || undefined,
          target_id: active.target_id || undefined,
          limit: PAGE_SIZE,
          offset,
        },
        ctrl.signal,
      )
      .then(res => {
        setEvents(res.events)
        setTotal(res.total)
        setError(null)
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
  }, [active, offset])

  const applyFilters = () => {
    setOffset(0)
    setActive(draft)
  }
  const clearFilters = () => {
    setDraft(emptyFilters)
    setActive(emptyFilters)
    setOffset(0)
  }

  const pageMeta = useMemo(() => {
    const start = total === 0 ? 0 : offset + 1
    const end = Math.min(offset + PAGE_SIZE, total)
    return { start, end }
  }, [offset, total])

  const onEnter = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      applyFilters()
    }
  }

  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="Append-only history of security-relevant events."
      />

      <Card noHover variant="low" className="mb-6 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[10rem] flex-1">
            <Input
              label="Event type"
              placeholder="login_success"
              value={draft.event_type}
              onChange={e => setDraft({ ...draft, event_type: e.target.value })}
              onKeyDown={onEnter}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="min-w-[10rem] flex-1">
            <Input
              label="Actor ID"
              placeholder="uuid"
              value={draft.actor_id}
              onChange={e => setDraft({ ...draft, actor_id: e.target.value })}
              onKeyDown={onEnter}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="min-w-[10rem] flex-1">
            <Input
              label="Target ID"
              placeholder="uuid"
              value={draft.target_id}
              onChange={e => setDraft({ ...draft, target_id: e.target.value })}
              onKeyDown={onEnter}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={applyFilters} className="h-12">
              Apply
            </Button>
            <Button variant="ghost" onClick={clearFilters} className="h-12">
              Clear
            </Button>
          </div>
        </div>
      </Card>

      {loading ? (
        <Loading label="Loading events…" />
      ) : error ? (
        <ErrorState error={error} />
      ) : events.length === 0 ? (
        <EmptyState
          title="No events match"
          description="Try widening the filters or clearing them entirely."
        />
      ) : (
        <>
          <Card noHover className="overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Event</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map(e => {
                  const isOpen = expanded === e.id
                  return (
                    <Row
                      key={e.id}
                      event={e}
                      open={isOpen}
                      onToggle={() => setExpanded(isOpen ? null : e.id)}
                    />
                  )
                })}
              </TableBody>
            </Table>
          </Card>

          {/* Pagination footer. We avoid jumping pages, Prev/Next is plenty
              for an audit log, and "page N of M" would race against new
              events being inserted at the head. */}
          <div className="mt-6 flex items-center justify-between">
            <span className="text-xs font-bold uppercase tracking-widest text-on-surface-variant">
              Showing {pageMeta.start}–{pageMeta.end} of {total}
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                className="gap-1"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                <ChevronLeft size={14} />
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="gap-1"
                disabled={offset + PAGE_SIZE >= total}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                Next
                <ChevronRight size={14} />
              </Button>
            </div>
          </div>
        </>
      )}
    </>
  )
}

const Row = ({
  event,
  open,
  onToggle,
}: {
  event: AuditEvent
  open: boolean
  onToggle: () => void
}) => {
  return (
    <>
      <TableRow className="cursor-pointer" onClick={onToggle}>
        <TableCell>
          <Badge
            status={statusForEvent(event.event_type)}
            label={event.event_type}
          />
        </TableCell>
        <TableCell>
          {event.actor_id ? (
            <span className="font-mono text-xs">{shortID(event.actor_id)}</span>
          ) : (
            <Dash />
          )}
        </TableCell>
        <TableCell>
          {event.target_id ? (
            <span className="font-mono text-xs">
              {shortID(event.target_id)}
            </span>
          ) : (
            <Dash />
          )}
        </TableCell>
        <TableCell>{event.ip_address || <Dash />}</TableCell>
        <TableCell className="whitespace-nowrap">
          {formatDateTime(event.created_at)}
        </TableCell>
      </TableRow>
      {open && (
        <TableRow className="bg-surface-container-low">
          <TableCell colSpan={5}>
            <Detail event={event} />
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

const Dash = () => <span className="text-on-surface-variant/40">-</span>

const Detail = ({ event }: { event: AuditEvent }) => {
  const hasMeta = Object.keys(event.metadata || {}).length > 0

  return (
    <div className="space-y-4 py-2">
      <div className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
        <DetailLine
          label="Event ID"
          value={<code className="font-mono text-xs">{event.id}</code>}
        />
        <DetailLine label="Created" value={formatDateTime(event.created_at)} />
        {event.actor_id && (
          <DetailLine
            label="Actor"
            value={<code className="font-mono text-xs">{event.actor_id}</code>}
          />
        )}
        {event.target_id && (
          <DetailLine
            label="Target"
            value={<code className="font-mono text-xs">{event.target_id}</code>}
          />
        )}
        {event.user_agent && (
          <DetailLine
            label="User-Agent"
            value={event.user_agent}
            className="sm:col-span-2"
          />
        )}
      </div>

      {/* The metadata blob is event-type-specific. Pretty-print it on expand so
          the operator can read it without learning each type's shape. */}
      {hasMeta && (
        <CodeBlock
          title="Metadata"
          value={JSON.stringify(event.metadata, null, 2)}
          maxHeight={256}
        />
      )}
    </div>
  )
}

const DetailLine = ({
  label,
  value,
  className,
}: {
  label: string
  value: React.ReactNode
  className?: string
}) => (
  <div className={className}>
    <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant">
      {label}
    </span>
    <div className="mt-0.5 text-sm text-on-surface">{value}</div>
  </div>
)

export default Audit
