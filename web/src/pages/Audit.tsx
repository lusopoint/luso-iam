import { useEffect, useMemo, useState } from "react";

import PageHeader from "../components/PageHeader";
import { EmptyState, ErrorState, Loading } from "../components/States";
import { ApiError, api } from "../lib/api";
import type { AuditEvent } from "../lib/types";
import { formatDateTime, shortID } from "../lib/util";

/*
 * Audit: paginated, filterable view of the audit_log. The filter inputs
 * commit on submit, not on every keystroke — audit_log reads are cheap
 * but we don't want to re-issue queries while someone is mid-typing an
 * actor UUID.
 *
 * The result table favours scannability: event type prominent, timestamp
 * to the right, expandable metadata row beneath each event.
 */

const PAGE_SIZE = 50;

interface Filters {
  event_type: string;
  actor_id: string;
  target_id: string;
}

const emptyFilters: Filters = { event_type: "", actor_id: "", target_id: "" };

export default function Audit() {
  // `active` is what the query is currently using; `draft` is what the
  // form holds before the operator submits. Keeping them separate avoids
  // a fetch on every keystroke.
  const [active, setActive] = useState<Filters>(emptyFilters);
  const [draft, setDraft] = useState<Filters>(emptyFilters);

  const [offset, setOffset] = useState(0);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
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
      .then((res) => {
        setEvents(res.events);
        setTotal(res.total);
        setError(null);
        setLoading(false);
      })
      .catch((err) => {
        if (ctrl.signal.aborted) return;
        setError(
          err instanceof ApiError
            ? err
            : new ApiError({ type: "about:blank", title: "Error", status: 0, detail: String(err) }),
        );
        setLoading(false);
      });
    return () => ctrl.abort();
  }, [active, offset]);

  function applyFilters(e: React.FormEvent) {
    e.preventDefault();
    setOffset(0);
    setActive(draft);
  }
  function clearFilters() {
    setDraft(emptyFilters);
    setActive(emptyFilters);
    setOffset(0);
  }

  const pageMeta = useMemo(() => {
    const start = total === 0 ? 0 : offset + 1;
    const end = Math.min(offset + PAGE_SIZE, total);
    return { start, end };
  }, [offset, total]);

  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="Append-only history of security-relevant events."
      />

      <form
        onSubmit={applyFilters}
        className="card mb-4 flex flex-wrap items-end gap-3 p-3"
      >
        <Field
          label="Event type"
          placeholder="login_success"
          value={draft.event_type}
          onChange={(v) => setDraft({ ...draft, event_type: v })}
        />
        <Field
          label="Actor ID"
          placeholder="uuid"
          value={draft.actor_id}
          onChange={(v) => setDraft({ ...draft, actor_id: v })}
        />
        <Field
          label="Target ID"
          placeholder="uuid"
          value={draft.target_id}
          onChange={(v) => setDraft({ ...draft, target_id: v })}
        />
        <div className="flex gap-2">
          <button type="submit" className="btn-primary">Apply</button>
          <button type="button" className="btn-secondary" onClick={clearFilters}>
            Clear
          </button>
        </div>
      </form>

      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} />
      ) : events.length === 0 ? (
        <EmptyState
          title="No events match"
          description="Try widening the filters or clearing them entirely."
        />
      ) : (
        <>
          <div className="card overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50 dark:bg-slate-900/40">
                <tr>
                  <th className="table-th">Event</th>
                  <th className="table-th">Actor</th>
                  <th className="table-th">Target</th>
                  <th className="table-th">IP</th>
                  <th className="table-th">When</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => {
                  const isOpen = expanded === e.id;
                  return (
                    <Row
                      key={e.id}
                      event={e}
                      open={isOpen}
                      onToggle={() => setExpanded(isOpen ? null : e.id)}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination footer. We avoid jumping pages — Prev/Next is plenty
              for an audit log, and "page N of M" would race against new
              events being inserted at the head. */}
          <div className="mt-3 flex items-center justify-between text-sm text-slate-500 dark:text-slate-400">
            <span>
              Showing {pageMeta.start}–{pageMeta.end} of {total}
            </span>
            <div className="flex gap-2">
              <button
                className="btn-secondary"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                ← Prev
              </button>
              <button
                className="btn-secondary"
                disabled={offset + PAGE_SIZE >= total}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                Next →
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );
}

function Field({
  label,
  placeholder,
  value,
  onChange,
}: {
  label: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <label className="flex-1 min-w-[10rem]">
      <span className="label">{label}</span>
      <input
        className="input"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="off"
        spellCheck={false}
      />
    </label>
  );
}

function Row({
  event,
  open,
  onToggle,
}: {
  event: AuditEvent;
  open: boolean;
  onToggle: () => void;
}) {
  // The metadata blob is event-type-specific. Pretty-print it on expand so
  // the operator can read it without learning each type's shape.
  return (
    <>
      <tr
        className="table-row cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/40"
        onClick={onToggle}
      >
        <td className="table-td">
          <span className="font-mono text-xs">{event.event_type}</span>
        </td>
        <td className="table-td">
          {event.actor_id ? (
            <span className="font-mono text-xs">{shortID(event.actor_id)}</span>
          ) : (
            <span className="text-slate-400">—</span>
          )}
        </td>
        <td className="table-td">
          {event.target_id ? (
            <span className="font-mono text-xs">{shortID(event.target_id)}</span>
          ) : (
            <span className="text-slate-400">—</span>
          )}
        </td>
        <td className="table-td">
          {event.ip_address || <span className="text-slate-400">—</span>}
        </td>
        <td className="table-td whitespace-nowrap">
          {formatDateTime(event.created_at)}
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50/50 dark:bg-slate-900/30">
          <td colSpan={5} className="px-4 py-3">
            <Detail event={event} />
          </td>
        </tr>
      )}
    </>
  );
}

function Detail({ event }: { event: AuditEvent }) {
  const hasMeta = Object.keys(event.metadata || {}).length > 0;
  return (
    <div className="space-y-2 text-sm">
      <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
        <DetailLine label="Event ID" value={<code className="font-mono text-xs">{event.id}</code>} />
        <DetailLine label="Created" value={formatDateTime(event.created_at)} />
        {event.actor_id && (
          <DetailLine label="Actor" value={<code className="font-mono text-xs">{event.actor_id}</code>} />
        )}
        {event.target_id && (
          <DetailLine label="Target" value={<code className="font-mono text-xs">{event.target_id}</code>} />
        )}
        {event.user_agent && (
          <DetailLine label="User-Agent" value={event.user_agent} className="sm:col-span-2" />
        )}
      </div>
      {hasMeta && (
        <details open className="mt-2">
          <summary className="cursor-pointer text-xs font-medium text-slate-600 dark:text-slate-300">
            Metadata
          </summary>
          <pre className="mt-1 max-h-64 overflow-auto rounded bg-slate-100 p-2 font-mono text-xs text-slate-800 dark:bg-slate-800 dark:text-slate-200">
            {JSON.stringify(event.metadata, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}

function DetailLine({
  label,
  value,
  className,
}: {
  label: string;
  value: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={className}>
      <span className="text-xs text-slate-500 dark:text-slate-400">{label}: </span>
      <span className="text-slate-800 dark:text-slate-200">{value}</span>
    </div>
  );
}
