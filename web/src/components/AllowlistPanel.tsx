import { useEffect, useRef, useState } from 'react'
import type { ChangeEvent } from 'react'
import {
  Alert,
  Button,
  EmptyState,
  Loading,
  TagInput,
  useConfirm,
  useToast,
} from '@lusopoint/luso-ui'
import { Upload, X } from 'lucide-react'

import { ApiError, api } from '../lib/api.ts'
import type { AllowlistMutateResponse } from '../lib/types.ts'
import { parseEmailList, validEmail } from '../lib/util.ts'

type Kind = 'client' | 'cas'

// bind the right API trio for the service kind
const listFn = (kind: Kind, id: string, signal?: AbortSignal) =>
  kind === 'client'
    ? api.listClientAllowlist(id, signal)
    : api.listCASServiceAllowlist(id, signal)
const addFn = (kind: Kind, id: string, emails: string[]) =>
  kind === 'client'
    ? api.addClientAllowlist(id, emails)
    : api.addCASServiceAllowlist(id, emails)
const delFn = (kind: Kind, id: string, emails: string[]) =>
  kind === 'client'
    ? api.deleteClientAllowlist(id, emails)
    : api.deleteCASServiceAllowlist(id, emails)

// manages the per service email allow list
// we use the dedicated allowed list endpoint manage the data
export const AllowlistPanel = ({
  kind,
  id,
  enforced,
}: {
  kind: Kind
  id: string
  enforced: boolean
}) => {
  const toast = useToast()
  const confirm = useConfirm()
  const fileRef = useRef<HTMLInputElement>(null)

  const [entries, setEntries] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [staged, setStaged] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const ctrl = new AbortController()
    setLoading(true)
    listFn(kind, id, ctrl.signal)
      .then(r => {
        setEntries(r.entries.map(e => e.email))
        setError(null)
      })
      .catch(e => {
        if (ctrl.signal.aborted) return
        setError(e instanceof ApiError ? e.message : String(e))
      })
      .finally(() => {
        if (!ctrl.signal.aborted) setLoading(false)
      })
    return () => ctrl.abort()
  }, [kind, id])

  const reportMutation = (r: AllowlistMutateResponse) => {
    const bits: string[] = []
    if (r.added) bits.push(`${r.added} added`)
    if (r.deleted) bits.push(`${r.deleted} removed`)
    if (r.invalid?.length) bits.push(`${r.invalid.length} invalid skipped`)
    toast.success(
      bits.length ? `${bits.join(', ')}.` : 'No changes.',
      r.invalid?.length ? `Skipped: ${r.invalid.join(', ')}` : undefined,
    )
  }

  const add = async (emails: string[]) => {
    if (emails.length === 0) return
    setBusy(true)
    try {
      const r = await addFn(kind, id, emails)
      setEntries(prev => Array.from(new Set([...prev, ...emails])).sort())
      setStaged([])
      reportMutation(r)
    } catch (e) {
      toast.error(
        'Could not update allow-list.',
        e instanceof ApiError ? e.message : String(e),
      )
    } finally {
      setBusy(false)
    }
  }

  const remove = async (email: string) => {
    setBusy(true)
    try {
      await delFn(kind, id, [email])
      setEntries(prev => prev.filter(x => x !== email))
    } catch (e) {
      toast.error(
        'Could not remove entry.',
        e instanceof ApiError ? e.message : String(e),
      )
    } finally {
      setBusy(false)
    }
  }

  const clearAll = async () => {
    if (entries.length === 0) return
    const ok = await confirm({
      title: 'Remove all entries?',
      message: `This removes all ${entries.length} address(es) from the allow-list.`,
      confirmLabel: 'Remove all',
      danger: true,
    })
    if (!ok) return
    setBusy(true)
    try {
      await delFn(kind, id, entries)
      setEntries([])
      toast.success('Allow-list cleared.')
    } catch (e) {
      toast.error(
        'Could not clear allow-list.',
        e instanceof ApiError ? e.message : String(e),
      )
    } finally {
      setBusy(false)
    }
  }

  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = '' // let the same file be re-selected later
    if (!file) return
    const text = await file.text()
    const parsed = parseEmailList(text)
    if (parsed.length === 0) {
      toast.error('No email addresses found in that file.')
      return
    }
    await add(parsed)
  }

  return (
    <div className="space-y-4">
      {!enforced && (
        <div className="rounded-lg border-l-4 border-error/50 bg-surface-container-lowest px-4 py-3 text-sm text-on-surface-variant">
          Enforcement is off for this service. Turn on{' '}
          <strong className="text-on-surface">Require allow-list</strong> above
          to restrict access to the addresses below. Until then, anyone who can
          authenticate may use it.
        </div>
      )}

      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="flex-1">
          <TagInput
            label="Add addresses"
            value={staged}
            onChange={setStaged}
            placeholder="user@example.com"
            validate={validEmail}
          />
        </div>
        <div className="flex gap-2">
          <Button
            onClick={() => add(staged)}
            disabled={busy || staged.length === 0}
          >
            {busy
              ? 'Saving…'
              : `Add${staged.length ? ` ${staged.length}` : ''}`}
          </Button>
          <Button
            variant="outline"
            className="gap-2"
            disabled={busy}
            onClick={() => fileRef.current?.click()}
          >
            <Upload size={16} />
            Import
          </Button>
          <input
            ref={fileRef}
            type="file"
            accept=".csv,.txt,text/csv,text/plain"
            className="hidden"
            onChange={onFile}
          />
        </div>
      </div>
      <p className="ml-1 -mt-1 text-xs text-on-surface-variant">
        Paste or type addresses (comma/space separated), or import a CSV / text
        file, one address per line. Duplicates and invalid entries are ignored.
      </p>

      {loading && <Loading label="Loading allow-list…" />}
      {error && <Alert variant="error">{error}</Alert>}

      {!loading && !error && (
        <>
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-on-surface-variant">
              {entries.length} address{entries.length === 1 ? '' : 'es'}
            </span>
            {entries.length > 0 && (
              <Button
                variant="ghost"
                size="sm"
                disabled={busy}
                onClick={clearAll}
                className="text-error hover:bg-error/10"
              >
                Remove all
              </Button>
            )}
          </div>

          {entries.length === 0 ? (
            <EmptyState
              title="No addresses yet."
              description="Add or import the emails permitted to use this service."
            />
          ) : (
            <ul className="flex flex-wrap gap-2">
              {entries.map(email => (
                <li
                  key={email}
                  className="flex items-center gap-2 rounded-lg bg-surface-container-lowest py-1.5 pl-3 pr-1.5 font-mono text-xs text-on-surface"
                >
                  <span className="break-all">{email}</span>
                  <button
                    type="button"
                    aria-label={`Remove ${email}`}
                    disabled={busy}
                    onClick={() => remove(email)}
                    className="rounded p-0.5 text-on-surface-variant hover:bg-error/10 hover:text-error disabled:opacity-40"
                  >
                    <X size={14} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  )
}
