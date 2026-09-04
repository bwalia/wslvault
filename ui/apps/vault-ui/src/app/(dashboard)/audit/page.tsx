'use client'
import { useState } from 'react'
import useSWR from 'swr'
import { useFetcher } from '@/hooks/useVaultSWR'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { EmptyState } from '@/components/ui/EmptyState'
import { Button } from '@/components/ui/Button'
import { Activity, X } from 'lucide-react'
import { formatDateTime, formatRelativeTime } from '@/lib/utils'
import { cn } from '@/lib/utils'

interface AuditEvent {
  event_id: string
  action: string
  resource: string
  principal: string
  outcome: string
  timestamp: string
  metadata?: Record<string, string>
  ip_address?: string
  user_agent?: string
}

interface AuditResponse {
  events?: AuditEvent[]
  total?: number
}

function buildUrl(params: { action: string; principal: string; from: string; to: string }) {
  const q = new URLSearchParams({ limit: '100' })
  if (params.action) q.set('action', params.action)
  if (params.principal) q.set('principal', params.principal)
  if (params.from) q.set('from', params.from)
  if (params.to) q.set('to', params.to)
  return `/api/audit/v1/audit/events?${q.toString()}`
}

const filterInputClass =
  'w-full px-3 py-1.5 text-sm rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500 transition-colors'

export default function AuditPage() {
  const fetcher = useFetcher()

  const [filters, setFilters] = useState({ action: '', principal: '', from: '', to: '' })
  const [applied, setApplied] = useState({ action: '', principal: '', from: '', to: '' })
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)

  const { data, isLoading } = useSWR<AuditResponse>(buildUrl(applied), fetcher)
  const events = data?.events ?? []

  const applyFilters = () => setApplied({ ...filters })
  const clearFilters = () => {
    setFilters({ action: '', principal: '', from: '', to: '' })
    setApplied({ action: '', principal: '', from: '', to: '' })
  }

  const hasFilters = Object.values(applied).some(Boolean)

  const columns: Column<AuditEvent>[] = [
    {
      field: 'action',
      label: 'Action',
      sortable: true,
      render: row => (
        <span className="font-mono text-sm text-ink">{row.action}</span>
      ),
    },
    {
      field: 'principal',
      label: 'Principal',
      sortable: true,
      render: row => (
        <span className="font-mono text-sm text-ink-muted">{row.principal ?? '—'}</span>
      ),
    },
    {
      field: 'resource',
      label: 'Resource',
      render: row => (
        <span className="font-mono text-sm text-ink-muted truncate max-w-xs block">
          {row.resource}
        </span>
      ),
    },
    {
      field: 'outcome',
      label: 'Outcome',
      render: row => <StatusBadge status={row.outcome} />,
    },
    {
      field: 'timestamp',
      label: 'Time',
      sortable: true,
      render: row => (
        <span
          className="font-mono text-sm tabular text-ink-faint"
          title={formatDateTime(row.timestamp)}
        >
          {formatRelativeTime(row.timestamp)}
        </span>
      ),
    },
  ]

  return (
    <div className="flex gap-6 max-w-7xl">
      <div className="flex-1 min-w-0 space-y-4">
        <PageHeader
          title="Audit Log"
          description="Forensic event history across all services and principals"
        guide={
          <>
            <p>
              Every read, write and sign-in is recorded here — who did it, what
              they touched, and whether it succeeded.
            </p>
            <p>
              The records are chained together cryptographically, so an entry
              cannot be quietly altered or removed after the fact. If one were,
              the chain would no longer verify.
            </p>
          </>
        }
      />

        {/* Filter bar — single row above the table */}
        <div className="flex flex-wrap items-end gap-3 px-4 py-3 bg-surface rounded-xl border border-line">
          <div className="flex-1 min-w-32">
            <label
              htmlFor="filter-action"
              className="block text-xs font-medium text-ink-muted mb-1"
            >
              Action
            </label>
            <input
              id="filter-action"
              value={filters.action}
              onChange={e => setFilters(f => ({ ...f, action: e.target.value }))}
              onKeyDown={e => e.key === 'Enter' && applyFilters()}
              placeholder="e.g. secret.read"
              className={filterInputClass}
            />
          </div>
          <div className="flex-1 min-w-32">
            <label
              htmlFor="filter-principal"
              className="block text-xs font-medium text-ink-muted mb-1"
            >
              Principal
            </label>
            <input
              id="filter-principal"
              value={filters.principal}
              onChange={e => setFilters(f => ({ ...f, principal: e.target.value }))}
              onKeyDown={e => e.key === 'Enter' && applyFilters()}
              placeholder="user or key ID"
              className={filterInputClass}
            />
          </div>
          <div>
            <label
              htmlFor="filter-from"
              className="block text-xs font-medium text-ink-muted mb-1"
            >
              From
            </label>
            <input
              id="filter-from"
              type="datetime-local"
              value={filters.from}
              onChange={e => setFilters(f => ({ ...f, from: e.target.value }))}
              className={cn(filterInputClass, 'w-auto')}
            />
          </div>
          <div>
            <label
              htmlFor="filter-to"
              className="block text-xs font-medium text-ink-muted mb-1"
            >
              To
            </label>
            <input
              id="filter-to"
              type="datetime-local"
              value={filters.to}
              onChange={e => setFilters(f => ({ ...f, to: e.target.value }))}
              className={cn(filterInputClass, 'w-auto')}
            />
          </div>
          <div className="flex items-center gap-2 pb-px">
            <Button size="sm" onClick={applyFilters}>Apply</Button>
            {hasFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters} aria-label="Clear filters">
                <X className="w-4 h-4" aria-hidden="true" /> Clear
              </Button>
            )}
          </div>
        </div>

        {events.length === 0 && !isLoading ? (
          <EmptyState
            icon={Activity}
            title="No audit events found"
            description={
              hasFilters
                ? 'No events match the current filters. Try broadening the time range or clearing a filter.'
                : 'Audit events will appear here as actions are performed across services.'
            }
            action={
              hasFilters ? (
                <Button variant="secondary" size="sm" onClick={clearFilters}>
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        ) : (
          <DataTable
            columns={columns}
            data={(events as unknown as Record<string, unknown>[]) ?? []}
            loading={isLoading}
            keyField="event_id"
            onRowClick={row => setSelectedEvent(row as unknown as AuditEvent)}
          />
        )}
      </div>

      {/* Event detail drawer */}
      {selectedEvent && (
        <div className="w-80 shrink-0">
          <Card className="sticky top-6">
            <CardHeader>
              <CardTitle>Event Detail</CardTitle>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1.5 rounded-md text-ink-faint hover:text-ink hover:bg-surface-2 transition-colors focus-ring"
                aria-label="Close event detail"
              >
                <X className="w-4 h-4" aria-hidden="true" />
              </button>
            </CardHeader>
            <CardBody>
              <dl className="space-y-3">
                <DetailRow label="Event ID" value={selectedEvent.event_id} mono />
                <DetailRow label="Action" value={selectedEvent.action} mono />
                <DetailRow label="Resource" value={selectedEvent.resource} mono />
                <DetailRow label="Principal" value={selectedEvent.principal ?? '—'} mono />
                <DetailRow label="Outcome">
                  <StatusBadge status={selectedEvent.outcome} />
                </DetailRow>
                <DetailRow
                  label="Time"
                  value={formatDateTime(selectedEvent.timestamp)}
                  mono
                />
                {selectedEvent.ip_address && (
                  <DetailRow label="IP Address" value={selectedEvent.ip_address} mono />
                )}
                {selectedEvent.user_agent && (
                  <DetailRow label="User Agent" value={selectedEvent.user_agent} mono />
                )}
                {selectedEvent.metadata &&
                  Object.keys(selectedEvent.metadata).length > 0 && (
                    <div>
                      <dt className="text-xs uppercase tracking-wide text-ink-faint mb-1.5">
                        Metadata
                      </dt>
                      <dd>
                        <pre className="font-mono text-xs text-ink bg-surface-2 border border-line rounded-lg p-3 overflow-auto max-h-48 whitespace-pre-wrap break-all">
                          {JSON.stringify(selectedEvent.metadata, null, 2)}
                        </pre>
                      </dd>
                    </div>
                  )}
              </dl>
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  )
}

function DetailRow({
  label,
  value,
  mono,
  children,
}: {
  label: string
  value?: string
  mono?: boolean
  children?: React.ReactNode
}) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-ink-faint mb-0.5">{label}</dt>
      <dd>
        {children ?? (
          <span
            className={cn(
              'text-sm text-ink break-all',
              mono && 'font-mono',
            )}
          >
            {value}
          </span>
        )}
      </dd>
    </div>
  )
}
