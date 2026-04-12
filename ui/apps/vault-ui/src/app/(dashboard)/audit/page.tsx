'use client'
import { useState } from 'react'
import useSWR from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Card, CardHeader, CardBody } from '@/components/ui/Card'
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

export default function AuditPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)

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
      render: row => <span className="font-mono text-xs">{row.action}</span>,
    },
    {
      field: 'principal',
      label: 'Principal',
      sortable: true,
      render: row => <span className="text-xs text-slate-500">{row.principal ?? '—'}</span>,
    },
    {
      field: 'resource',
      label: 'Resource',
      render: row => (
        <span className="text-xs text-slate-600 dark:text-slate-400 truncate max-w-xs block">
          {row.resource}
        </span>
      ),
    },
    { field: 'outcome', label: 'Outcome', render: row => <StatusBadge status={row.outcome} /> },
    {
      field: 'timestamp',
      label: 'Time',
      sortable: true,
      render: row => (
        <span className="text-xs text-slate-500" title={formatDateTime(row.timestamp)}>
          {formatRelativeTime(row.timestamp)}
        </span>
      ),
    },
  ]

  return (
    <div className="flex gap-6">
      <div className="flex-1 min-w-0">
        <PageHeader title="Audit Log" description="Event history across all services" icon={Activity} />

        {/* Filter bar */}
        <div className="flex flex-wrap items-end gap-3 mb-4 p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800">
          <div className="flex-1 min-w-36">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
              Action
            </label>
            <input
              value={filters.action}
              onChange={e => setFilters(f => ({ ...f, action: e.target.value }))}
              placeholder="e.g. secret.read"
              className="w-full px-3 py-1.5 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
            />
          </div>
          <div className="flex-1 min-w-36">
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
              Principal
            </label>
            <input
              value={filters.principal}
              onChange={e => setFilters(f => ({ ...f, principal: e.target.value }))}
              placeholder="user or key ID"
              className="w-full px-3 py-1.5 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
              From
            </label>
            <input
              type="datetime-local"
              value={filters.from}
              onChange={e => setFilters(f => ({ ...f, from: e.target.value }))}
              className="px-3 py-1.5 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
              To
            </label>
            <input
              type="datetime-local"
              value={filters.to}
              onChange={e => setFilters(f => ({ ...f, to: e.target.value }))}
              className="px-3 py-1.5 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
            />
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={applyFilters}>Apply</Button>
            {hasFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="w-4 h-4" /> Clear
              </Button>
            )}
          </div>
        </div>

        <DataTable
          columns={columns}
          data={(events as unknown as Record<string, unknown>[]) ?? []}
          loading={isLoading}
          keyField="event_id"
          onRowClick={row => setSelectedEvent(row as unknown as AuditEvent)}
        />
      </div>

      {/* Detail drawer */}
      {selectedEvent && (
        <div className="w-80 flex-shrink-0">
          <Card className="sticky top-6">
            <CardHeader>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                  Event Detail
                </h3>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1 rounded text-slate-400 hover:text-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </CardHeader>
            <CardBody className="space-y-3 text-sm">
              <DetailRow label="Event ID" value={selectedEvent.event_id} mono />
              <DetailRow label="Action" value={selectedEvent.action} mono />
              <DetailRow label="Resource" value={selectedEvent.resource} mono />
              <DetailRow label="Principal" value={selectedEvent.principal ?? '—'} />
              <DetailRow label="Outcome">
                <StatusBadge status={selectedEvent.outcome} />
              </DetailRow>
              <DetailRow label="Time" value={formatDateTime(selectedEvent.timestamp)} />
              {selectedEvent.ip_address && (
                <DetailRow label="IP" value={selectedEvent.ip_address} mono />
              )}
              {selectedEvent.metadata && Object.keys(selectedEvent.metadata).length > 0 && (
                <div>
                  <p className="text-xs font-medium text-slate-500 mb-1">Metadata</p>
                  <pre className="text-xs font-mono bg-slate-50 dark:bg-slate-800 rounded-lg p-2 overflow-auto max-h-40">
                    {JSON.stringify(selectedEvent.metadata, null, 2)}
                  </pre>
                </div>
              )}
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
      <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-0.5">{label}</p>
      {children ?? (
        <p className={cn('text-xs text-slate-800 dark:text-slate-200 break-all', mono && 'font-mono')}>
          {value}
        </p>
      )}
    </div>
  )
}
