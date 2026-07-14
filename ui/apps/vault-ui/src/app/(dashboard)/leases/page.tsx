'use client'
import { useState } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { EmptyState } from '@/components/ui/EmptyState'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Button } from '@/components/ui/Button'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { Key, RefreshCw, XCircle } from 'lucide-react'
import { formatDateTime, getRemainingSeconds, formatDuration } from '@/lib/utils'
import { cn } from '@/lib/utils'

interface Lease {
  id: string
  secret_path: string
  state: string
  ttl: number
  expires_at: string
  renewable: boolean
  created_at: string
}

type StateFilter = 'all' | 'active' | 'renewing' | 'expired' | 'revoked'

const LEASES_KEY = '/api/lease/v1/leases'

function TTLBar({ expiresAt }: { expiresAt: string }) {
  const remaining = getRemainingSeconds(expiresAt)
  // Estimate total from when remaining could be 0–24h; show progress as % of 24h
  const total = 24 * 3600
  const pct = Math.min(100, Math.round((remaining / total) * 100))
  // Use functional colors: healthy → primary, warning → warn, critical → danger
  const fillColor =
    pct > 50 ? 'bg-primary-500' : pct > 20 ? 'bg-warn-500' : 'bg-danger-500'

  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-1.5 rounded-full bg-surface-3 overflow-hidden">
        <div
          className={cn('h-full rounded-full transition-colors', fillColor)}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[13px] font-mono tabular text-ink-muted w-16 text-right flex-shrink-0">
        {remaining > 0 ? formatDuration(remaining) : 'Expired'}
      </span>
    </div>
  )
}

export default function LeasesPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)
  const [stateFilter, setStateFilter] = useState<StateFilter>('all')

  const { data: leasesData, isLoading } = useSWR<{ leases: Lease[] }>(LEASES_KEY, fetcher)
  const leases = leasesData?.leases ?? []

  const filtered =
    stateFilter === 'all' ? leases : leases.filter(l => l.state === stateFilter)

  const [revokeTarget, setRevokeTarget] = useState<Lease | null>(null)
  const [revoking, setRevoking] = useState(false)
  const [renewingId, setRenewingId] = useState<string | null>(null)

  const onRenew = async (lease: Lease) => {
    setRenewingId(lease.id)
    try {
      await mutate(`${LEASES_KEY}/${lease.id}/renew`, 'POST', {}, token, tenantId)
      await swrMutate(LEASES_KEY)
    } catch {
      // ignore
    } finally {
      setRenewingId(null)
    }
  }

  const onRevoke = async () => {
    if (!revokeTarget) return
    setRevoking(true)
    try {
      await mutate(`${LEASES_KEY}/${revokeTarget.id}/revoke`, 'POST', {}, token, tenantId)
      await swrMutate(LEASES_KEY)
      setRevokeTarget(null)
    } catch {
      // ignore
    } finally {
      setRevoking(false)
    }
  }

  const columns: Column<Lease>[] = [
    {
      field: 'secret_path',
      label: 'Secret Path',
      sortable: true,
      mono: true,
    },
    {
      field: 'id',
      label: 'Lease ID',
      mono: true,
      render: row => (
        <span className="font-mono text-[13px] text-ink-muted">{row.id}</span>
      ),
    },
    { field: 'state', label: 'State', render: row => <StatusBadge status={row.state} /> },
    {
      field: 'expires_at',
      label: 'TTL',
      render: row => <TTLBar expiresAt={row.expires_at} />,
    },
    {
      field: 'created_at',
      label: 'Created',
      sortable: true,
      render: row => <span className="text-xs text-ink-muted">{formatDateTime(row.created_at)}</span>,
    },
    {
      field: '_actions',
      label: '',
      render: row => (
        <div className="flex items-center gap-1">
          {row.renewable && (
            <Button
              variant="ghost"
              size="sm"
              loading={renewingId === row.id}
              aria-label={`Renew lease for ${row.secret_path}`}
              onClick={e => { e.stopPropagation(); onRenew(row) }}
            >
              <RefreshCw className="w-4 h-4" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            aria-label={`Revoke lease for ${row.secret_path}`}
            onClick={e => { e.stopPropagation(); setRevokeTarget(row) }}
            className="text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-600/10"
          >
            <XCircle className="w-4 h-4" />
          </Button>
        </div>
      ),
    },
  ]

  const tabs: { value: StateFilter; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'active', label: 'Active' },
    { value: 'renewing', label: 'Renewing' },
    { value: 'expired', label: 'Expired' },
    { value: 'revoked', label: 'Revoked' },
  ]

  return (
    <div>
      <PageHeader
        title="Leases"
        description="Active secret leases and TTL management"
      />

      {/* State filter — quiet segmented buttons; selected = bg-surface-3 text-ink */}
      <div className="flex items-center gap-1 mb-6 p-1 rounded-lg bg-surface-2 border border-line w-fit">
        {tabs.map(tab => (
          <button
            key={tab.value}
            onClick={() => setStateFilter(tab.value)}
            className={cn(
              'px-3 py-1.5 text-sm font-medium rounded-md transition-colors focus-ring',
              stateFilter === tab.value
                ? 'bg-surface-3 text-ink'
                : 'text-ink-muted hover:text-ink',
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {!isLoading && leases.length === 0 ? (
        <EmptyState
          icon={Key}
          title="No leases yet"
          description="Secret leases will appear here once clients start reading time-bound credentials."
        />
      ) : (
        <DataTable
          columns={columns}
          data={(filtered as unknown as Record<string, unknown>[]) ?? []}
          loading={isLoading}
          keyField="id"
          emptyMessage="No leases match the selected filter."
        />
      )}

      <ConfirmModal
        open={!!revokeTarget}
        onClose={() => setRevokeTarget(null)}
        onConfirm={onRevoke}
        title="Revoke lease"
        description={`Revoke lease for "${revokeTarget?.secret_path}"? The associated credentials will be immediately invalidated.`}
        confirmLabel="Revoke"
        loading={revoking}
      />
    </div>
  )
}
