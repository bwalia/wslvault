'use client'
import { useState } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
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
  const color =
    pct > 50 ? 'bg-accent-500' : pct > 20 ? 'bg-warn-500' : 'bg-danger-500'

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
        <div className={cn('h-full rounded-full transition-all', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-slate-500 w-16 text-right">
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
    { field: 'secret_path', label: 'Secret Path', sortable: true, render: row => <span className="font-mono text-xs">{row.secret_path}</span> },
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
      render: row => <span className="text-xs text-slate-500">{formatDateTime(row.created_at)}</span>,
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
              onClick={e => { e.stopPropagation(); onRenew(row) }}
            >
              <RefreshCw className="w-4 h-4" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={e => { e.stopPropagation(); setRevokeTarget(row) }}
            className="text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-900/20"
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
        icon={Key}
      />

      {/* State filter tabs */}
      <div className="border-b border-slate-200 dark:border-slate-800 mb-6">
        <nav className="flex gap-1 -mb-px">
          {tabs.map(tab => (
            <button
              key={tab.value}
              onClick={() => setStateFilter(tab.value)}
              className={cn(
                'px-4 py-2.5 text-sm font-medium border-b-2 transition-colors',
                stateFilter === tab.value
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200',
              )}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      <DataTable
        columns={columns}
        data={(filtered as unknown as Record<string, unknown>[]) ?? []}
        loading={isLoading}
        keyField="id"
      />

      <ConfirmModal
        open={!!revokeTarget}
        onClose={() => setRevokeTarget(null)}
        onConfirm={onRevoke}
        title="Revoke Lease"
        description={`Revoke lease for "${revokeTarget?.secret_path}"? The associated credentials will be immediately invalidated.`}
        confirmLabel="Revoke"
        loading={revoking}
      />
    </div>
  )
}
