'use client'
import { useState, useCallback } from 'react'
import { mutate as swrMutate } from 'swr'
import { useVaultSWR, useVaultMutate } from '@/hooks/useVaultSWR'
import { useAuth } from '@/contexts/AuthContext'
import { useAsyncAction } from '@/hooks/useAsyncAction'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorBanner, LoadError } from '@/components/ErrorBanner'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Button } from '@/components/ui/Button'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { Key, RefreshCw, XCircle } from 'lucide-react'
import { formatDateTime, getRemainingSeconds, formatDuration } from '@/lib/utils'
import { cn } from '@/lib/utils'

interface Lease {
  id: string
  tenant_id: string
  target_type: string
  target_label: string
  state: string
  ttl_seconds: number
  max_ttl_seconds: number
  renewable: boolean
  issued_at: string
  expires_at: string
  revoked_at: string | null
  remaining_seconds: number
}

type StateFilter = 'all' | 'active' | 'expired' | 'revoked'

const LEASES_KEY = '/api/lease/v1/leases'

function TTLBar({ expiresAt, ttlSeconds }: { expiresAt: string; ttlSeconds: number }) {
  const remaining = getRemainingSeconds(expiresAt)
  const total = Math.max(ttlSeconds, 1)
  const pct = Math.min(100, Math.round((remaining / total) * 100))
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
      <span className="text-[13px] font-mono tabular text-ink-muted w-16 text-right shrink-0">
        {remaining > 0 ? formatDuration(remaining) : 'Expired'}
      </span>
    </div>
  )
}

export default function LeasesPage() {
  const { leaseId, logout } = useAuth()
  const vaultMutate = useVaultMutate()
  const [stateFilter, setStateFilter] = useState<StateFilter>('all')

  const query = stateFilter === 'all' ? LEASES_KEY : `${LEASES_KEY}?state=${stateFilter}`
  const { data: leasesData, error: loadError, isLoading } =
    useVaultSWR<{ leases: Lease[] }>(query)
  const leases = leasesData?.leases ?? []

  const [revokeTarget, setRevokeTarget] = useState<Lease | null>(null)
  const [renewingId, setRenewingId] = useState<string | null>(null)

  const renew = useAsyncAction()
  const revoke = useAsyncAction()

  const onRenew = useCallback(
    (lease: Lease) => {
      setRenewingId(lease.id)
      void renew
        .run(
          async () => {
            await vaultMutate(`${LEASES_KEY}/${lease.id}/renew`, 'POST', {
              increment_seconds: 3600,
            })
            await swrMutate(query)
          },
          { fallback: 'Failed to renew lease' },
        )
        .finally(() => setRenewingId(null))
    },
    [renew, vaultMutate, query],
  )

  const onRevoke = useCallback(() => {
    if (!revokeTarget) return
    // A swallowed failure here told the operator a credential was revoked when
    // it may still be live. That is the one outcome this page must never fake.
    const self = leaseId !== null && revokeTarget.id === leaseId
    void revoke.run(
      async () => {
        await vaultMutate(`${LEASES_KEY}/${revokeTarget.id}/revoke`, 'POST', {})
        if (self) {
          logout()
          return
        }
        await swrMutate(query)
      },
      { fallback: 'Failed to revoke lease', onSuccess: () => setRevokeTarget(null) },
    )
  }, [revoke, revokeTarget, vaultMutate, query, leaseId, logout])

  const columns: Column<Lease>[] = [
    {
      field: 'target_label',
      label: 'Target',
      sortable: true,
      mono: true,
      render: row => (
        <span className="font-mono text-[13px]">
          {row.target_label}
          {leaseId && row.id === leaseId && (
            <span className="ml-2 text-[11px] font-sans font-medium text-primary-600 dark:text-primary-400">
              this session
            </span>
          )}
        </span>
      ),
    },
    {
      field: 'target_type',
      label: 'Type',
      render: row => (
        <span className="text-xs text-ink-muted">{row.target_type}</span>
      ),
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
      render: row => <TTLBar expiresAt={row.expires_at} ttlSeconds={row.ttl_seconds} />,
    },
    {
      field: 'issued_at',
      label: 'Issued',
      sortable: true,
      render: row => <span className="text-xs text-ink-muted">{formatDateTime(row.issued_at)}</span>,
    },
    {
      field: '_actions',
      label: '',
      render: row => (
        <div className="flex items-center gap-1">
          {row.renewable && row.state === 'active' && (
            <Button
              variant="ghost"
              size="sm"
              loading={renewingId === row.id}
              aria-label={`Renew lease for ${row.target_label}`}
              onClick={e => { e.stopPropagation(); onRenew(row) }}
            >
              <RefreshCw className="w-4 h-4" />
            </Button>
          )}
          {row.state !== 'revoked' && (
            <Button
              variant="ghost"
              size="sm"
              aria-label={`Revoke lease for ${row.target_label}`}
              onClick={e => { e.stopPropagation(); setRevokeTarget(row) }}
              className="text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-600/10"
            >
              <XCircle className="w-4 h-4" />
            </Button>
          )}
        </div>
      ),
    },
  ]

  const tabs: { value: StateFilter; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'active', label: 'Active' },
    { value: 'expired', label: 'Expired' },
    { value: 'revoked', label: 'Revoked' },
  ]

  return (
    <div>
      <PageHeader
        title="Leases"
        description="Token leases and remaining TTL. Revoking a lease immediately invalidates that JWT."
      />

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

      <ErrorBanner message={renew.error} onDismiss={renew.clearError} />

      {loadError ? (
        <LoadError error={loadError} what="leases" />
      ) : !isLoading && leases.length === 0 ? (
        <EmptyState
          icon={Key}
          title="No leases yet"
          description={
            leaseId
              ? 'No leases match this filter. Token leases appear here; KV secret reads do not.'
              : 'This login did not create a lease — identity could not reach lease-manager. Log out and in again once that service is up. KV secret reads never create a lease.'
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={(leases as unknown as Record<string, unknown>[]) ?? []}
          loading={isLoading}
          keyField="id"
          emptyMessage="No leases match the selected filter."
        />
      )}

      <ConfirmModal
        open={!!revokeTarget}
        onClose={() => { setRevokeTarget(null); revoke.clearError() }}
        onConfirm={onRevoke}
        title="Revoke lease"
        description={
          leaseId && revokeTarget?.id === leaseId
            ? `Revoke this session ("${revokeTarget?.target_label}")? You will be signed out immediately.`
            : `Revoke lease "${revokeTarget?.target_label}"? The associated token will stop working immediately.`
        }
        confirmLabel="Revoke"
        loading={revoke.pending}
        error={revoke.error}
      />
    </div>
  )
}
