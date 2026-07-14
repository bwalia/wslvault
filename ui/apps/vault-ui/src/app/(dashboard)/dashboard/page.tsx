'use client'
import useSWR from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { StatCard } from '@/components/ui/StatCard'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { CodeChip } from '@/components/ui/CodeChip'
import { formatRelativeTime } from '@/lib/utils'
import { Activity } from 'lucide-react'

interface AuditEvent {
  event_id: string
  action: string
  resource: string
  outcome: string
  timestamp: string
}

interface AuditResponse {
  events?: AuditEvent[]
}

type TenantsResponse = unknown[]

type ApiKeysResponse = unknown[]

interface SecretsResponse {
  paths?: string[]
}

export default function DashboardPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)

  const { data: tenants } = useSWR<TenantsResponse>('/api/identity/v1/tenants', fetcher)
  const { data: apiKeys } = useSWR<ApiKeysResponse>('/api/identity/v1/api-keys', fetcher)
  const { data: secrets } = useSWR<SecretsResponse>(
    '/api/secret/v1/secret/list?prefix=',
    fetcher,
  )
  const { data: audit } = useSWR<AuditResponse>(
    '/api/audit/v1/audit/events?limit=10',
    fetcher,
  )

  return (
    <div className="max-w-7xl space-y-6">
      <PageHeader title="Dashboard" description="WSLVault overview" />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Tenants"
          value={tenants?.length ?? '—'}
        />
        <StatCard
          label="API Keys"
          value={apiKeys?.length ?? '—'}
        />
        <StatCard
          label="Secrets"
          value={secrets?.paths?.length ?? '—'}
        />
        <StatCard
          label="Policies"
          value="—"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Audit Events</CardTitle>
        </CardHeader>
        <CardBody className="p-0">
          {audit?.events?.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-surface-2">
                  <tr>
                    <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                      Action
                    </th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                      Resource
                    </th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                      Outcome
                    </th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-ink-faint">
                      Time
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {audit.events.map(e => (
                    <tr
                      key={e.event_id}
                      className="hover:bg-surface-2 transition-colors"
                    >
                      <td className="px-4 py-2.5">
                        <span className="font-mono text-[13px] text-ink">{e.action}</span>
                      </td>
                      <td className="px-4 py-2.5 max-w-xs truncate">
                        <CodeChip value={e.resource} truncate={48} />
                      </td>
                      <td className="px-4 py-2.5">
                        <StatusBadge status={e.outcome} />
                      </td>
                      <td className="px-4 py-2.5 text-xs text-ink-faint tabular">
                        {formatRelativeTime(e.timestamp)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              icon={Activity}
              title="No recent activity"
              description="Audit events will appear here as operations are performed against this vault."
            />
          )}
        </CardBody>
      </Card>
    </div>
  )
}
