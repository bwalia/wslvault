'use client'
import useSWR from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { StatCard } from '@/components/ui/StatCard'
import { Card, CardHeader, CardBody } from '@/components/ui/Card'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { formatRelativeTime } from '@/lib/utils'
import { Lock, Key, Shield, Users, Activity } from 'lucide-react'

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
    <div>
      <PageHeader title="Dashboard" description="WSLVault overview" icon={Activity} />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          label="Tenants"
          value={tenants?.length ?? '—'}
          icon={Users}
          color="text-primary-600 bg-primary-50 dark:bg-primary-900/20 dark:text-primary-400"
        />
        <StatCard
          label="API Keys"
          value={apiKeys?.length ?? '—'}
          icon={Key}
          color="text-accent-600 bg-accent-50 dark:bg-accent-900/20 dark:text-accent-600"
        />
        <StatCard
          label="Secrets"
          value={secrets?.paths?.length ?? '—'}
          icon={Lock}
          color="text-warn-600 bg-warn-50 dark:bg-warn-900/20 dark:text-warn-500"
        />
        <StatCard
          label="Policies"
          value="—"
          icon={Shield}
          color="text-danger-600 bg-danger-50 dark:bg-danger-900/20 dark:text-danger-400"
        />
      </div>

      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">
            Recent Audit Events
          </h2>
        </CardHeader>
        <CardBody className="p-0">
          {audit?.events?.length ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 dark:border-slate-800">
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">
                    Action
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">
                    Resource
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">
                    Outcome
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {audit.events.map(e => (
                  <tr
                    key={e.event_id}
                    className="border-b border-slate-100 dark:border-slate-800/50 hover:bg-slate-50 dark:hover:bg-slate-800/30"
                  >
                    <td className="px-6 py-3 font-mono text-xs">{e.action}</td>
                    <td className="px-6 py-3 text-slate-600 dark:text-slate-400 truncate max-w-xs">
                      {e.resource}
                    </td>
                    <td className="px-6 py-3">
                      <StatusBadge status={e.outcome} />
                    </td>
                    <td className="px-6 py-3 text-slate-500 text-xs">
                      {formatRelativeTime(e.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="py-12 text-center text-slate-400 text-sm">No recent activity</div>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
