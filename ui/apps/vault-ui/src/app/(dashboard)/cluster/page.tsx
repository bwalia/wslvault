'use client'
import useSWR from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardBody } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { StatCard } from '@/components/ui/StatCard'
import { Server, RefreshCw, Crown } from 'lucide-react'
import { Button } from '@/components/ui/Button'

interface ClusterNode {
  id: string
  address: string
  role: 'leader' | 'follower' | 'candidate' | string
  health: 'healthy' | 'unhealthy' | 'unknown' | string
  raft_index: number | null
  commit_index: number | null
  last_contact_ms: number | null
}

interface ClusterStatus {
  leader_id: string | null
  term: number | null
  nodes: ClusterNode[]
  quorum_met: boolean | null
  raft_index: number | null
  commit_index: number | null
}

function healthVariant(health: string): 'success' | 'danger' | 'warning' | 'default' {
  switch (health.toLowerCase()) {
    case 'healthy':
      return 'success'
    case 'unhealthy':
      return 'danger'
    default:
      return 'warning'
  }
}

function roleVariant(role: string): 'info' | 'default' | 'warning' {
  switch (role.toLowerCase()) {
    case 'leader':
      return 'info'
    case 'candidate':
      return 'warning'
    default:
      return 'default'
  }
}

const CLUSTER_KEY = '/api/gateway/v1/cluster/status'

export default function ClusterPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)

  const {
    data,
    isLoading,
    error,
    mutate: revalidate,
  } = useSWR<ClusterStatus>(CLUSTER_KEY, fetcher, { refreshInterval: 10_000 })

  const nodes = data?.nodes ?? []
  const healthyCount = nodes.filter(n => n.health === 'healthy').length
  const leaderNode = nodes.find(n => n.role === 'leader')

  return (
    <div>
      <PageHeader
        title="Cluster & HA Health"
        description="Raft cluster topology, node health, and consensus metrics"
        icon={Server}
        iconColor="bg-warn-100 text-warn-600 dark:bg-warn-900/20 dark:text-warn-400"
        actions={
          <Button variant="secondary" size="sm" onClick={() => revalidate()}>
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
        }
      />

      {/* Summary stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatCard
          label="Total Nodes"
          value={isLoading ? '—' : nodes.length}
          icon={Server}
          color="text-primary-600 bg-primary-50 dark:bg-primary-900/20 dark:text-primary-400"
        />
        <StatCard
          label="Healthy Nodes"
          value={isLoading ? '—' : healthyCount}
          icon={Server}
          color="text-accent-600 bg-accent-50 dark:bg-accent-900/20 dark:text-accent-600"
        />
        <StatCard
          label="Raft Term"
          value={isLoading ? '—' : (data?.term ?? '—')}
          icon={Crown}
          color="text-warn-600 bg-warn-50 dark:bg-warn-900/20 dark:text-warn-500"
        />
        <StatCard
          label="Commit Index"
          value={isLoading ? '—' : (data?.commit_index ?? '—')}
          icon={Server}
          color="text-danger-600 bg-danger-50 dark:bg-danger-900/20 dark:text-danger-400"
        />
      </div>

      {/* Quorum status banner */}
      {!isLoading && data && (
        <div
          className={`mb-6 px-5 py-3 rounded-xl border flex items-center gap-3 text-sm font-medium ${
            data.quorum_met === false
              ? 'bg-danger-50 dark:bg-danger-900/20 border-danger-200 dark:border-danger-800 text-danger-700 dark:text-danger-400'
              : data.quorum_met === true
              ? 'bg-accent-50 dark:bg-accent-900/20 border-accent-200 dark:border-accent-800 text-accent-700 dark:text-accent-400'
              : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400'
          }`}
        >
          <span className="font-semibold">Quorum:</span>
          {data.quorum_met === true
            ? 'Met — cluster is fully operational'
            : data.quorum_met === false
            ? 'Not met — cluster may be unavailable for writes'
            : 'Unknown'}
          {leaderNode && (
            <span className="ml-auto flex items-center gap-1 text-xs font-normal text-slate-600 dark:text-slate-400">
              <Crown className="w-3.5 h-3.5 text-warn-500" />
              Leader: {leaderNode.address ?? leaderNode.id}
            </span>
          )}
        </div>
      )}

      {/* Node table */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Cluster Nodes</h2>
        </CardHeader>
        <CardBody className="p-0">
          {isLoading ? (
            <div className="py-12 text-center text-sm text-slate-400">Loading cluster status…</div>
          ) : error ? (
            <div className="py-12 text-center text-sm text-danger-600 dark:text-danger-400">
              Failed to load cluster status:{' '}
              {error instanceof Error ? error.message : 'Unknown error'}
            </div>
          ) : nodes.length === 0 ? (
            <div className="py-12 text-center text-sm text-slate-400">
              No cluster nodes reported
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-slate-50 dark:bg-slate-800/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Node
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Address
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Role
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Health
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Raft Index
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Commit Index
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Last Contact
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-slate-900 divide-y divide-slate-100 dark:divide-slate-800/50">
                {nodes.map(node => (
                  <tr
                    key={node.id}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors"
                  >
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        {node.role === 'leader' && (
                          <Crown className="w-3.5 h-3.5 text-warn-500 flex-shrink-0" />
                        )}
                        <span className="font-mono text-xs text-slate-700 dark:text-slate-300 truncate max-w-[120px]">
                          {node.id}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-3 text-xs font-mono text-slate-500">
                      {node.address ?? '—'}
                    </td>
                    <td className="px-6 py-3">
                      <Badge variant={roleVariant(node.role)}>{node.role}</Badge>
                    </td>
                    <td className="px-6 py-3">
                      <Badge variant={healthVariant(node.health)}>{node.health}</Badge>
                    </td>
                    <td className="px-6 py-3 text-xs text-slate-500">
                      {node.raft_index?.toLocaleString() ?? '—'}
                    </td>
                    <td className="px-6 py-3 text-xs text-slate-500">
                      {node.commit_index?.toLocaleString() ?? '—'}
                    </td>
                    <td className="px-6 py-3 text-xs text-slate-500">
                      {node.last_contact_ms != null ? `${node.last_contact_ms} ms` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardBody>
      </Card>
    </div>
  )
}
