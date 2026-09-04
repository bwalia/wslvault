'use client'
import { useVaultSWR } from '@/hooks/useVaultSWR'
import { api } from '@/lib/api'
import { PageHeader } from '@/components/ui/PageHeader'
import { motion } from 'framer-motion'
import { stagger, staggerItem } from '@/lib/motion'
import { useAuth } from '@/contexts/AuthContext'
import { StatCard } from '@/components/ui/StatCard'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { EmptyState } from '@/components/ui/EmptyState'
import { ErrorBanner, LoadError } from '@/components/ErrorBanner'
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
  const { policies } = useAuth()
  // Tenants and API keys are administrator-only. Requesting them as an
  // ordinary tenant member returned 403 and painted the landing page with an
  // error banner and two "!" tiles — telling someone their vault was broken
  // when in fact it was working and those two figures were simply not theirs
  // to see. Passing `null` to SWR skips the request entirely.
  const isAdmin = policies.some(
    p => p === 'wslvault:platform-admin' || p === 'admin' || p === 'root',
  )

  const { data: tenants, error: tenantsError } = useVaultSWR<TenantsResponse>(
    isAdmin ? api.identity.tenants() : null,
  )
  const { data: apiKeys, error: apiKeysError } = useVaultSWR<ApiKeysResponse>(
    isAdmin ? api.identity.apiKeys() : null,
  )
  const { data: secrets, error: secretsError } = useVaultSWR<SecretsResponse>(api.secret.list())
  const { data: audit, error: auditError } = useVaultSWR<AuditResponse>(
    '/api/audit/v1/audit/events?limit=10',
  )

  // This is the landing page. Every stat previously fell back to an em-dash on
  // error, so a completely dead backend rendered as a healthy, empty vault —
  // the most confident possible way to be wrong. Surface it once at the top
  // rather than four times in the cards.
  const loadFailure = tenantsError ?? apiKeysError ?? secretsError
  const failureMessage =
    loadFailure instanceof Error
      ? `Some dashboard data could not be loaded: ${loadFailure.message}`
      : ''

  return (
    <div className="max-w-7xl space-y-6">
      <PageHeader
        title="Dashboard"
        description="An overview of what is in your vault and what has happened recently."
        guide={
          <>
            <p>
              This is the front door. The tiles show how much is stored, and the
              list below shows what has happened recently.
            </p>
            <p>
              Nothing here is a secret itself — reading an actual value takes a
              deliberate trip to <strong>Secrets</strong>, and that read is written to
              the audit log like everything else.
            </p>
          </>
        }
      />

      <ErrorBanner message={failureMessage} />

      <motion.div
        variants={stagger}
        initial="hidden"
        animate="visible"
        className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4"
      >
        {isAdmin && (
          <>
            <motion.div variants={staggerItem}>
              <StatCard
                label="Tenants"
                value={tenantsError ? '!' : tenants?.length ?? '—'}
                detail="organisations in this deployment"
              />
            </motion.div>
            <motion.div variants={staggerItem}>
              <StatCard
                label="Access keys"
                value={apiKeysError ? '!' : apiKeys?.length ?? '—'}
                detail="people and services that can sign in"
              />
            </motion.div>
          </>
        )}
        <motion.div variants={staggerItem}>
          <StatCard
            label="Secrets"
            value={secretsError ? '!' : secrets?.paths?.length ?? '—'}
            detail="values stored, all encrypted"
          />
        </motion.div>
      </motion.div>

      <Card>
        <CardHeader>
          <CardTitle>Recent activity</CardTitle>
        </CardHeader>
        <CardBody className="p-0">
          {audit?.events?.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-surface-2 border-b border-line-strong">
                  <tr>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-faint">
                      Action
                    </th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-faint">
                      Resource
                    </th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-faint">
                      Outcome
                    </th>
                    <th className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-faint">
                      Time
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {audit.events.map(e => (
                    <tr
                      key={e.event_id}
                      className="transition-colors hover:bg-surface-2 hover:shadow-[inset_2px_0_0_0_var(--brass)]"
                    >
                      <td className="px-4 py-3">
                        <span className="font-mono text-[13px] text-ink">{e.action}</span>
                      </td>
                      <td className="px-4 py-3 max-w-xs truncate">
                        <CodeChip value={e.resource} truncate={48} />
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={e.outcome} />
                      </td>
                      <td className="px-4 py-3 text-xs text-ink-faint tabular">
                        {formatRelativeTime(e.timestamp)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : auditError ? (
            // The audit widget is the most misleading of the four: "No recent
            // activity" on a failed fetch reads as "nothing has happened",
            // which is exactly the wrong conclusion during an incident.
            <div className="p-4">
              <LoadError error={auditError} what="audit events" />
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
