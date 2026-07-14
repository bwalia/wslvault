'use client'
import { useState } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate } from '@/lib/fetcher'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { EmptyState } from '@/components/ui/EmptyState'
import { Modal } from '@/components/ui/Modal'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { Shield, Plus, Trash2, Edit2, X } from 'lucide-react'

interface PolicyRule {
  paths: string[]
  capabilities: string[]
}

interface Policy {
  name: string
  rules: PolicyRule[]
}

const ALL_CAPS = ['read', 'write', 'create', 'update', 'delete', 'list', 'deny'] as const
const POLICIES_KEY = '/api/policy/v1/policies'

// Empty rule factory
const emptyRule = (): PolicyRule => ({ paths: [''], capabilities: [] })

export default function PoliciesPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)
  const { data: policies, isLoading } = useSWR<Policy[]>(POLICIES_KEY, fetcher)

  const [modalOpen, setModalOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<Policy | null>(null)
  const [policyName, setPolicyName] = useState('')
  const [rules, setRules] = useState<PolicyRule[]>([emptyRule()])
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')

  const [deleteTarget, setDeleteTarget] = useState<Policy | null>(null)
  const [deleting, setDeleting] = useState(false)

  const openCreate = () => {
    setEditTarget(null)
    setPolicyName('')
    setRules([emptyRule()])
    setSaveError('')
    setModalOpen(true)
  }

  const openEdit = (policy: Policy) => {
    setEditTarget(policy)
    setPolicyName(policy.name)
    // Ensure each rule has at least one path entry
    setRules(policy.rules.map(r => ({ ...r, paths: r.paths.length ? r.paths : [''] })))
    setSaveError('')
    setModalOpen(true)
  }

  const onSave = async () => {
    if (!policyName.trim()) {
      setSaveError('Policy name is required')
      return
    }
    setSaving(true)
    setSaveError('')
    try {
      const payload: Policy = {
        name: policyName.trim(),
        rules: rules.map(r => ({
          paths: r.paths.filter(p => p.trim()),
          capabilities: r.capabilities,
        })),
      }
      if (editTarget) {
        await mutate(`${POLICIES_KEY}/${editTarget.name}`, 'PUT', payload, token, tenantId)
      } else {
        await mutate(POLICIES_KEY, 'POST', payload, token, tenantId)
      }
      await swrMutate(POLICIES_KEY)
      setModalOpen(false)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save policy')
    } finally {
      setSaving(false)
    }
  }

  const onDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await mutate(`${POLICIES_KEY}/${deleteTarget.name}`, 'DELETE', null, token, tenantId)
      await swrMutate(POLICIES_KEY)
      setDeleteTarget(null)
    } catch {
      // ignore
    } finally {
      setDeleting(false)
    }
  }

  // Rule mutation helpers
  const addRule = () => setRules(r => [...r, emptyRule()])
  const removeRule = (i: number) => setRules(r => r.filter((_, j) => j !== i))

  const updatePath = (ruleIdx: number, pathIdx: number, val: string) =>
    setRules(r => r.map((rule, i) => {
      if (i !== ruleIdx) return rule
      const paths = [...rule.paths]
      paths[pathIdx] = val
      return { ...rule, paths }
    }))

  const addPath = (ruleIdx: number) =>
    setRules(r => r.map((rule, i) => i === ruleIdx ? { ...rule, paths: [...rule.paths, ''] } : rule))

  const removePath = (ruleIdx: number, pathIdx: number) =>
    setRules(r => r.map((rule, i) =>
      i === ruleIdx ? { ...rule, paths: rule.paths.filter((_, j) => j !== pathIdx) } : rule,
    ))

  const toggleCap = (ruleIdx: number, cap: string) =>
    setRules(r => r.map((rule, i) => {
      if (i !== ruleIdx) return rule
      const caps = rule.capabilities.includes(cap)
        ? rule.capabilities.filter(c => c !== cap)
        : [...rule.capabilities, cap]
      return { ...rule, capabilities: caps }
    }))

  const columns: Column<Policy>[] = [
    { field: 'name', label: 'Name', sortable: true, mono: true },
    {
      field: 'rules',
      label: 'Rules',
      render: row => (
        <Badge variant="default">
          {Array.isArray(row.rules) ? row.rules.length : 0} rule{row.rules?.length === 1 ? '' : 's'}
        </Badge>
      ),
    },
    {
      field: '_caps',
      label: 'Capabilities',
      render: row => {
        const caps = new Set<string>()
        row.rules?.forEach((r: PolicyRule) => r.capabilities?.forEach((c: string) => caps.add(c)))
        return (
          <div className="flex flex-wrap gap-1">
            {[...caps].map(c => (
              <span
                key={c}
                className={cn(
                  'inline-flex px-1.5 py-0.5 rounded text-[11px] font-mono font-medium border',
                  c === 'deny'
                    ? 'bg-danger-50 text-danger-700 border-danger-100 dark:bg-danger-600/15 dark:text-danger-400 dark:border-danger-600/30'
                    : 'bg-surface-2 text-ink-muted border-line',
                )}
              >
                {c}
              </span>
            ))}
          </div>
        )
      },
    },
    {
      field: '_actions',
      label: '',
      render: row => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            aria-label={`Edit policy ${row.name}`}
            onClick={e => { e.stopPropagation(); openEdit(row) }}
          >
            <Edit2 className="w-4 h-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            aria-label={`Delete policy ${row.name}`}
            onClick={e => { e.stopPropagation(); setDeleteTarget(row) }}
            className="text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-600/10"
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div>
      <PageHeader
        title="Policies"
        description="Manage access control policies"
        actions={
          <Button onClick={openCreate}>
            <Plus className="w-4 h-4" />
            Create Policy
          </Button>
        }
      />

      {!isLoading && (policies ?? []).length === 0 ? (
        <EmptyState
          icon={Shield}
          title="No policies yet"
          description="Create your first policy to define which capabilities are allowed on secret paths."
          action={
            <Button onClick={openCreate}>
              <Plus className="w-4 h-4" />
              Create Policy
            </Button>
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={(policies as unknown as Record<string, unknown>[] | undefined) ?? []}
          loading={isLoading}
          keyField="name"
          onRowClick={row => openEdit(row as unknown as Policy)}
          emptyMessage="No policies match your search."
        />
      )}

      {/* Policy editor modal */}
      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editTarget ? `Edit policy: ${editTarget.name}` : 'Create policy'}
        size="lg"
        footer={
          <>
            <Button variant="secondary" size="sm" onClick={() => setModalOpen(false)}>Cancel</Button>
            <Button size="sm" loading={saving} onClick={onSave}>
              {editTarget ? 'Save changes' : 'Create policy'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {saveError && <p className="text-sm text-danger-600">{saveError}</p>}

          <Input
            label="Policy name"
            placeholder="admin-policy"
            value={policyName}
            onChange={e => setPolicyName(e.target.value)}
            disabled={!!editTarget}
            mono
          />

          {/* Rule builder */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-ink">Rules</span>
              <Button variant="ghost" size="sm" onClick={addRule} type="button">
                <Plus className="w-3.5 h-3.5" /> Add rule
              </Button>
            </div>
            <div className="space-y-3">
              {rules.map((rule, rIdx) => (
                <div key={rIdx} className="p-3 rounded-lg border border-line bg-surface-2 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-ink-faint uppercase tracking-wide">
                      Rule {rIdx + 1}
                    </span>
                    {rules.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeRule(rIdx)}
                        aria-label={`Remove rule ${rIdx + 1}`}
                        className="text-ink-faint hover:text-danger-600 p-0.5 rounded transition-colors focus-ring"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>

                  {/* Paths */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-ink-muted">Paths (glob)</span>
                      <button
                        type="button"
                        onClick={() => addPath(rIdx)}
                        className="text-xs text-primary-600 hover:text-primary-700 transition-colors focus-ring rounded"
                      >
                        + add path
                      </button>
                    </div>
                    {rule.paths.map((path, pIdx) => (
                      <div key={pIdx} className="flex items-center gap-1.5">
                        <div className="flex-1">
                          <Input
                            mono
                            value={path}
                            onChange={e => updatePath(rIdx, pIdx, e.target.value)}
                            placeholder="secret/data/** or **"
                          />
                        </div>
                        {rule.paths.length > 1 && (
                          <button
                            type="button"
                            onClick={() => removePath(rIdx, pIdx)}
                            aria-label={`Remove path ${pIdx + 1} from rule ${rIdx + 1}`}
                            className="text-ink-faint hover:text-danger-600 p-0.5 rounded transition-colors focus-ring"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Capabilities — segmented toggle chips */}
                  <div>
                    <span className="text-xs text-ink-muted mb-1.5 block">Capabilities</span>
                    <div className="flex flex-wrap gap-1">
                      {ALL_CAPS.map(cap => (
                        <button
                          key={cap}
                          type="button"
                          onClick={() => toggleCap(rIdx, cap)}
                          className={cn(
                            'px-2.5 py-1 text-[11px] rounded border font-mono font-medium transition-colors focus-ring',
                            rule.capabilities.includes(cap)
                              ? cap === 'deny'
                                ? 'bg-danger-600 text-white border-danger-600'
                                : 'bg-primary-600 text-white border-primary-600'
                              : 'bg-surface border-line text-ink-muted hover:bg-surface-3',
                          )}
                        >
                          {cap}
                        </button>
                      ))}
                    </div>
                    {rule.capabilities.includes('deny') && (
                      <p className="mt-1.5 text-xs text-danger-600">
                        deny overrides all other capabilities for matching paths
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={onDelete}
        title="Delete policy"
        description={`Delete policy "${deleteTarget?.name}"? This may revoke access for API keys using this policy.`}
        confirmLabel="Delete"
        loading={deleting}
      />
    </div>
  )
}
