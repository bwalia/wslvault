'use client'
import { useState, useCallback } from 'react'
import { mutate as swrMutate } from 'swr'
import { useVaultSWR, useVaultMutate } from '@/hooks/useVaultSWR'
import { useAsyncAction } from '@/hooks/useAsyncAction'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { EmptyState } from '@/components/ui/EmptyState'
import { Modal } from '@/components/ui/Modal'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { ErrorBanner, LoadError } from '@/components/ErrorBanner'
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
const POLICIES_KEY = api.policy.list()

// Empty rule factory
const emptyRule = (): PolicyRule => ({ paths: [''], capabilities: [] })

export default function PoliciesPage() {
  const vaultMutate = useVaultMutate()
  const { data: policies, error: loadError, isLoading } = useVaultSWR<Policy[]>(POLICIES_KEY)

  const [modalOpen, setModalOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<Policy | null>(null)
  const [policyName, setPolicyName] = useState('')
  const [rules, setRules] = useState<PolicyRule[]>([emptyRule()])
  const [deleteTarget, setDeleteTarget] = useState<Policy | null>(null)

  const save = useAsyncAction()
  const remove = useAsyncAction()

  const openCreate = useCallback(() => {
    setEditTarget(null)
    setPolicyName('')
    setRules([emptyRule()])
    save.clearError()
    setModalOpen(true)
  }, [save])

  const openEdit = useCallback(
    (policy: Policy) => {
      setEditTarget(policy)
      setPolicyName(policy.name)
      // `rules` is typed non-optional but comes off the wire. Unguarded, a
      // policy without it threw on row-click and took the page to the error
      // boundary.
      setRules((policy.rules ?? []).map(r => ({ ...r, paths: r.paths?.length ? r.paths : [''] })))
      save.clearError()
      setModalOpen(true)
    },
    [save],
  )

  const onSave = useCallback(() => {
    void save.run(
      async () => {
        if (!policyName.trim()) throw new Error('Policy name is required')
        const payload: Policy = {
          name: policyName.trim(),
          rules: rules.map(r => ({
            paths: r.paths.filter(p => p.trim()),
            capabilities: r.capabilities,
          })),
        }
        if (editTarget) {
          await vaultMutate(api.policy.byName(editTarget.name), 'PUT', payload)
        } else {
          await vaultMutate(POLICIES_KEY, 'POST', payload)
        }
        await swrMutate(POLICIES_KEY)
      },
      { fallback: 'Failed to save policy', onSuccess: () => setModalOpen(false) },
    )
  }, [save, policyName, rules, editTarget, vaultMutate])

  const onDelete = useCallback(() => {
    if (!deleteTarget) return
    void remove.run(
      async () => {
        await vaultMutate(api.policy.byName(deleteTarget.name), 'DELETE')
        await swrMutate(POLICIES_KEY)
      },
      { fallback: 'Failed to delete policy', onSuccess: () => setDeleteTarget(null) },
    )
  }, [remove, deleteTarget, vaultMutate])

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
                  'inline-flex px-1.5 py-0.5 rounded text-xs font-mono font-medium border',
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
        guide={
          <>
            <p>
              A <strong>policy</strong> is a list of rules. Each one says which paths a
              holder may touch, and what they may do — read, write, list or delete.
            </p>
            <p>
              Policies attach to API keys. A key carrying a policy that grants
              <strong> read</strong> on <strong>secret/prod/**</strong> can read every production
              secret and change none of them.
            </p>
          </>
        }
        actions={
          <Button onClick={openCreate}>
            <Plus className="w-4 h-4" />
            Create Policy
          </Button>
        }
      />

      {loadError ? (
        <LoadError error={loadError} what="policies" />
      ) : !isLoading && (policies ?? []).length === 0 ? (
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
            <Button
              variant="secondary"
              size="sm"
              disabled={save.pending}
              onClick={() => { setModalOpen(false); save.clearError() }}
            >
              Cancel
            </Button>
            <Button size="sm" loading={save.pending} onClick={onSave}>
              {editTarget ? 'Save changes' : 'Create policy'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <ErrorBanner message={save.error} onDismiss={save.clearError} />

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
                            'px-2.5 py-1 text-xs rounded border font-mono font-medium transition-colors focus-ring',
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
        onClose={() => { setDeleteTarget(null); remove.clearError() }}
        onConfirm={onDelete}
        title="Delete policy"
        description={`Delete policy "${deleteTarget?.name}"? This may revoke access for API keys using this policy.`}
        confirmLabel="Delete"
        loading={remove.pending}
        error={remove.error}
      />
    </div>
  )
}
