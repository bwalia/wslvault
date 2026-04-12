'use client'
import { useState } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
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
    setRules(r => r.map((rule, i) => i === ruleIdx ? { ...rule, paths: rule.paths.filter((_, j) => j !== pathIdx) } : rule))

  const toggleCap = (ruleIdx: number, cap: string) =>
    setRules(r => r.map((rule, i) => {
      if (i !== ruleIdx) return rule
      const caps = rule.capabilities.includes(cap)
        ? rule.capabilities.filter(c => c !== cap)
        : [...rule.capabilities, cap]
      return { ...rule, capabilities: caps }
    }))

  const columns: Column<Policy>[] = [
    { field: 'name', label: 'Name', sortable: true },
    {
      field: 'rules',
      label: 'Rules',
      render: row => (
        <Badge variant="info">{Array.isArray(row.rules) ? row.rules.length : 0} rule{row.rules?.length === 1 ? '' : 's'}</Badge>
      ),
    },
    {
      field: '_caps',
      label: 'Capabilities',
      render: row => {
        const caps = new Set<string>()
        row.rules?.forEach(r => r.capabilities?.forEach(c => caps.add(c)))
        return (
          <div className="flex flex-wrap gap-1">
            {[...caps].map(c => (
              <span key={c} className={`inline-flex px-1.5 py-0.5 rounded text-xs font-medium ${c === 'deny' ? 'bg-danger-50 dark:bg-danger-900/20 text-danger-700 dark:text-danger-400' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'}`}>
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
          <Button variant="ghost" size="sm" onClick={e => { e.stopPropagation(); openEdit(row) }}>
            <Edit2 className="w-4 h-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={e => { e.stopPropagation(); setDeleteTarget(row) }}
            className="text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-900/20"
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
        icon={Shield}
        actions={
          <Button onClick={openCreate}>
            <Plus className="w-4 h-4" />
            New Policy
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={(policies as unknown as Record<string, unknown>[] | undefined) ?? []}
        loading={isLoading}
        keyField="name"
        onRowClick={row => openEdit(row as unknown as Policy)}
        emptyMessage="No policies yet — create your first policy to control access"
      />

      {/* Policy editor modal */}
      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={editTarget ? `Edit Policy: ${editTarget.name}` : 'New Policy'}
        size="lg"
        footer={
          <>
            <Button variant="secondary" size="sm" onClick={() => setModalOpen(false)}>Cancel</Button>
            <Button size="sm" loading={saving} onClick={onSave}>
              {editTarget ? 'Save Changes' : 'Create Policy'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {saveError && <p className="text-sm text-danger-600 dark:text-danger-400">{saveError}</p>}

          <Input
            label="Policy Name"
            placeholder="admin-policy"
            value={policyName}
            onChange={e => setPolicyName(e.target.value)}
            disabled={!!editTarget}
          />

          {/* Rule builder */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm font-medium text-slate-700 dark:text-slate-300">Rules</label>
              <Button variant="ghost" size="sm" onClick={addRule} type="button">
                <Plus className="w-3.5 h-3.5" /> Add Rule
              </Button>
            </div>
            <div className="space-y-3">
              {rules.map((rule, rIdx) => (
                <div key={rIdx} className="p-3 rounded-lg border border-slate-200 dark:border-slate-700 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-500 uppercase tracking-wide">Rule {rIdx + 1}</span>
                    {rules.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeRule(rIdx)}
                        className="text-danger-500 hover:text-danger-700 p-0.5"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>

                  {/* Paths */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="text-xs text-slate-500">Paths (glob)</label>
                      <button
                        type="button"
                        onClick={() => addPath(rIdx)}
                        className="text-xs text-primary-600 hover:text-primary-700"
                      >
                        + add path
                      </button>
                    </div>
                    {rule.paths.map((path, pIdx) => (
                      <div key={pIdx} className="flex items-center gap-1.5">
                        <input
                          value={path}
                          onChange={e => updatePath(rIdx, pIdx, e.target.value)}
                          placeholder="secret/data/** or **"
                          className="flex-1 px-2.5 py-1.5 text-sm font-mono rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
                        />
                        {rule.paths.length > 1 && (
                          <button type="button" onClick={() => removePath(rIdx, pIdx)} className="text-slate-400 hover:text-danger-500">
                            <X className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Capabilities */}
                  <div>
                    <label className="text-xs text-slate-500 mb-1.5 block">Capabilities</label>
                    <div className="flex flex-wrap gap-1.5">
                      {ALL_CAPS.map(cap => (
                        <button
                          key={cap}
                          type="button"
                          onClick={() => toggleCap(rIdx, cap)}
                          className={`px-2.5 py-1 text-xs rounded-md font-medium transition-colors ${
                            rule.capabilities.includes(cap)
                              ? cap === 'deny'
                                ? 'bg-danger-100 text-danger-700 dark:bg-danger-900/30 dark:text-danger-400 ring-1 ring-danger-400'
                                : 'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300 ring-1 ring-primary-400'
                              : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'
                          }`}
                        >
                          {cap}
                        </button>
                      ))}
                    </div>
                    {rule.capabilities.includes('deny') && (
                      <p className="mt-1.5 text-xs text-danger-600 dark:text-danger-400">
                        ⚠ deny overrides all other capabilities for matching paths
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
        title="Delete Policy"
        description={`Delete policy "${deleteTarget?.name}"? This may revoke access for API keys using this policy.`}
        confirmLabel="Delete"
        loading={deleting}
      />
    </div>
  )
}
