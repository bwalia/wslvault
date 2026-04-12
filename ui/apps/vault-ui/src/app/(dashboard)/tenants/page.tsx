'use client'
import { useState } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Modal } from '@/components/ui/Modal'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { ShieldCheck, Plus, Trash2 } from 'lucide-react'
import { formatDateTime } from '@/lib/utils'
import { useForm } from 'react-hook-form'

interface Tenant {
  id: string
  slug: string
  display_name: string
  tier: string
  root_key_id: string
  created_at: string
}

interface TenantFormValues {
  slug: string
  display_name: string
  tier: 'shared' | 'dedicated' | 'sovereign'
  root_key_id: string
}

const TENANTS_KEY = '/api/identity/v1/tenants'

export default function TenantsPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)
  const { data: tenants, isLoading } = useSWR<Tenant[]>(TENANTS_KEY, fetcher)

  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  const [deleteTarget, setDeleteTarget] = useState<Tenant | null>(null)
  const [deleting, setDeleting] = useState(false)

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TenantFormValues>({ defaultValues: { tier: 'shared' } })

  const onCreate = async (values: TenantFormValues) => {
    setCreating(true)
    setCreateError('')
    try {
      await mutate(TENANTS_KEY, 'POST', values, token, tenantId)
      await swrMutate(TENANTS_KEY)
      setCreateOpen(false)
      reset()
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create tenant')
    } finally {
      setCreating(false)
    }
  }

  const onDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await mutate(`${TENANTS_KEY}/${deleteTarget.id}`, 'DELETE', null, token, tenantId)
      await swrMutate(TENANTS_KEY)
      setDeleteTarget(null)
    } catch {
      // Silently ignore — the confirm modal will close
    } finally {
      setDeleting(false)
    }
  }

  const columns: Column<Tenant>[] = [
    { field: 'display_name', label: 'Name', sortable: true },
    { field: 'slug', label: 'Slug', sortable: true, render: row => <span className="font-mono text-xs">{row.slug}</span> },
    { field: 'tier', label: 'Tier', render: row => <StatusBadge status={row.tier} /> },
    {
      field: 'created_at',
      label: 'Created',
      sortable: true,
      render: row => (
        <span className="text-xs text-slate-500">{formatDateTime(row.created_at)}</span>
      ),
    },
    {
      field: '_actions',
      label: '',
      render: row => (
        <Button
          variant="ghost"
          size="sm"
          onClick={e => { e.stopPropagation(); setDeleteTarget(row) }}
          className="text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-900/20"
        >
          <Trash2 className="w-4 h-4" />
        </Button>
      ),
    },
  ]

  return (
    <div>
      <PageHeader
        title="Tenants"
        description="Manage multi-tenant namespaces"
        icon={ShieldCheck}
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" />
            Create Tenant
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={(tenants as unknown as Record<string, unknown>[] | undefined) ?? []}
        loading={isLoading}
        keyField="id"
      />

      {/* Create modal */}
      <Modal
        open={createOpen}
        onClose={() => { setCreateOpen(false); reset(); setCreateError('') }}
        title="Create Tenant"
        size="md"
        footer={
          <>
            <Button variant="secondary" size="sm" onClick={() => { setCreateOpen(false); reset() }}>
              Cancel
            </Button>
            <Button size="sm" loading={creating} onClick={handleSubmit(onCreate)}>
              Create
            </Button>
          </>
        }
      >
        <form className="space-y-4" onSubmit={handleSubmit(onCreate)}>
          {createError && (
            <p className="text-sm text-danger-600 dark:text-danger-400">{createError}</p>
          )}
          <Input
            label="Slug"
            placeholder="my-tenant"
            error={errors.slug?.message}
            {...register('slug', { required: 'Slug is required' })}
          />
          <Input
            label="Display Name"
            placeholder="My Tenant"
            error={errors.display_name?.message}
            {...register('display_name', { required: 'Display name is required' })}
          />
          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">
              Tier
            </label>
            <select
              className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500/50"
              {...register('tier')}
            >
              <option value="shared">Shared</option>
              <option value="dedicated">Dedicated</option>
              <option value="sovereign">Sovereign</option>
            </select>
          </div>
          <Input
            label="Root Key ID (optional)"
            placeholder="key-..."
            {...register('root_key_id')}
          />
        </form>
      </Modal>

      {/* Delete confirm */}
      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={onDelete}
        title="Delete Tenant"
        description={`Are you sure you want to delete tenant "${deleteTarget?.display_name}"? This action cannot be undone.`}
        confirmText={deleteTarget?.slug}
        confirmLabel="Delete"
        loading={deleting}
      />
    </div>
  )
}
