'use client'
import { useState } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { CodeChip } from '@/components/ui/CodeChip'
import { Modal } from '@/components/ui/Modal'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Plus, Trash2 } from 'lucide-react'
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
    {
      field: 'slug',
      label: 'Slug',
      sortable: true,
      render: row => <CodeChip value={row.slug} />,
    },
    {
      field: 'id',
      label: 'Tenant ID',
      render: row => <CodeChip value={row.id} truncate={20} copyable />,
    },
    { field: 'tier', label: 'Tier', render: row => <StatusBadge status={row.tier} /> },
    {
      field: 'created_at',
      label: 'Created',
      sortable: true,
      render: row => (
        <span className="text-xs text-ink-muted tabular">{formatDateTime(row.created_at)}</span>
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
          className="text-danger-600 hover:bg-danger-50"
          aria-label={`Delete tenant ${row.display_name}`}
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
        emptyMessage="No tenants yet. Create your first tenant to get started."
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
            <p className="text-sm text-danger-600">{createError}</p>
          )}
          <Input
            label="Slug"
            placeholder="my-tenant"
            mono
            hint="A short, URL-safe identifier for this tenant. Cannot be changed after creation."
            error={errors.slug?.message}
            {...register('slug', { required: 'Slug is required' })}
          />
          <Input
            label="Display Name"
            placeholder="My Tenant"
            hint="Human-readable name shown in the UI."
            error={errors.display_name?.message}
            {...register('display_name', { required: 'Display name is required' })}
          />
          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-ink">
              Tier
            </label>
            <select
              className="w-full px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500 transition-colors"
              {...register('tier')}
            >
              <option value="shared">Shared — multi-tenant cluster, cost-efficient</option>
              <option value="dedicated">Dedicated — isolated cluster, higher isolation</option>
              <option value="sovereign">Sovereign — air-gapped or jurisdiction-specific</option>
            </select>
            <p className="text-xs text-ink-faint">
              Shared is suitable for most workloads. Choose Dedicated or Sovereign for stricter isolation requirements.
            </p>
          </div>
          <Input
            label="Root Key ID (optional)"
            placeholder="key-..."
            mono
            hint="The KMS key used to wrap this tenant's root token. Leave blank to use the default."
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
