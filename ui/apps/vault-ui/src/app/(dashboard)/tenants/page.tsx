'use client'
import { useState, useCallback } from 'react'
import { mutate as swrMutate } from 'swr'
import { useVaultSWR, useVaultMutate } from '@/hooks/useVaultSWR'
import { useAsyncAction } from '@/hooks/useAsyncAction'
import { api } from '@/lib/api'
import { ErrorBanner, LoadError } from '@/components/ErrorBanner'
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

const TENANTS_KEY = api.identity.tenants()

export default function TenantsPage() {
  const vaultMutate = useVaultMutate()
  const { data: tenants, error: loadError, isLoading } = useVaultSWR<Tenant[]>(TENANTS_KEY)

  const [createOpen, setCreateOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Tenant | null>(null)

  const create = useAsyncAction()
  const remove = useAsyncAction()

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TenantFormValues>({ defaultValues: { tier: 'shared' } })

  const onCreate = useCallback(
    (values: TenantFormValues) => {
      void create.run(
        async () => {
          await vaultMutate(TENANTS_KEY, 'POST', values)
          await swrMutate(TENANTS_KEY)
        },
        {
          fallback: 'Failed to create tenant',
          onSuccess: () => {
            setCreateOpen(false)
            reset()
          },
        },
      )
    },
    [create, vaultMutate, reset],
  )

  const onDelete = useCallback(() => {
    if (!deleteTarget) return
    // The previous comment here claimed "the confirm modal will close" on
    // failure. It did not: setDeleteTarget(null) sat inside the try, so a
    // failed delete left the modal open with the spinner stopped and no
    // message — the failure was indistinguishable from a no-op.
    void remove.run(
      async () => {
        await vaultMutate(api.identity.tenant(deleteTarget.id), 'DELETE')
        await swrMutate(TENANTS_KEY)
      },
      { fallback: 'Failed to delete tenant', onSuccess: () => setDeleteTarget(null) },
    )
  }, [remove, deleteTarget, vaultMutate])

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

      {loadError ? (
        <LoadError error={loadError} what="tenants" />
      ) : (
        <DataTable
          columns={columns}
          data={(tenants as unknown as Record<string, unknown>[] | undefined) ?? []}
          loading={isLoading}
          keyField="id"
          emptyMessage="No tenants yet. Create your first tenant to get started."
        />
      )}

      {/* Create modal */}
      <Modal
        open={createOpen}
        onClose={() => { setCreateOpen(false); reset(); create.clearError() }}
        title="Create Tenant"
        size="md"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              disabled={create.pending}
              onClick={() => { setCreateOpen(false); reset(); create.clearError() }}
            >
              Cancel
            </Button>
            <Button size="sm" loading={create.pending} onClick={handleSubmit(onCreate)}>
              Create
            </Button>
          </>
        }
      >
        <form className="space-y-4" onSubmit={handleSubmit(onCreate)}>
          <ErrorBanner message={create.error} onDismiss={create.clearError} />
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
        onClose={() => { setDeleteTarget(null); remove.clearError() }}
        onConfirm={onDelete}
        title="Delete Tenant"
        description={`Are you sure you want to delete tenant "${deleteTarget?.display_name}"? This action cannot be undone.`}
        confirmText={deleteTarget?.slug}
        confirmLabel="Delete"
        loading={remove.pending}
        error={remove.error}
      />
    </div>
  )
}
