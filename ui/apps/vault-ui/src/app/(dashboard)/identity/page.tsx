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
import { CodeChip } from '@/components/ui/CodeChip'
import { Users, Plus, Trash2, Check, Copy, RefreshCw } from 'lucide-react'
import { formatDateTime } from '@/lib/utils'
import { useForm } from 'react-hook-form'

interface ApiKey {
  id: string
  name: string
  tenant_id: string
  key_prefix: string
  policies: string[]
  path_prefixes: string[]
  created_by: string
  created_at: string
  expires_at: string | null
  last_used_at: string | null
  rate_limit_per_minute: number | null
}

interface ApiKeyCreateResponse extends ApiKey {
  key: string
}

interface ApiKeyFormValues {
  name: string
  policies: string
  path_prefixes: string
  expires_in_seconds: string
  rate_limit_per_minute: string
}

const APIKEYS_KEY = '/api/identity/v1/api-keys'

export default function IdentityPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)

  const { data: apiKeys, isLoading } = useSWR<ApiKey[]>(APIKEYS_KEY, fetcher)

  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [formError, setFormError] = useState('')

  const [rotateTarget, setRotateTarget] = useState<ApiKey | null>(null)
  const [rotating, setRotating] = useState(false)
  const [rotatedKeyValue, setRotatedKeyValue] = useState<string | null>(null)

  const [deleteTarget, setDeleteTarget] = useState<ApiKey | null>(null)
  const [deleting, setDeleting] = useState(false)

  const form = useForm<ApiKeyFormValues>({
    defaultValues: { policies: '', path_prefixes: '', expires_in_seconds: '', rate_limit_per_minute: '60' },
  })

  const onCreateKey = async (values: ApiKeyFormValues) => {
    setCreating(true)
    setFormError('')
    try {
      const body: Record<string, unknown> = {
        name: values.name,
        tenant_id: tenantId,
      }
      if (values.policies.trim()) body.policies = values.policies.split(',').map(p => p.trim()).filter(Boolean)
      if (values.path_prefixes.trim()) body.path_prefixes = values.path_prefixes.split(',').map(p => p.trim()).filter(Boolean)
      if (values.expires_in_seconds.trim()) body.expires_in_seconds = parseInt(values.expires_in_seconds)
      if (values.rate_limit_per_minute.trim()) body.rate_limit_per_minute = parseInt(values.rate_limit_per_minute)

      const res = await mutate(APIKEYS_KEY, 'POST', body, token, tenantId) as ApiKeyCreateResponse
      await swrMutate(APIKEYS_KEY)
      setNewKeyValue(res.key)
      form.reset()
      setCreateOpen(false)
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to create API key')
    } finally {
      setCreating(false)
    }
  }

  const onRotate = async () => {
    if (!rotateTarget) return
    setRotating(true)
    try {
      const res = await mutate(
        `${APIKEYS_KEY}/${rotateTarget.id}/rotate`,
        'POST',
        {},
        token,
        tenantId,
      ) as ApiKeyCreateResponse
      await swrMutate(APIKEYS_KEY)
      setRotateTarget(null)
      setRotatedKeyValue(res.key)
    } catch {
      // ignore
    } finally {
      setRotating(false)
    }
  }

  const onDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await mutate(`${APIKEYS_KEY}/${deleteTarget.id}`, 'DELETE', null, token, tenantId)
      await swrMutate(APIKEYS_KEY)
      setDeleteTarget(null)
    } catch {
      // ignore
    } finally {
      setDeleting(false)
    }
  }

  const copyKey = async (val: string) => {
    await navigator.clipboard.writeText(val)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const columns: Column<ApiKey>[] = [
    { field: 'name', label: 'Name', sortable: true },
    {
      field: 'key_prefix',
      label: 'Key Prefix',
      mono: true,
      render: row => (
        <CodeChip value={`wslv_${row.key_prefix}…`} />
      ),
    },
    {
      field: 'policies',
      label: 'Policies',
      render: row => (
        <div className="flex flex-wrap gap-1">
          {row.policies.length > 0
            ? row.policies.map(p => (
                <Badge key={p} variant="info" size="sm">
                  {p}
                </Badge>
              ))
            : <span className="text-xs text-ink-faint">—</span>
          }
        </div>
      ),
    },
    {
      field: 'last_used_at',
      label: 'Last Used',
      render: row => (
        <span className="text-xs text-ink-muted">
          {row.last_used_at ? formatDateTime(row.last_used_at) : 'Never'}
        </span>
      ),
    },
    {
      field: 'expires_at',
      label: 'Expires',
      render: row => (
        <span className="text-xs text-ink-muted">
          {row.expires_at ? formatDateTime(row.expires_at) : 'Never'}
        </span>
      ),
    },
    {
      field: 'rate_limit_per_minute',
      label: 'Rate Limit',
      align: 'right',
      render: row => (
        <span className="text-xs font-mono tabular text-ink-muted">{row.rate_limit_per_minute ?? 60}/min</span>
      ),
    },
    {
      field: '_actions',
      label: '',
      render: row => (
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            aria-label={`Rotate key for ${row.name}`}
            onClick={e => { e.stopPropagation(); setRotateTarget(row) }}
          >
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            aria-label={`Delete key ${row.name}`}
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
        title="Identity & Access"
        description="Manage API keys and access credentials"
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" />
            Create API Key
          </Button>
        }
      />

      {!isLoading && (apiKeys ?? []).length === 0 ? (
        <EmptyState
          icon={Users}
          title="No API keys yet"
          description="Create your first API key to start authenticating requests to the vault."
          action={
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="w-4 h-4" />
              Create API Key
            </Button>
          }
        />
      ) : (
        <DataTable
          columns={columns}
          data={(apiKeys as unknown as Record<string, unknown>[] | undefined) ?? []}
          loading={isLoading}
          keyField="id"
          emptyMessage="No API keys match your search."
        />
      )}

      {/* Create API Key modal */}
      <Modal
        open={createOpen}
        onClose={() => { setCreateOpen(false); form.reset(); setFormError('') }}
        title="Create API key"
        size="md"
        footer={
          <>
            <Button variant="secondary" size="sm" onClick={() => { setCreateOpen(false); form.reset() }}>
              Cancel
            </Button>
            <Button size="sm" loading={creating} onClick={form.handleSubmit(onCreateKey)}>
              Create
            </Button>
          </>
        }
      >
        <form className="space-y-4" onSubmit={form.handleSubmit(onCreateKey)}>
          {formError && <p className="text-sm text-danger-600">{formError}</p>}
          <Input
            label="Name"
            placeholder="my-app-key"
            error={form.formState.errors.name?.message}
            {...form.register('name', { required: 'Name is required' })}
          />
          <Input
            label="Policies (comma-separated)"
            placeholder="admin, read-only"
            {...form.register('policies')}
          />
          <Input
            label="Path prefixes (comma-separated)"
            placeholder="secrets/prod/, secrets/staging/"
            mono
            {...form.register('path_prefixes')}
          />
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Expires in (seconds)"
              placeholder="Leave blank = never"
              type="number"
              {...form.register('expires_in_seconds')}
            />
            <Input
              label="Rate limit / min"
              placeholder="60"
              type="number"
              {...form.register('rate_limit_per_minute')}
            />
          </div>
        </form>
      </Modal>

      {/* Key reveal modal — shown once after creation */}
      <KeyRevealModal
        title="API key created"
        keyValue={newKeyValue}
        copied={copied}
        onCopy={copyKey}
        onClose={() => setNewKeyValue(null)}
      />

      {/* Rotated key reveal modal */}
      <KeyRevealModal
        title="API key rotated"
        keyValue={rotatedKeyValue}
        copied={copied}
        onCopy={copyKey}
        onClose={() => setRotatedKeyValue(null)}
      />

      {/* Rotate confirm */}
      <ConfirmModal
        open={!!rotateTarget}
        onClose={() => setRotateTarget(null)}
        onConfirm={onRotate}
        title="Rotate API key"
        description={`Generate a new secret for "${rotateTarget?.name}"? The existing key will be invalidated immediately.`}
        confirmLabel="Rotate"
        loading={rotating}
      />

      {/* Delete confirm */}
      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={onDelete}
        title="Delete API key"
        description={`Are you sure you want to delete "${deleteTarget?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        loading={deleting}
      />
    </div>
  )
}

function KeyRevealModal({
  title,
  keyValue,
  copied,
  onCopy,
  onClose,
}: {
  title: string
  keyValue: string | null
  copied: boolean
  onCopy: (val: string) => void
  onClose: () => void
}) {
  return (
    <Modal
      open={!!keyValue}
      onClose={onClose}
      title={title}
      size="md"
      footer={<Button onClick={onClose}>Done</Button>}
    >
      <div className="space-y-3">
        {/* One-time warning — uses warn palette for functional status, not decoration */}
        <div className="flex items-start gap-2 p-3 rounded-lg bg-warn-50 border border-warn-100 dark:bg-warn-600/10 dark:border-warn-600/25">
          <span className="text-warn-700 dark:text-warn-500 text-sm font-medium leading-snug">
            This key is shown once. Store it in a safe place now.
          </span>
        </div>

        {/* Revealed key — full-width, mono, selectable, with copy button */}
        <div className="flex items-start gap-2 p-3 rounded-lg border border-line bg-surface-2">
          <code
            className={cn(
              'flex-1 font-mono text-[13px] text-ink break-all select-all leading-relaxed',
            )}
          >
            {keyValue}
          </code>
          <button
            onClick={() => keyValue && onCopy(keyValue)}
            aria-label={copied ? 'Copied' : 'Copy key'}
            className="flex-shrink-0 p-1.5 rounded hover:bg-surface-3 text-ink-faint hover:text-ink transition-colors focus-ring"
          >
            {copied ? <Check className="w-4 h-4 text-success-600" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>
      </div>
    </Modal>
  )
}
