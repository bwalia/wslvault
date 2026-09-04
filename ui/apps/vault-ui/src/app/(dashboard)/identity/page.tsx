'use client'
import { useState, useCallback } from 'react'
import { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
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
  mfa_required?: boolean
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
  mfa_required: boolean
}

const APIKEYS_KEY = api.identity.apiKeys()

/**
 * Narrow an API-key mutation response, or explain why it can't be trusted.
 *
 * `mutate` resolves `T | null`, and the old code cast that straight to
 * `ApiKeyCreateResponse` before reading `.key`. On any unexpected body that
 * threw a TypeError into an empty catch — and for *rotate* the consequence is
 * unrecoverable: the server has already invalidated the old key, so a
 * discarded new key locks the caller out permanently. Validate before trusting.
 */
function requireKeyResponse(res: unknown): ApiKeyCreateResponse {
  if (!res || typeof res !== 'object') {
    throw new Error('Identity service returned an empty response — the key was not returned.')
  }
  const key = (res as { key?: unknown }).key
  if (typeof key !== 'string' || !key) {
    throw new Error('Identity service response contained no key value.')
  }
  return res as ApiKeyCreateResponse
}

export default function IdentityPage() {
  const { tenantId } = useAuth()
  const vaultMutate = useVaultMutate()

  const { data: apiKeys, error: loadError, isLoading } = useVaultSWR<ApiKey[]>(APIKEYS_KEY)

  const [createOpen, setCreateOpen] = useState(false)
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null)
  /** Whether the key just created will demand an authenticator, so the reveal
   *  can hand over the enrolment link alongside it. */
  const [newKeyNeedsEnrolment, setNewKeyNeedsEnrolment] = useState(false)
  const [copied, setCopied] = useState(false)
  const [enrolmentCopied, setEnrolmentCopied] = useState(false)
  const [copyError, setCopyError] = useState('')

  const [rotateTarget, setRotateTarget] = useState<ApiKey | null>(null)
  const [rotatedKeyValue, setRotatedKeyValue] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ApiKey | null>(null)

  const create = useAsyncAction()
  const rotate = useAsyncAction()
  const remove = useAsyncAction()

  const form = useForm<ApiKeyFormValues>({
    // MFA defaults OFF so a new key can sign in straight away, and the holder
    // turns it on for themselves from the MFA page — confirming an enrolment
    // sets `mfa_required` (mfa_store::confirm). Demanding it up front would
    // hand people a key that cannot log in until it is enrolled, which is the
    // right posture only when someone deliberately chooses it.
    defaultValues: {
      policies: '',
      path_prefixes: '',
      expires_in_seconds: '',
      rate_limit_per_minute: '60',
      mfa_required: false,
    },
  })

  const onCreateKey = useCallback(
    (values: ApiKeyFormValues) => {
      void create.run(
        async () => {
          const body: Record<string, unknown> = {
            name: values.name,
            tenant_id: tenantId,
            mfa_required: values.mfa_required,
          }
          if (values.policies.trim())
            body.policies = values.policies.split(',').map(p => p.trim()).filter(Boolean)
          if (values.path_prefixes.trim())
            body.path_prefixes = values.path_prefixes.split(',').map(p => p.trim()).filter(Boolean)

          // parseInt returns NaN on junk, and JSON.stringify turns NaN into
          // null — the server then sees an explicit null rather than "unset".
          if (values.expires_in_seconds.trim()) {
            const n = Number.parseInt(values.expires_in_seconds, 10)
            if (!Number.isFinite(n) || n <= 0) throw new Error('Expiry must be a positive number of seconds')
            body.expires_in_seconds = n
          }
          if (values.rate_limit_per_minute.trim()) {
            const n = Number.parseInt(values.rate_limit_per_minute, 10)
            if (!Number.isFinite(n) || n < 0) throw new Error('Rate limit must be a non-negative number')
            body.rate_limit_per_minute = n
          }

          const res = requireKeyResponse(await vaultMutate(APIKEYS_KEY, 'POST', body))
          await swrMutate(APIKEYS_KEY)
          return res
        },
        {
          fallback: 'Failed to create API key',
          onSuccess: res => {
            setNewKeyValue(res.key)
            // Captured from the submitted values, not read back off the form:
            // `reset()` on the next line would clear it first.
            setNewKeyNeedsEnrolment(values.mfa_required)
            form.reset()
            setCreateOpen(false)
          },
        },
      )
    },
    [create, vaultMutate, tenantId, form],
  )

  const onRotate = useCallback(() => {
    if (!rotateTarget) return
    void rotate.run(
      async () => {
        const res = requireKeyResponse(
          await vaultMutate(api.identity.rotateApiKey(rotateTarget.id), 'POST', {}),
        )
        await swrMutate(APIKEYS_KEY)
        return res
      },
      {
        fallback: 'Failed to rotate API key',
        onSuccess: res => {
          // Reveal the new key BEFORE dismissing the modal. If this ordering is
          // ever reversed and the reveal throws, the only copy of the new key
          // is gone and the old one is already dead server-side.
          setRotatedKeyValue(res.key)
          setRotateTarget(null)
        },
      },
    )
  }, [rotate, rotateTarget, vaultMutate])

  const onDelete = useCallback(() => {
    if (!deleteTarget) return
    void remove.run(
      async () => {
        await vaultMutate(api.identity.apiKey(deleteTarget.id), 'DELETE')
        await swrMutate(APIKEYS_KEY)
      },
      { fallback: 'Failed to revoke API key', onSuccess: () => setDeleteTarget(null) },
    )
  }, [remove, deleteTarget, vaultMutate])

  const copyKey = useCallback(async (val: string, which: 'key' | 'enrolment' = 'key') => {
    // clipboard.writeText rejects on an insecure origin (plain HTTP) or a denied
    // permission. Unhandled, the user believes a one-time key is on their
    // clipboard when it is not — and it is not shown again.
    try {
      await navigator.clipboard.writeText(val)
      setCopyError('')
      if (which === 'enrolment') {
        setEnrolmentCopied(true)
        setTimeout(() => setEnrolmentCopied(false), 2000)
      } else {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
      }
    } catch {
      setCopyError('Could not copy — select the key and copy it manually.')
    }
  }, [])

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
      // `policies` is typed non-optional but arrives from the network. If the
      // server ever omits it, `.length` throws mid-render and takes the whole
      // page to the error boundary over a cosmetic column.
      render: row => (
        <div className="flex flex-wrap gap-1">
          {(row.policies ?? []).length > 0
            ? (row.policies ?? []).map(p => (
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
      field: 'mfa_required',
      label: 'MFA',
      render: row =>
        row.mfa_required ? (
          <Badge variant="success" size="sm">Required</Badge>
        ) : (
          <span className="text-xs text-ink-faint">Off</span>
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
        guide={
          <>
            <p>
              An <strong>API key</strong> is how someone signs in — a person through this
              console, or a service from its own code.
            </p>
            <p>
              Keys are shown once, when created, and never again. Only a
              fingerprint is stored, so if one is lost it must be replaced rather
              than recovered.
            </p>
            <p>
              <strong>Rotate</strong> issues a fresh key and retires the old one.
              <strong> Revoke</strong> stops a key working immediately.
            </p>
          </>
        }
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" />
            Create API Key
          </Button>
        }
      />

      {/* A failed load must not render as "No API keys yet" — that reads as a
          confident empty vault when the truth may be a 403 or a dead backend. */}
      {loadError ? (
        <LoadError error={loadError} what="API keys" />
      ) : !isLoading && (apiKeys ?? []).length === 0 ? (
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
        onClose={() => { setCreateOpen(false); form.reset(); create.clearError() }}
        title="Create API key"
        size="md"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              disabled={create.pending}
              onClick={() => { setCreateOpen(false); form.reset(); create.clearError() }}
            >
              Cancel
            </Button>
            <Button size="sm" loading={create.pending} onClick={form.handleSubmit(onCreateKey)}>
              Create
            </Button>
          </>
        }
      >
        <form className="space-y-4" onSubmit={form.handleSubmit(onCreateKey)}>
          <ErrorBanner message={create.error} onDismiss={create.clearError} />
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
          <div className="flex items-start gap-2.5 p-3 rounded-lg border border-line bg-surface-2">
            <input
              id="mfa-required"
              type="checkbox"
              className="mt-0.5 w-4 h-4 rounded border-line-strong text-primary-600 focus-ring"
              {...form.register('mfa_required')}
            />
            <label htmlFor="mfa-required" className="text-sm leading-snug">
              <span className="font-medium text-ink">
                Require an authenticator app before this key can sign in
              </span>
              <span className="block text-ink-muted mt-0.5">
                Leave this off and the holder can sign in immediately, then turn on
                MFA themselves from the MFA page. Tick it to insist they set up an
                authenticator first — they will need the enrolment link to do so.
              </span>
            </label>
          </div>
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
        enrolmentCopied={enrolmentCopied}
        copyError={copyError}
        onCopy={copyKey}
        onClose={() => setNewKeyValue(null)}
        showEnrolmentLink={newKeyNeedsEnrolment}
      />

      {/* Rotated key reveal modal */}
      <KeyRevealModal
        title="API key rotated"
        keyValue={rotatedKeyValue}
        copied={copied}
        copyError={copyError}
        onCopy={copyKey}
        onClose={() => setRotatedKeyValue(null)}
      />

      {/* Rotate confirm */}
      <ConfirmModal
        open={!!rotateTarget}
        onClose={() => { setRotateTarget(null); rotate.clearError() }}
        onConfirm={onRotate}
        title="Rotate API key"
        description={`Generate a new secret for "${rotateTarget?.name}"? The existing key will be invalidated immediately.`}
        confirmLabel="Rotate"
        loading={rotate.pending}
        error={rotate.error}
      />

      {/* Delete confirm */}
      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => { setDeleteTarget(null); remove.clearError() }}
        onConfirm={onDelete}
        title="Delete API key"
        description={`Are you sure you want to delete "${deleteTarget?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        loading={remove.pending}
        error={remove.error}
      />
    </div>
  )
}

function KeyRevealModal({
  title,
  keyValue,
  copied,
  enrolmentCopied = false,
  copyError,
  onCopy,
  onClose,
  showEnrolmentLink = false,
}: {
  title: string
  keyValue: string | null
  copied: boolean
  /** Independent of `copied` so copying the enrolment link does not flash
   *  the checkmark on the key button. */
  enrolmentCopied?: boolean
  /** Clipboard failure. Critical here: the key is shown exactly once, so a
   *  silent copy failure means the user walks away with nothing. */
  copyError?: string
  onCopy: (val: string, which?: 'key' | 'enrolment') => void
  onClose: () => void
  /** Show the hand-over instructions for a key that will demand an
   *  authenticator. Without them the operator has the key but no idea that the
   *  recipient also needs somewhere to enrol. */
  showEnrolmentLink?: boolean
}) {
  // Read at render rather than module scope: the deployment's own hostname is
  // what the recipient must open, and it is not known at build time.
  const enrolmentUrl =
    typeof window === 'undefined' ? '/enroll' : `${window.location.origin}/enroll`
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
              'flex-1 font-mono text-sm text-ink break-all select-all leading-relaxed',
            )}
          >
            {keyValue}
          </code>
          <button
            onClick={() => keyValue && onCopy(keyValue, 'key')}
            aria-label={copied ? 'Copied' : 'Copy key'}
            className="shrink-0 p-1.5 rounded hover:bg-surface-3 text-ink-faint hover:text-ink transition-colors focus-ring"
          >
            {copied ? <Check className="w-4 h-4 text-success-600" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>

        {copyError && (
          <p role="alert" className="text-xs text-danger-600">
            {copyError}
          </p>
        )}

        {showEnrolmentLink && (
          <div className="pt-1 space-y-2">
            <p className="text-sm font-medium text-ink">Send the holder both of these</p>
            <div className="flex items-start gap-2 p-3 rounded-lg border border-line bg-surface-2">
              <code className="flex-1 font-mono text-sm text-ink break-all select-all leading-relaxed">
                {enrolmentUrl}
              </code>
              <button
                onClick={() => onCopy(enrolmentUrl, 'enrolment')}
                aria-label={enrolmentCopied ? 'Copied enrolment link' : 'Copy enrolment link'}
                className="shrink-0 p-1.5 rounded hover:bg-surface-3 text-ink-faint hover:text-ink transition-colors focus-ring"
              >
                {enrolmentCopied ? (
                  <Check className="w-4 h-4 text-success-600" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
            <p className="text-xs text-ink-muted leading-relaxed">
              The link is public and holds no secret, so it can go anywhere. Send the
              key itself through a password manager or another channel meant for
              secrets — not in the same message, so that one intercepted message is
              never enough on its own.
            </p>
          </div>
        )}
      </div>
    </Modal>
  )
}
