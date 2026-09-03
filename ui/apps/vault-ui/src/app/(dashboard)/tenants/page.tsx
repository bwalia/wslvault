'use client'
import { useState, useCallback } from 'react'
import { mutate as swrMutate } from 'swr'
import { useVaultSWR, useVaultMutate } from '@/hooks/useVaultSWR'
import { useAsyncAction } from '@/hooks/useAsyncAction'
import { api } from '@/lib/api'
import { ErrorBanner, LoadError } from '@/components/ErrorBanner'
import { errorMessage } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { CodeChip } from '@/components/ui/CodeChip'
import { Modal } from '@/components/ui/Modal'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Plus, Trash2, UserPlus, Mail, Check, Copy, AlertCircle } from 'lucide-react'
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

/** What comes back from issuing an invitation. The URL is shown once. */
interface InvitationIssued {
  email: string
  expires_at: string
  invitation_url: string
  email_sent: boolean
  email_error?: string
}

interface TenantFormValues {
  slug: string
  display_name: string
  tier: 'shared' | 'dedicated' | 'sovereign'
  root_key_id: string
  /** Optional. When present, an invitation is sent as soon as the tenant exists. */
  email: string
}

const TENANTS_KEY = api.identity.tenants()

export default function TenantsPage() {
  const vaultMutate = useVaultMutate()
  const { data: tenants, error: loadError, isLoading } = useVaultSWR<Tenant[]>(TENANTS_KEY)

  const [createOpen, setCreateOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Tenant | null>(null)
  const [inviteTarget, setInviteTarget] = useState<Tenant | null>(null)
  const [inviteEmail, setInviteEmail] = useState('')
  /** Set once an invitation is issued. Holds the link, which is shown once. */
  const [issued, setIssued] = useState<InvitationIssued | null>(null)
  const [linkCopied, setLinkCopied] = useState(false)
  /** Set when a tenant was created but its invitation did not send. The tenant
   *  exists, so this must not be reported as a creation failure. */
  const [createdButNotInvited, setCreatedButNotInvited] = useState('')

  const create = useAsyncAction()
  const remove = useAsyncAction()
  const invite = useAsyncAction()

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors },
  } = useForm<TenantFormValues>({ defaultValues: { tier: 'shared' } })

  /** Which derived fields the user has taken over, so we stop writing to them. */
  const [touched, setTouched] = useState({ slug: false, root_key_id: false })

  /** Clear the form *and* the takeover flags — otherwise the next tenant created
   *  in this session inherits the last one's "user edited this" state and
   *  silently stops auto-filling. */
  const resetForm = useCallback(() => {
    reset()
    setTouched({ slug: false, root_key_id: false })
  }, [reset])

  /**
   * Derive slug, and root key id from slug, as the name is typed.
   *
   * Only until the user edits one themselves — overwriting a deliberate slug on
   * the next keystroke in the name field is the classic version of this feature
   * done badly, and the slug cannot be changed after creation, so getting it
   * wrong is permanent.
   */
  const onNameChange = useCallback(
    (name: string) => {
      const slug = name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
      if (!touched.slug) {
        setValue('slug', slug, { shouldValidate: !!slug })
        if (!touched.root_key_id) {
          setValue('root_key_id', slug ? `${slug}-kek` : '', { shouldValidate: !!slug })
        }
      }
    },
    [setValue, touched.slug, touched.root_key_id],
  )

  const onSlugChange = useCallback(
    (slug: string) => {
      if (!touched.root_key_id) {
        setValue('root_key_id', slug ? `${slug}-kek` : '', { shouldValidate: !!slug })
      }
    },
    [setValue, touched.root_key_id],
  )

  const onCreate = useCallback(
    (values: TenantFormValues) => {
      void create.run(
        async () => {
          // `email` is a field of this form, not of the tenant — send only what
          // the tenant API accepts rather than letting an unknown key through.
          const { email, ...tenantFields } = values
          const tenant = (await vaultMutate(TENANTS_KEY, 'POST', tenantFields)) as Tenant
          await swrMutate(TENANTS_KEY)

          const address = email?.trim()
          if (!address) return { tenant, invitation: null, inviteError: '' }

          // The tenant is already created and durable here. An invitation
          // failure is reported on its own rather than thrown, because throwing
          // would surface as "Failed to create tenant" — sending the operator
          // to create a tenant that already exists.
          try {
            const invitation = (await vaultMutate(
              api.identity.tenantInvitations(tenant.id),
              'POST',
              { email: address },
            )) as InvitationIssued
            return { tenant, invitation, inviteError: '' }
          } catch (e) {
            return { tenant, invitation: null, inviteError: errorMessage(e) }
          }
        },
        {
          fallback: 'Failed to create tenant',
          onSuccess: res => {
            setCreateOpen(false)
            resetForm()
            if (res.invitation) {
              // Reuse the invitation modal to show the link, which is the only
              // copy — closing straight to the table would discard it.
              setInviteTarget(res.tenant)
              setIssued(res.invitation)
            } else if (res.inviteError) {
              // Reopen on the invite step with the address kept, so retrying is
              // one click and the tenant is not created twice.
              setInviteTarget(res.tenant)
              setInviteEmail(values.email.trim())
              setCreatedButNotInvited(res.inviteError)
            }
          },
        },
      )
    },
    [create, vaultMutate, resetForm],
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

  const onInvite = useCallback(() => {
    if (!inviteTarget) return
    void invite.run(
      async () =>
        (await vaultMutate(api.identity.tenantInvitations(inviteTarget.id), 'POST', {
          email: inviteEmail.trim(),
        })) as InvitationIssued,
      {
        fallback: 'Failed to send the invitation',
        // Deliberately does NOT close the modal: the link is returned once and
        // is the only copy. Closing on success would throw it away in the case
        // that matters most — when the email did not send.
        onSuccess: res => setIssued(res),
      },
    )
  }, [invite, inviteTarget, inviteEmail, vaultMutate])

  const closeInvite = useCallback(() => {
    setInviteTarget(null)
    setInviteEmail('')
    setIssued(null)
    setLinkCopied(false)
    setCreatedButNotInvited('')
    invite.clearError()
  }, [invite])

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
        <div className="flex items-center justify-end gap-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={e => { e.stopPropagation(); setInviteTarget(row) }}
            aria-label={`Invite tenant ${row.display_name}`}
          >
            <UserPlus className="w-4 h-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={e => { e.stopPropagation(); setDeleteTarget(row) }}
            className="text-danger-600 hover:bg-danger-50"
            aria-label={`Delete tenant ${row.display_name}`}
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
        onClose={() => { setCreateOpen(false); resetForm(); create.clearError() }}
        title="Create Tenant"
        size="md"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              disabled={create.pending}
              onClick={() => { setCreateOpen(false); resetForm(); create.clearError() }}
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
            label="Display Name"
            placeholder="My Tenant"
            hint="Human-readable name shown in the UI."
            error={errors.display_name?.message}
            {...register('display_name', {
              required: 'Display name is required',
              onChange: e => onNameChange(e.target.value),
            })}
          />
          <Input
            label="Slug"
            placeholder="my-tenant"
            mono
            hint="A short, URL-safe identifier. Filled in from the name — edit it if you want something different. Cannot be changed after creation."
            error={errors.slug?.message}
            {...register('slug', {
              required: 'Slug is required',
              // Only flip the flag on the first edit: returning the same object
              // when it is already set lets React bail out of the re-render.
              onChange: e => {
                setTouched(t => (t.slug ? t : { ...t, slug: true }))
                onSlugChange(e.target.value)
              },
            })}
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
            label="Root Key ID"
            placeholder="my-tenant-kek"
            mono
            hint="Names the key-encryption key this tenant's material is filed under. Filled in from the slug; change it only if you are pointing at a specific KMS key."
            error={errors.root_key_id?.message}
            {...register('root_key_id', {
              required: 'Root key ID is required',
              onChange: () =>
                setTouched(t => (t.root_key_id ? t : { ...t, root_key_id: true })),
            })}
          />
          <div className="pt-1 border-t border-line">
            <Input
              label="Tenant's email (optional)"
              type="email"
              placeholder="contact@their-company.com"
              hint="Where to send this tenant's invitation. They get a one-time link that mints their access key and sets up their authenticator app. Leave blank to send it later from the tenant list."
              error={errors.email?.message}
              {...register('email', {
                // Validated here as well as server-side so a typo is caught
                // before the tenant is created — the tenant would exist and the
                // invitation would not, which is a confusing half-done state.
                validate: v =>
                  !v?.trim() || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim())
                    ? true
                    : 'That does not look like an email address',
              })}
            />
          </div>
        </form>
      </Modal>

      {/* Invite modal */}
      <Modal
        open={!!inviteTarget}
        onClose={closeInvite}
        title={
          issued
            ? 'Invitation sent'
            : `Invite ${inviteTarget?.display_name ?? 'tenant'}`
        }
        size="md"
        footer={
          issued ? (
            <Button size="sm" onClick={closeInvite}>Done</Button>
          ) : (
            <>
              <Button variant="secondary" size="sm" disabled={invite.pending} onClick={closeInvite}>
                Cancel
              </Button>
              <Button
                size="sm"
                loading={invite.pending}
                disabled={!inviteEmail.trim()}
                onClick={onInvite}
              >
                <Mail className="w-4 h-4" />
                Send invitation
              </Button>
            </>
          )
        }
      >
        {issued ? (
          <div className="space-y-4">
            {issued.email_sent ? (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-success-50 border border-success-100 dark:bg-success-600/10 dark:border-success-600/25">
                <Check className="w-4 h-4 shrink-0 mt-0.5 text-success-700 dark:text-success-500" />
                <p className="text-sm text-success-700 dark:text-success-500">
                  Emailed to <strong>{issued.email}</strong>.
                </p>
              </div>
            ) : (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-warn-50 border border-warn-100 dark:bg-warn-600/10 dark:border-warn-600/25">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-warn-700 dark:text-warn-500" />
                <div className="text-sm text-warn-700 dark:text-warn-500">
                  <p className="font-medium">The email was not sent — send this link yourself.</p>
                  {issued.email_error && (
                    <p className="mt-0.5 opacity-90">{issued.email_error}</p>
                  )}
                </div>
              </div>
            )}

            <div>
              <p className="text-sm font-medium text-ink mb-1.5">Invitation link</p>
              <div className="flex items-start gap-2 p-3 rounded-lg border border-line bg-surface-2">
                <code className="flex-1 font-mono text-[13px] text-ink break-all select-all leading-relaxed">
                  {issued.invitation_url}
                </code>
                <button
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(issued.invitation_url)
                      setLinkCopied(true)
                      setTimeout(() => setLinkCopied(false), 2000)
                    } catch {
                      /* Selectable above; the user can copy by hand. */
                    }
                  }}
                  aria-label={linkCopied ? 'Copied' : 'Copy invitation link'}
                  className="shrink-0 p-1.5 rounded hover:bg-surface-3 text-ink-faint hover:text-ink transition-colors focus-ring"
                >
                  {linkCopied ? <Check className="w-4 h-4 text-success-600" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
              <p className="mt-1.5 text-xs text-ink-muted leading-relaxed">
                Shown once — only a hash of it is stored. It works a single time and expires{' '}
                {formatDateTime(issued.expires_at)}.
              </p>
            </div>
          </div>
        ) : (
          <form
            className="space-y-4"
            onSubmit={e => { e.preventDefault(); onInvite() }}
          >
            {createdButNotInvited && (
              <div className="flex items-start gap-2 p-3 rounded-lg bg-warn-50 border border-warn-100 dark:bg-warn-600/10 dark:border-warn-600/25">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-warn-700 dark:text-warn-500" />
                <div className="text-sm text-warn-700 dark:text-warn-500">
                  <p className="font-medium">
                    The tenant was created, but the invitation was not sent.
                  </p>
                  <p className="mt-0.5 opacity-90">{createdButNotInvited}</p>
                  <p className="mt-1 opacity-90">
                    Do not create it again — send the invitation from here.
                  </p>
                </div>
              </div>
            )}
            <ErrorBanner message={invite.error} onDismiss={invite.clearError} />
            <Input
              label="Tenant's email"
              type="email"
              placeholder="contact@their-company.com"
              value={inviteEmail}
              onChange={e => setInviteEmail(e.target.value)}
              hint="Where to send this tenant's invitation. They receive a one-time link that mints their access key and sets up their authenticator app."
            />
          </form>
        )}
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
