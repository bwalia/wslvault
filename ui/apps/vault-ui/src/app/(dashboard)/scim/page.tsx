'use client'
import { useState, useCallback } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { mutate, errorMessage } from '@/lib/fetcher'
import { useFetcher } from '@/hooks/useVaultSWR'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { DataTable, Column } from '@/components/ui/DataTable'
import { Modal } from '@/components/ui/Modal'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Users, Plus, Trash2, Pencil, UsersRound } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { formatDateTime, cn } from '@/lib/utils'

// ---------------------------------------------------------------------------
// SCIM type definitions (RFC 7644 / RFC 7643)
// ---------------------------------------------------------------------------

interface ScimMeta {
  resourceType: string
  created?: string
  lastModified?: string
  location?: string
  version?: string
}

interface ScimName {
  formatted?: string
  familyName?: string
  givenName?: string
}

interface ScimEmail {
  value: string
  type?: string
  primary?: boolean
}

interface ScimUser {
  id: string
  externalId?: string
  userName: string
  displayName?: string
  name?: ScimName
  emails?: ScimEmail[]
  active: boolean
  meta?: ScimMeta
}

interface ScimMember {
  value: string
  display?: string
  $ref?: string
}

interface ScimGroup {
  id: string
  externalId?: string
  displayName: string
  members?: ScimMember[]
  meta?: ScimMeta
}

interface ScimListResponse<T> {
  totalResults: number
  itemsPerPage: number
  startIndex: number
  Resources: T[]
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

// SCIM lives on identity-service at /scim/v2/*, not on the gateway proxy
// (which points at region-health). /api/identity/* is the right rewrite.
const USERS_KEY = '/api/identity/scim/v2/Users'
const GROUPS_KEY = '/api/identity/scim/v2/Groups'

// ---------------------------------------------------------------------------
// Form types
// ---------------------------------------------------------------------------

interface UserFormValues {
  userName: string
  displayName: string
  givenName: string
  familyName: string
  email: string
  active: boolean
}

interface GroupFormValues {
  displayName: string
  memberIds: string // comma-separated user IDs
}

// ---------------------------------------------------------------------------
// Helper: primary email
// ---------------------------------------------------------------------------

function primaryEmail(user: ScimUser): string {
  const primary = user.emails?.find(e => e.primary)
  return primary?.value ?? user.emails?.[0]?.value ?? '—'
}

// ---------------------------------------------------------------------------
// Users tab
// ---------------------------------------------------------------------------

function UsersTab() {
  const { token, tenantId } = useAuth()
  const fetcher = useFetcher()

  const { data, isLoading } = useSWR<ScimListResponse<ScimUser>>(USERS_KEY, fetcher)
  const users: ScimUser[] = data?.Resources ?? []

  const [createOpen, setCreateOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<ScimUser | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ScimUser | null>(null)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  const [formError, setFormError] = useState('')

  const form = useForm<UserFormValues>({
    defaultValues: {
      userName: '',
      displayName: '',
      givenName: '',
      familyName: '',
      email: '',
      active: true,
    },
  })

  const openCreate = useCallback(() => {
    form.reset({
      userName: '',
      displayName: '',
      givenName: '',
      familyName: '',
      email: '',
      active: true,
    })
    setFormError('')
    setCreateOpen(true)
  }, [form])

  const openEdit = useCallback(
    (user: ScimUser) => {
      form.reset({
        userName: user.userName,
        displayName: user.displayName ?? '',
        givenName: user.name?.givenName ?? '',
        familyName: user.name?.familyName ?? '',
        email: primaryEmail(user) === '—' ? '' : primaryEmail(user),
        active: user.active,
      })
      setFormError('')
      setEditTarget(user)
    },
    [form],
  )

  const buildUserPayload = (values: UserFormValues) => ({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName: values.userName,
    displayName: values.displayName || undefined,
    name: {
      givenName: values.givenName || undefined,
      familyName: values.familyName || undefined,
      formatted:
        [values.givenName, values.familyName].filter(Boolean).join(' ') || undefined,
    },
    emails: values.email
      ? [{ value: values.email, type: 'work', primary: true }]
      : undefined,
    active: values.active,
  })

  const onCreateUser = async (values: UserFormValues) => {
    setSaving(true)
    setFormError('')
    try {
      await mutate(USERS_KEY, 'POST', buildUserPayload(values), token, tenantId)
      await swrMutate(USERS_KEY)
      setCreateOpen(false)
      form.reset()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to create user')
    } finally {
      setSaving(false)
    }
  }

  const onEditUser = async (values: UserFormValues) => {
    if (!editTarget) return
    setSaving(true)
    setFormError('')
    try {
      await mutate(
        `${USERS_KEY}/${editTarget.id}`,
        'PUT',
        { id: editTarget.id, ...buildUserPayload(values) },
        token,
        tenantId,
      )
      await swrMutate(USERS_KEY)
      setEditTarget(null)
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to update user')
    } finally {
      setSaving(false)
    }
  }

  const onDeleteUser = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    setDeleteError('')
    try {
      await mutate(`${USERS_KEY}/${deleteTarget.id}`, 'DELETE', null, token, tenantId)
      await swrMutate(USERS_KEY)
      setDeleteTarget(null)
    } catch (err) {
      // "The user stays in the list" was the whole problem: deprovisioning a
      // user is a security action, and a silent failure means an operator
      // believes access is gone when it is not.
      setDeleteError(errorMessage(err, 'Failed to delete user'))
    } finally {
      setDeleting(false)
    }
  }

  const columns: Column<ScimUser>[] = [
    {
      field: 'userName',
      label: 'Username',
      sortable: true,
      render: row => (
        <span className="font-mono text-[13px] text-ink">{row.userName}</span>
      ),
    },
    {
      field: 'displayName',
      label: 'Display Name',
      sortable: true,
      render: row => <span className="text-ink">{row.displayName ?? '—'}</span>,
    },
    {
      field: 'email',
      label: 'Email',
      render: row => (
        <span className="font-mono text-[13px] text-ink-muted">{primaryEmail(row)}</span>
      ),
    },
    {
      field: 'active',
      label: 'Status',
      render: row => <StatusBadge status={row.active ? 'active' : 'inactive'} />,
    },
    {
      field: 'meta.lastModified',
      label: 'Last Modified',
      render: row => (
        <span className="text-xs text-ink-muted tabular">
          {row.meta?.lastModified ? formatDateTime(row.meta.lastModified) : '—'}
        </span>
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
            onClick={e => {
              e.stopPropagation()
              openEdit(row)
            }}
            aria-label={`Edit user ${row.userName}`}
          >
            <Pencil className="w-4 h-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={e => {
              e.stopPropagation()
              setDeleteTarget(row)
            }}
            className="text-danger-600 hover:bg-danger-50"
            aria-label={`Delete user ${row.userName}`}
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold text-ink flex items-center gap-2">
          Users
          <Badge variant="default" size="sm">
            {data?.totalResults ?? users.length}
          </Badge>
        </h2>
        <Button size="sm" onClick={openCreate}>
          <Plus className="w-4 h-4" />
          New User
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={users as unknown as Record<string, unknown>[]}
        loading={isLoading}
        keyField="id"
        emptyMessage="No SCIM users provisioned. Add your first user to begin."
      />

      {/* Create user modal */}
      <Modal
        open={createOpen}
        onClose={() => {
          setCreateOpen(false)
          form.reset()
          setFormError('')
        }}
        title="Create SCIM User"
        size="md"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setCreateOpen(false)
                form.reset()
              }}
            >
              Cancel
            </Button>
            <Button size="sm" loading={saving} onClick={form.handleSubmit(onCreateUser)}>
              Create
            </Button>
          </>
        }
      >
        <UserForm form={form} formError={formError} onSubmit={onCreateUser} />
      </Modal>

      {/* Edit user modal */}
      <Modal
        open={!!editTarget}
        onClose={() => {
          setEditTarget(null)
          setFormError('')
        }}
        title={`Edit User: ${editTarget?.userName ?? ''}`}
        size="md"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditTarget(null)}
            >
              Cancel
            </Button>
            <Button size="sm" loading={saving} onClick={form.handleSubmit(onEditUser)}>
              Save
            </Button>
          </>
        }
      >
        <UserForm form={form} formError={formError} onSubmit={onEditUser} />
      </Modal>

      {/* Delete confirm */}
      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => { setDeleteTarget(null); setDeleteError('') }}
        onConfirm={onDeleteUser}
        title="Delete SCIM User"
        description={`Permanently delete user "${deleteTarget?.userName}"? This cannot be undone.`}
        confirmLabel="Delete"
        loading={deleting}
        error={deleteError}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Shared user form body (used by both create and edit modals)
// ---------------------------------------------------------------------------

function UserForm({
  form,
  formError,
  onSubmit,
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  form: ReturnType<typeof useForm<UserFormValues>>
  formError: string
  onSubmit: (values: UserFormValues) => Promise<void>
}) {
  return (
    <form className="space-y-4" onSubmit={form.handleSubmit(onSubmit)}>
      {formError && <p className="text-sm text-danger-600">{formError}</p>}
      <Input
        label="Username"
        placeholder="jdoe"
        mono
        error={form.formState.errors.userName?.message}
        {...form.register('userName', { required: 'Username is required' })}
      />
      <Input
        label="Display Name"
        placeholder="John Doe"
        {...form.register('displayName')}
      />
      <div className="grid grid-cols-2 gap-3">
        <Input
          label="Given Name"
          placeholder="John"
          {...form.register('givenName')}
        />
        <Input
          label="Family Name"
          placeholder="Doe"
          {...form.register('familyName')}
        />
      </div>
      <Input
        label="Email"
        type="email"
        placeholder="john@example.com"
        {...form.register('email')}
      />
      <div className="flex items-center gap-2">
        <input
          type="checkbox"
          id="active-checkbox"
          className="w-4 h-4 rounded border-line-strong text-primary-600 focus:ring-primary-500"
          {...form.register('active')}
        />
        <label
          htmlFor="active-checkbox"
          className="text-sm font-medium text-ink"
        >
          Active
        </label>
      </div>
    </form>
  )
}

// ---------------------------------------------------------------------------
// Groups tab
// ---------------------------------------------------------------------------

function GroupsTab() {
  const { token, tenantId } = useAuth()
  const fetcher = useFetcher()

  const { data, isLoading } = useSWR<ScimListResponse<ScimGroup>>(GROUPS_KEY, fetcher)
  const groups: ScimGroup[] = data?.Resources ?? []

  const [createOpen, setCreateOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<ScimGroup | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<ScimGroup | null>(null)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState('')
  const [formError, setFormError] = useState('')

  const form = useForm<GroupFormValues>({
    defaultValues: { displayName: '', memberIds: '' },
  })

  const openCreate = useCallback(() => {
    form.reset({ displayName: '', memberIds: '' })
    setFormError('')
    setCreateOpen(true)
  }, [form])

  const openEdit = useCallback(
    (group: ScimGroup) => {
      form.reset({
        displayName: group.displayName,
        memberIds: (group.members ?? []).map(m => m.value).join(', '),
      })
      setFormError('')
      setEditTarget(group)
    },
    [form],
  )

  const buildGroupPayload = (values: GroupFormValues) => ({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    displayName: values.displayName,
    members: values.memberIds
      ? values.memberIds
          .split(',')
          .map(id => id.trim())
          .filter(Boolean)
          .map(id => ({ value: id }))
      : [],
  })

  const onCreateGroup = async (values: GroupFormValues) => {
    setSaving(true)
    setFormError('')
    try {
      await mutate(GROUPS_KEY, 'POST', buildGroupPayload(values), token, tenantId)
      await swrMutate(GROUPS_KEY)
      setCreateOpen(false)
      form.reset()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to create group')
    } finally {
      setSaving(false)
    }
  }

  const onEditGroup = async (values: GroupFormValues) => {
    if (!editTarget) return
    setSaving(true)
    setFormError('')
    try {
      await mutate(
        `${GROUPS_KEY}/${editTarget.id}`,
        'PUT',
        { id: editTarget.id, ...buildGroupPayload(values) },
        token,
        tenantId,
      )
      await swrMutate(GROUPS_KEY)
      setEditTarget(null)
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to update group')
    } finally {
      setSaving(false)
    }
  }

  const onDeleteGroup = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    setDeleteError('')
    try {
      await mutate(`${GROUPS_KEY}/${deleteTarget.id}`, 'DELETE', null, token, tenantId)
      await swrMutate(GROUPS_KEY)
      setDeleteTarget(null)
    } catch (err) {
      setDeleteError(errorMessage(err, 'Failed to delete group'))
    } finally {
      setDeleting(false)
    }
  }

  const columns: Column<ScimGroup>[] = [
    {
      field: 'displayName',
      label: 'Group Name',
      sortable: true,
      render: row => (
        <span className="font-medium text-ink">{row.displayName}</span>
      ),
    },
    {
      field: 'members',
      label: 'Members',
      render: row => {
        const memberList = row.members ?? []
        if (memberList.length === 0) {
          return <span className="text-xs text-ink-faint">No members</span>
        }
        const displayed = memberList.slice(0, 4)
        const overflow = memberList.length - displayed.length
        return (
          <div className="flex flex-wrap gap-1">
            {displayed.map(m => (
              <Badge key={m.value} variant="default" size="sm" className="font-mono text-[13px]">
                {m.display ?? m.value}
              </Badge>
            ))}
            {overflow > 0 && (
              <Badge variant="default" size="sm">
                +{overflow} more
              </Badge>
            )}
          </div>
        )
      },
    },
    {
      field: 'memberCount',
      label: 'Count',
      render: row => (
        <Badge variant="default" size="sm">
          {(row.members ?? []).length}
        </Badge>
      ),
    },
    {
      field: 'meta.lastModified',
      label: 'Last Modified',
      render: row => (
        <span className="text-xs text-ink-muted tabular">
          {row.meta?.lastModified ? formatDateTime(row.meta.lastModified) : '—'}
        </span>
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
            onClick={e => {
              e.stopPropagation()
              openEdit(row)
            }}
            aria-label={`Edit group ${row.displayName}`}
          >
            <Pencil className="w-4 h-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={e => {
              e.stopPropagation()
              setDeleteTarget(row)
            }}
            className="text-danger-600 hover:bg-danger-50"
            aria-label={`Delete group ${row.displayName}`}
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold text-ink flex items-center gap-2">
          Groups
          <Badge variant="default" size="sm">
            {data?.totalResults ?? groups.length}
          </Badge>
        </h2>
        <Button size="sm" onClick={openCreate}>
          <Plus className="w-4 h-4" />
          New Group
        </Button>
      </div>

      <DataTable
        columns={columns}
        data={groups as unknown as Record<string, unknown>[]}
        loading={isLoading}
        keyField="id"
        emptyMessage="No SCIM groups defined. Create a group to manage user access."
      />

      {/* Create group modal */}
      <Modal
        open={createOpen}
        onClose={() => {
          setCreateOpen(false)
          form.reset()
          setFormError('')
        }}
        title="Create SCIM Group"
        size="md"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setCreateOpen(false)
                form.reset()
              }}
            >
              Cancel
            </Button>
            <Button size="sm" loading={saving} onClick={form.handleSubmit(onCreateGroup)}>
              Create
            </Button>
          </>
        }
      >
        <GroupForm form={form} formError={formError} onSubmit={onCreateGroup} />
      </Modal>

      {/* Edit group modal */}
      <Modal
        open={!!editTarget}
        onClose={() => {
          setEditTarget(null)
          setFormError('')
        }}
        title={`Edit Group: ${editTarget?.displayName ?? ''}`}
        size="md"
        footer={
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setEditTarget(null)}
            >
              Cancel
            </Button>
            <Button size="sm" loading={saving} onClick={form.handleSubmit(onEditGroup)}>
              Save
            </Button>
          </>
        }
      >
        <GroupForm form={form} formError={formError} onSubmit={onEditGroup} />
      </Modal>

      {/* Delete confirm */}
      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => { setDeleteTarget(null); setDeleteError('') }}
        onConfirm={onDeleteGroup}
        title="Delete SCIM Group"
        description={`Permanently delete group "${deleteTarget?.displayName}"? This cannot be undone.`}
        confirmLabel="Delete"
        loading={deleting}
        error={deleteError}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Shared group form body
// ---------------------------------------------------------------------------

function GroupForm({
  form,
  formError,
  onSubmit,
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  form: ReturnType<typeof useForm<GroupFormValues>>
  formError: string
  onSubmit: (values: GroupFormValues) => Promise<void>
}) {
  return (
    <form className="space-y-4" onSubmit={form.handleSubmit(onSubmit)}>
      {formError && <p className="text-sm text-danger-600">{formError}</p>}
      <Input
        label="Display Name"
        placeholder="engineering"
        error={form.formState.errors.displayName?.message}
        {...form.register('displayName', { required: 'Display name is required' })}
      />
      <div className="space-y-1.5">
        <label className="block text-sm font-medium text-ink">
          Member User IDs{' '}
          <span className="text-ink-faint font-normal">(comma-separated)</span>
        </label>
        <textarea
          rows={4}
          placeholder="user-id-1, user-id-2, user-id-3"
          className="w-full px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm font-mono placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500 transition-colors resize-none"
          {...form.register('memberIds')}
        />
        <p className="text-xs text-ink-faint">
          Enter the SCIM user IDs of group members, separated by commas.
        </p>
      </div>
    </form>
  )
}

// ---------------------------------------------------------------------------
// Page root — tabbed layout (Users / Groups)
// ---------------------------------------------------------------------------

type Tab = 'users' | 'groups'

export default function ScimPage() {
  const [activeTab, setActiveTab] = useState<Tab>('users')

  return (
    <div>
      <PageHeader
        title="SCIM Administration"
        description="Manage users and groups via SCIM 2.0 (RFC 7644)"
      />

      {/* Quiet segmented control */}
      <div className="flex gap-0.5 mb-6 border border-line rounded-lg p-0.5 w-fit">
        {(
          [
            { key: 'users', label: 'Users', icon: Users },
            { key: 'groups', label: 'Groups', icon: UsersRound },
          ] as { key: Tab; label: string; icon: React.ElementType }[]
        ).map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={cn(
              'flex items-center gap-2 px-4 py-1.5 text-sm rounded-md transition-colors focus-ring',
              activeTab === tab.key
                ? 'bg-surface-3 text-ink font-medium'
                : 'text-ink-muted hover:text-ink',
            )}
          >
            <tab.icon className="w-4 h-4" aria-hidden="true" />
            {tab.label}
          </button>
        ))}
      </div>

      <Card>
        <CardBody>
          {activeTab === 'users' ? <UsersTab /> : <GroupsTab />}
        </CardBody>
      </Card>
    </div>
  )
}
