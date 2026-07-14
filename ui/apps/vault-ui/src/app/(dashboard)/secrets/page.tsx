'use client'
import { useState, useCallback } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { Lock, ChevronRight, ChevronDown, Eye, EyeOff, Plus, Trash2, Save, Code2 } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SecretListResponse {
  paths?: string[]
}

interface SecretData {
  data: Record<string, string>
  metadata?: {
    version: number
    versions?: number[]
  }
}

function SecretTree({
  prefix,
  paths,
  onSelect,
  selected,
}: {
  prefix: string
  paths: string[]
  onSelect: (path: string) => void
  selected: string | null
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  // Determine which items are "directories" (have sub-paths) vs leaves
  const items = paths.map(p => {
    const full = prefix ? `${prefix}/${p}` : p
    const isDir = paths.some(other => other !== p && other.startsWith(p + '/'))
    return { name: p, full, isDir }
  })

  return (
    <ul className="space-y-0.5">
      {items.map(item => {
        const isExpanded = expanded.has(item.full)
        return (
          <li key={item.full}>
            <button
              onClick={() => {
                if (item.isDir) {
                  setExpanded(prev => {
                    const next = new Set(prev)
                    if (next.has(item.full)) next.delete(item.full)
                    else next.add(item.full)
                    return next
                  })
                } else {
                  onSelect(item.full)
                }
              }}
              aria-label={item.isDir ? `Toggle folder ${item.name}` : `Open secret ${item.name}`}
              className={cn(
                'w-full flex items-center gap-1.5 px-2 py-1.5 text-sm rounded-lg text-left transition-colors focus-ring',
                selected === item.full
                  ? 'bg-primary-600/10 text-primary-700'
                  : 'text-ink hover:bg-surface-2',
              )}
            >
              {item.isDir ? (
                isExpanded ? (
                  <ChevronDown className="w-4 h-4 flex-shrink-0 text-ink-faint" aria-hidden="true" />
                ) : (
                  <ChevronRight className="w-4 h-4 flex-shrink-0 text-ink-faint" aria-hidden="true" />
                )
              ) : (
                <Lock className="w-4 h-4 flex-shrink-0 text-ink-faint" aria-hidden="true" />
              )}
              <span className="truncate font-mono text-[13px]">{item.name}</span>
            </button>
          </li>
        )
      })}
    </ul>
  )
}

function SecretEditor({
  path,
  token,
  tenantId,
}: {
  path: string
  token: string | null
  tenantId: string | null
}) {
  const fetcher = createFetcher(token, tenantId)
  const secretUrl = `/api/secret/v1/secret/${encodeURIComponent(path)}`
  const { data, isLoading, mutate: revalidate } = useSWR<SecretData>(secretUrl, fetcher)

  const [kvPairs, setKvPairs] = useState<{ k: string; v: string; show: boolean }[]>([])
  const [jsonMode, setJsonMode] = useState(false)
  const [jsonText, setJsonText] = useState('')
  const [visible, setVisible] = useState<Record<number, boolean>>({})
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)

  // Populate editor when data loads
  useState(() => {
    if (data?.data) {
      const pairs = Object.entries(data.data).map(([k, v]) => ({ k, v, show: false }))
      setKvPairs(pairs)
      setJsonText(JSON.stringify(data.data, null, 2))
    }
  })

  const buildPayload = (): Record<string, string> => {
    if (jsonMode) {
      try {
        return JSON.parse(jsonText) as Record<string, string>
      } catch {
        throw new Error('Invalid JSON')
      }
    }
    return Object.fromEntries(kvPairs.map(p => [p.k, p.v]))
  }

  const onSave = async () => {
    setSaving(true)
    setSaveError('')
    try {
      const payload = buildPayload()
      await mutate(secretUrl, 'PUT', { data: payload }, token, tenantId)
      await revalidate()
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const onDelete = async () => {
    setDeleting(true)
    try {
      await mutate(secretUrl, 'DELETE', null, token, tenantId)
      await swrMutate(`/api/secret/v1/secret/list?prefix=`)
      setDeleteOpen(false)
    } catch {
      // ignore
    } finally {
      setDeleting(false)
    }
  }

  if (isLoading) {
    return <div className="py-12 text-center text-sm text-ink-faint">Loading…</div>
  }

  const pairs = data?.data
    ? Object.entries(data.data).map(([k, v]) => ({ k, v }))
    : kvPairs.map(p => ({ k: p.k, v: p.v }))

  return (
    <div className="space-y-4">
      {/* Path + version metadata */}
      <div className="flex items-start justify-between gap-3">
        <p className="font-mono text-[13px] text-ink break-all">{path}</p>
        <button
          onClick={() => setJsonMode(m => !m)}
          aria-label={jsonMode ? 'Switch to field editor' : 'Switch to JSON editor'}
          className={cn(
            'flex items-center gap-1 px-2 py-1 text-xs rounded-lg font-medium transition-colors focus-ring flex-shrink-0',
            jsonMode
              ? 'bg-primary-600/10 text-primary-700'
              : 'text-ink-muted hover:bg-surface-2',
          )}
        >
          <Code2 className="w-3.5 h-3.5" aria-hidden="true" /> JSON
        </button>
      </div>

      {/* Version metadata */}
      {data?.metadata && (
        <dl className="flex gap-4">
          <div>
            <dt className="text-xs text-ink-faint">Version</dt>
            <dd className="font-mono text-[13px] text-ink tabular">{data.metadata.version}</dd>
          </div>
          {data.metadata.versions && (
            <div>
              <dt className="text-xs text-ink-faint">All versions</dt>
              <dd className="font-mono text-[13px] text-ink tabular">
                {data.metadata.versions.join(', ')}
              </dd>
            </div>
          )}
        </dl>
      )}

      {jsonMode ? (
        <textarea
          value={jsonText}
          onChange={e => setJsonText(e.target.value)}
          rows={12}
          aria-label="JSON editor"
          className="w-full px-3 py-2 text-[13px] font-mono rounded-lg border border-line-strong bg-surface text-ink focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500 resize-none"
        />
      ) : (
        <div className="space-y-2">
          {pairs.map(({ k, v }, idx) => (
            <div key={idx} className="flex items-center gap-2">
              <input
                value={k}
                onChange={e => setKvPairs(prev => prev.map((p, i) => i === idx ? { ...p, k: e.target.value } : p))}
                placeholder="key"
                aria-label={`Field ${idx + 1} key`}
                className="w-1/3 px-3 py-1.5 text-[13px] font-mono rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
              />
              <div className="relative flex-1">
                <input
                  type={visible[idx] ? 'text' : 'password'}
                  value={v}
                  onChange={e => setKvPairs(prev => prev.map((p, i) => i === idx ? { ...p, v: e.target.value } : p))}
                  placeholder="value"
                  aria-label={`Field ${idx + 1} value`}
                  className="w-full px-3 py-1.5 pr-8 text-[13px] font-mono rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
                />
                <button
                  type="button"
                  onClick={() => setVisible(prev => ({ ...prev, [idx]: !prev[idx] }))}
                  aria-label={visible[idx] ? 'Hide value' : 'Show value'}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-faint hover:text-ink transition-colors focus-ring rounded"
                >
                  {visible[idx]
                    ? <EyeOff className="w-3.5 h-3.5" aria-hidden="true" />
                    : <Eye className="w-3.5 h-3.5" aria-hidden="true" />}
                </button>
              </div>
              <button
                onClick={() => setKvPairs(prev => prev.filter((_, i) => i !== idx))}
                aria-label={`Remove field ${idx + 1}`}
                className="p-1.5 text-ink-faint hover:text-danger-600 transition-colors focus-ring rounded"
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
              </button>
            </div>
          ))}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setKvPairs(prev => [...prev, { k: '', v: '', show: false }])}
          >
            <Plus className="w-3.5 h-3.5" aria-hidden="true" /> Add field
          </Button>
        </div>
      )}

      {saveError && <p className="text-xs text-danger-600">{saveError}</p>}

      <div className="flex items-center gap-2">
        <Button size="sm" loading={saving} onClick={onSave}>
          <Save className="w-3.5 h-3.5" aria-hidden="true" /> Save secret
        </Button>
        <Button
          variant="danger"
          size="sm"
          onClick={() => setDeleteOpen(true)}
        >
          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" /> Delete secret
        </Button>
      </div>

      <ConfirmModal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        onConfirm={onDelete}
        title="Delete secret"
        description={`Permanently delete "${path}"? All versions will be removed.`}
        confirmText={path.split('/').pop()}
        confirmLabel="Delete"
        loading={deleting}
      />
    </div>
  )
}

function NewSecretPanel({
  token,
  tenantId,
  onCreated,
}: {
  token: string | null
  tenantId: string | null
  onCreated: () => void
}) {
  const [secretPath, setSecretPath] = useState('')
  const [kvPairs, setKvPairs] = useState([{ k: '', v: '' }])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const onCreate = async () => {
    if (!secretPath.trim()) return
    setSaving(true)
    setError('')
    try {
      const data = Object.fromEntries(kvPairs.filter(p => p.k).map(p => [p.k, p.v]))
      await mutate(`/api/secret/v1/secret/${encodeURIComponent(secretPath)}`, 'POST', { data }, token, tenantId)
      await swrMutate('/api/secret/v1/secret/list?prefix=')
      onCreated()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create secret')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-ink">Create secret</h3>
      <div className="space-y-1.5">
        <label htmlFor="new-secret-path" className="block text-xs font-medium text-ink-muted">
          Path
        </label>
        <input
          id="new-secret-path"
          value={secretPath}
          onChange={e => setSecretPath(e.target.value)}
          placeholder="myapp/database"
          className="w-full px-3 py-1.5 text-[13px] font-mono rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
        />
      </div>
      <div className="space-y-2">
        {kvPairs.map((p, idx) => (
          <div key={idx} className="flex items-center gap-2">
            <input
              value={p.k}
              onChange={e => setKvPairs(prev => prev.map((x, i) => i === idx ? { ...x, k: e.target.value } : x))}
              placeholder="key"
              aria-label={`New field ${idx + 1} key`}
              className="w-1/3 px-3 py-1.5 text-[13px] font-mono rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
            />
            <input
              value={p.v}
              onChange={e => setKvPairs(prev => prev.map((x, i) => i === idx ? { ...x, v: e.target.value } : x))}
              placeholder="value"
              aria-label={`New field ${idx + 1} value`}
              className="flex-1 px-3 py-1.5 text-[13px] font-mono rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
            />
            <button
              onClick={() => setKvPairs(prev => prev.filter((_, i) => i !== idx))}
              aria-label={`Remove field ${idx + 1}`}
              className="p-1.5 text-ink-faint hover:text-danger-600 transition-colors focus-ring rounded"
            >
              <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        ))}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setKvPairs(prev => [...prev, { k: '', v: '' }])}
        >
          <Plus className="w-3.5 h-3.5" aria-hidden="true" /> Add field
        </Button>
      </div>
      {error && <p className="text-xs text-danger-600">{error}</p>}
      <Button size="sm" loading={saving} onClick={onCreate} disabled={!secretPath.trim()}>
        Create secret
      </Button>
    </div>
  )
}

export default function SecretsPage() {
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)

  const { data: listData, isLoading: listLoading } = useSWR<SecretListResponse>(
    '/api/secret/v1/secret/list?prefix=',
    fetcher,
  )
  const paths = listData?.paths ?? []

  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const handleCreated = useCallback(() => {
    setCreating(false)
  }, [])

  return (
    <div className="max-w-7xl space-y-6">
      <PageHeader
        title="Secrets"
        description="Browse and manage secret key-value pairs"
        actions={
          <Button onClick={() => { setCreating(true); setSelectedPath(null) }}>
            <Plus className="w-4 h-4" aria-hidden="true" />
            Create secret
          </Button>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Tree browser */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Secret paths</CardTitle>
          </CardHeader>
          <CardBody>
            {listLoading ? (
              <div className="text-xs text-ink-faint text-center py-8">Loading…</div>
            ) : paths.length === 0 ? (
              <EmptyState
                icon={Lock}
                title="No secrets yet"
                description="No secrets under this prefix yet. Write your first secret to see it here."
                action={
                  <Button
                    size="sm"
                    onClick={() => { setCreating(true); setSelectedPath(null) }}
                  >
                    <Plus className="w-3.5 h-3.5" aria-hidden="true" /> Create secret
                  </Button>
                }
              />
            ) : (
              <SecretTree
                prefix=""
                paths={paths}
                onSelect={setSelectedPath}
                selected={selectedPath}
              />
            )}
          </CardBody>
        </Card>

        {/* Right: Editor */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>
              {creating ? 'Create secret' : selectedPath ? 'Edit secret' : 'Select a secret'}
            </CardTitle>
          </CardHeader>
          <CardBody>
            {creating ? (
              <NewSecretPanel
                token={token}
                tenantId={tenantId}
                onCreated={handleCreated}
              />
            ) : selectedPath ? (
              <SecretEditor path={selectedPath} token={token} tenantId={tenantId} />
            ) : (
              <EmptyState
                icon={Lock}
                title="No secret selected"
                description="Select a secret from the tree to view or edit it."
              />
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
