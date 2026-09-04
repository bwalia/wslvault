'use client'

import { useState, useEffect, useCallback, useMemo, useRef, memo } from 'react'
import { useSWRConfig } from 'swr'
import { useVaultSWR, useVaultMutate } from '@/hooks/useVaultSWR'
import { useAsyncAction } from '@/hooks/useAsyncAction'
import { api } from '@/lib/api'
import { decodeSecretBlob, encodeSecretBlob, safeJsonParse } from '@/lib/safe'
import { buildSecretTree, ancestorsOf, type TreeNode } from '@/lib/secret-tree'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { ConfirmModal } from '@/components/ui/ConfirmModal'
import { ErrorBanner, LoadError } from '@/components/ErrorBanner'
import {
  Lock, ChevronRight, ChevronDown, Eye, EyeOff, Plus, Trash2, Save, Code2,
  Folder, FolderOpen, Search,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface SecretListResponse {
  paths?: string[]
}

/** Wire shape of `GET /v1/secret/data/*path`. */
interface SecretReadResponse {
  data: string // base64(JSON)
  version: number
  created_at: string
  metadata: Record<string, string>
}

/** Wire shape of `POST /v1/secret/delete/*path`. */
interface DeleteResponse {
  count: number
}

/** An editable key/value row. `id` is stable across reorders — see FieldRow. */
interface Field {
  id: string
  k: string
  v: string
}

// The API's `data` field is a single base64 string, not a JSON object.
// `decodeSecretBlob` / `encodeSecretBlob` (lib/safe) own that conversion and
// return a Result rather than throwing: a corrupt or non-base64 value must
// render an error in the panel, not unmount the page.

/** Monotonic ids for field rows; only needs to be unique within a session. */
let fieldSeq = 0
const nextFieldId = () => `f${++fieldSeq}`
const toFields = (obj: Record<string, string>): Field[] =>
  Object.entries(obj).map(([k, v]) => ({ id: nextFieldId(), k, v }))

// ---------------------------------------------------------------------------
// Tree

interface TreeRowProps {
  node: TreeNode
  depth: number
  selected: string | null
  expanded: ReadonlySet<string>
  onSelect: (path: string) => void
  onToggle: (path: string) => void
}

/**
 * One tree row plus its children.
 *
 * `memo` matters here: the tree re-renders on every keystroke in the editor
 * otherwise, and a vault with a few hundred paths makes that visible. The
 * callbacks it closes over are all `useCallback`-stable, so the comparison
 * actually holds.
 */
const TreeRow = memo(function TreeRow({
  node,
  depth,
  selected,
  expanded,
  onSelect,
  onToggle,
}: TreeRowProps) {
  const isFolder = node.children.length > 0
  const isOpen = expanded.has(node.path)
  const isSelected = selected === node.path

  // A node can be both a folder and a secret. Clicking selects the secret when
  // there is one; the chevron is the only way to toggle in that case.
  const handleClick = useCallback(() => {
    if (node.isLeaf) onSelect(node.path)
    else if (isFolder) onToggle(node.path)
  }, [node.isLeaf, node.path, isFolder, onSelect, onToggle])

  const handleToggle = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation()
      onToggle(node.path)
    },
    [node.path, onToggle],
  )

  return (
    <li>
      <div
        className={cn(
          'group relative flex items-center gap-1 rounded-lg transition-colors',
          // Brass, matching the sidebar's active item and the primary action.
          // Selection was previously a blue wash, the one place in the app that
          // said "current" in a colour nothing else used.
          isSelected ? 'bg-brass/[0.12]' : 'hover:bg-surface-2',
        )}
        style={{ paddingLeft: `${depth * 12}px` }}
      >
        {isSelected && (
          <span
            className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 rounded-full bg-brass"
            aria-hidden="true"
          />
        )}
        {isFolder ? (
          <button
            onClick={handleToggle}
            aria-label={isOpen ? `Collapse ${node.name}` : `Expand ${node.name}`}
            aria-expanded={isOpen}
            className="p-1 text-ink-faint hover:text-ink transition-colors focus-ring rounded shrink-0"
          >
            {isOpen ? (
              <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" aria-hidden="true" />
            )}
          </button>
        ) : (
          <span className="w-[22px] shrink-0" aria-hidden="true" />
        )}

        <button
          onClick={handleClick}
          aria-current={isSelected ? 'true' : undefined}
          className={cn(
            'flex-1 min-w-0 flex items-center gap-1.5 px-1 py-1.5 text-sm text-left rounded-lg focus-ring',
            isSelected ? 'text-ink font-medium' : 'text-ink',
          )}
        >
          {isFolder ? (
            isOpen ? (
              <FolderOpen className="w-4 h-4 shrink-0 text-ink-faint" aria-hidden="true" />
            ) : (
              <Folder className="w-4 h-4 shrink-0 text-ink-faint" aria-hidden="true" />
            )
          ) : (
            <Lock className="w-4 h-4 shrink-0 text-ink-faint" aria-hidden="true" />
          )}
          <span className="truncate font-mono text-sm">{node.name}</span>
          {isFolder && node.isLeaf && (
            <span className="text-[11px] text-ink-faint shrink-0" title="Also a secret">
              ●
            </span>
          )}
          {/* How much is under a folder, so a collapsed branch still says
              whether it holds two secrets or two hundred. */}
          {isFolder && (
            <span className="ml-auto pl-1.5 shrink-0 text-xs tabular-nums text-ink-faint">
              {node.leafCount}
            </span>
          )}
        </button>
      </div>

      {isFolder && isOpen && (
        <ul className="space-y-0.5" role="group">
          {node.children.map(child => (
            <TreeRow
              key={child.path}
              node={child}
              depth={depth + 1}
              selected={selected}
              expanded={expanded}
              onSelect={onSelect}
              onToggle={onToggle}
            />
          ))}
        </ul>
      )}
    </li>
  )
})

// ---------------------------------------------------------------------------
// Field row

interface FieldRowProps {
  field: Field
  index: number
  masked: boolean
  onChange: (id: string, patch: Partial<Field>) => void
  onRemove: (id: string) => void
  onToggleMask: (id: string) => void
}

/**
 * Keyed by `field.id`, never by array index.
 *
 * Index keys are the classic React list bug: delete row 0 of three and React
 * reconciles the *remaining* rows onto the old keys, so row 1's value appears
 * in row 0 and the mask state (also index-keyed before) follows the slot rather
 * than the field. For a form full of secrets, showing the wrong value under the
 * wrong key is not a cosmetic issue.
 */
const FieldRow = memo(function FieldRow({
  field,
  index,
  masked,
  onChange,
  onRemove,
  onToggleMask,
}: FieldRowProps) {
  return (
    // A row in a table rather than three bordered boxes floating in a stack.
    // The cell borders were doing nothing that the row divider does not, and a
    // secret with a dozen fields turned into a wall of outlines.
    <div className="group/row flex items-stretch">
      <input
        value={field.k}
        onChange={e => onChange(field.id, { k: e.target.value })}
        placeholder="key"
        aria-label={`Field ${index + 1} key`}
        className="w-1/3 min-w-0 px-3 py-2 text-sm font-mono bg-transparent text-ink placeholder:text-ink-faint border-r border-line focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary-500/40 focus:bg-surface-2"
      />
      <div className="relative flex-1 min-w-0 flex">
        <input
          type={masked ? 'password' : 'text'}
          value={field.v}
          onChange={e => onChange(field.id, { v: e.target.value })}
          placeholder="value"
          aria-label={`Field ${index + 1} value`}
          autoComplete="off"
          spellCheck={false}
          className="w-full px-3 py-2 pr-8 text-sm font-mono bg-transparent text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-inset focus:ring-primary-500/40 focus:bg-surface-2"
        />
        <button
          type="button"
          onClick={() => onToggleMask(field.id)}
          aria-label={masked ? `Show value for ${field.k || `field ${index + 1}`}` : `Hide value for ${field.k || `field ${index + 1}`}`}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-faint hover:text-ink transition-colors focus-ring rounded"
        >
          {masked ? <Eye className="w-3.5 h-3.5" aria-hidden="true" /> : <EyeOff className="w-3.5 h-3.5" aria-hidden="true" />}
        </button>
      </div>
      {/* Revealed on hover or keyboard focus. Delete sitting permanently beside
          every row invites the mis-click; hiding it from the keyboard would be
          worse, hence focus-within as well as hover. */}
      <button
        onClick={() => onRemove(field.id)}
        aria-label={`Remove field ${field.k || index + 1}`}
        className="px-2.5 text-ink-faint opacity-0 group-hover/row:opacity-100 focus:opacity-100 hover:text-danger-600 transition-all focus-ring rounded"
      >
        <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
      </button>
    </div>
  )
})

/** Shared editor for a list of key/value fields. */
function FieldEditor({
  fields,
  setFields,
}: {
  fields: Field[]
  setFields: React.Dispatch<React.SetStateAction<Field[]>>
}) {
  // Masked-by-default; tracked by field id so it survives reordering.
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(new Set())

  const onChange = useCallback(
    (id: string, patch: Partial<Field>) => {
      setFields(prev => prev.map(f => (f.id === id ? { ...f, ...patch } : f)))
    },
    [setFields],
  )

  const onRemove = useCallback(
    (id: string) => {
      setFields(prev => prev.filter(f => f.id !== id))
      setRevealed(prev => {
        if (!prev.has(id)) return prev
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    },
    [setFields],
  )

  const onToggleMask = useCallback((id: string) => {
    setRevealed(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const onAdd = useCallback(() => {
    setFields(prev => [...prev, { id: nextFieldId(), k: '', v: '' }])
  }, [setFields])

  return (
    <div>
      <div className="rounded-xl border border-line overflow-hidden">
        <div className="flex bg-surface-2 border-b border-line text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-muted">
          <span className="w-1/3 px-3 py-2 border-r border-line">Key</span>
          <span className="flex-1 px-3 py-2">Value</span>
          <span className="w-[34px]" aria-hidden="true" />
        </div>
        <div className="divide-y divide-line">
          {fields.length === 0 && (
            <p className="px-3 py-4 text-sm text-ink-faint">
              No fields yet — add one below.
            </p>
          )}
          {fields.map((field, idx) => (
            <FieldRow
              key={field.id}
              field={field}
              index={idx}
              masked={!revealed.has(field.id)}
              onChange={onChange}
              onRemove={onRemove}
              onToggleMask={onToggleMask}
            />
          ))}
        </div>
      </div>
      <Button variant="ghost" size="sm" onClick={onAdd} className="mt-2">
        <Plus className="w-3.5 h-3.5" aria-hidden="true" /> Add field
      </Button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Editor

function SecretEditor({ path, onDeleted }: { path: string; onDeleted: () => void }) {
  const vaultMutate = useVaultMutate()
  const { mutate: globalMutate } = useSWRConfig()

  const dataKey = api.secret.data(path)
  const { data, error, isLoading, mutate: revalidate } = useVaultSWR<SecretReadResponse>(dataKey)

  const [fields, setFields] = useState<Field[]>([])
  const [jsonMode, setJsonMode] = useState(false)
  const [jsonText, setJsonText] = useState('')
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [decodeError, setDecodeError] = useState('')

  const save = useAsyncAction()
  const del = useAsyncAction()

  // Decode once per response rather than on every render. A bad blob surfaces
  // as an inline error; it must never throw out of render.
  const decoded = useMemo(() => {
    if (!data?.data) return null
    return decodeSecretBlob(data.data)
  }, [data?.data])

  // Reset the editor when a new secret loads. Keyed on `path` too so switching
  // secrets never leaves the previous one's fields on screen.
  useEffect(() => {
    if (!decoded) return
    if (!decoded.ok) {
      setDecodeError(decoded.error)
      setFields([])
      setJsonText('')
      return
    }
    setDecodeError('')
    setFields(toFields(decoded.value))
    setJsonText(JSON.stringify(decoded.value, null, 2))
  }, [decoded, path])

  /** Throws with a user-facing message; callers run it inside useAsyncAction. */
  const buildPayload = useCallback((): Record<string, string> => {
    if (jsonMode) {
      const parsed = safeJsonParse<unknown>(jsonText)
      if (!parsed.ok) throw new Error('Invalid JSON — check the syntax')
      const value = parsed.value
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error('JSON must be an object of key/value pairs')
      }
      return value as Record<string, string>
    }
    return Object.fromEntries(fields.filter(f => f.k.trim()).map(f => [f.k, f.v]))
  }, [jsonMode, jsonText, fields])

  const onSave = useCallback(() => {
    void save.run(
      async () => {
        const encoded = encodeSecretBlob(buildPayload())
        if (!encoded.ok) throw new Error(encoded.error)
        await vaultMutate(dataKey, 'POST', { data: encoded.value })
        await revalidate()
      },
      { fallback: 'Save failed' },
    )
  }, [save, buildPayload, vaultMutate, dataKey, revalidate])

  const onDelete = useCallback(() => {
    void del.run(
      async () => {
        const res = await vaultMutate<DeleteResponse>(api.secret.delete(path), 'POST', {
          versions: [],
        })

        // `POST /v1/secret/delete/*` answers 200 even when it deleted nothing,
        // so a status check alone is not proof of work. Treat a zero count as
        // the failure it is rather than reporting a success that never happened.
        //
        // Check the shape, not just the value: `mutate` returns null for an
        // empty body, and `res && res.count === 0` would let that through as a
        // success — reintroducing the bug for any response that isn't the one
        // we expect.
        if (!res || typeof res.count !== 'number') {
          throw new Error('Unexpected response from the secret engine — delete not confirmed.')
        }
        if (res.count === 0) {
          throw new Error(
            'Server accepted the request but deleted 0 versions — nothing was removed.',
          )
        }
        await globalMutate(api.secret.list())
      },
      {
        fallback: 'Delete failed',
        onSuccess: () => {
          setDeleteOpen(false)
          onDeleted()
        },
      },
    )
  }, [del, vaultMutate, path, globalMutate, onDeleted])

  if (isLoading) {
    return <div className="py-12 text-center text-sm text-ink-faint">Loading…</div>
  }

  if (error) {
    return <LoadError error={error} what="this secret" onRetry={() => void revalidate()} />
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        {/* Breadcrumb rather than a flat string. The guidance is to use one at
            three levels or more, and a secret path is exactly that: the folders
            it sits in are meaningful context, not punctuation. The leaf carries
            a lock so the secret itself is distinguishable at a glance from the
            path leading to it. */}
        <nav aria-label="Secret path" className="min-w-0">
          <ol className="flex items-center flex-wrap gap-x-1 gap-y-0.5 font-mono text-sm">
            {path.split('/').map((part, i, all) => {
              const last = i === all.length - 1
              return (
                <li key={i} className="flex items-center gap-1 min-w-0">
                  {i > 0 && (
                    <ChevronRight
                      className="w-3 h-3 shrink-0 text-ink-faint"
                      aria-hidden="true"
                    />
                  )}
                  {last ? (
                    <span className="inline-flex items-center gap-1.5 font-medium text-ink truncate">
                      <Lock className="w-3 h-3 shrink-0 text-brass" aria-hidden="true" />
                      {part}
                    </span>
                  ) : (
                    <span className="text-ink-faint truncate">{part}</span>
                  )}
                </li>
              )
            })}
          </ol>
        </nav>
        <button
          onClick={() => setJsonMode(m => !m)}
          aria-label={jsonMode ? 'Switch to field editor' : 'Switch to JSON editor'}
          aria-pressed={jsonMode}
          className={cn(
            'flex items-center gap-1 px-2 py-1 text-xs rounded-lg font-medium transition-colors focus-ring shrink-0',
            jsonMode ? 'bg-primary-600/10 text-primary-700' : 'text-ink-muted hover:bg-surface-2',
          )}
        >
          <Code2 className="w-3.5 h-3.5" aria-hidden="true" /> JSON
        </button>
      </div>

      {data && (
        <dl className="flex gap-4">
          <div>
            <dt className="text-xs text-ink-faint">Version</dt>
            <dd className="font-mono text-sm text-ink tabular">{data.version}</dd>
          </div>
          {data.created_at && (
            <div>
              <dt className="text-xs text-ink-faint">Created</dt>
              <dd className="font-mono text-sm text-ink tabular">
                {new Date(data.created_at).toLocaleString()}
              </dd>
            </div>
          )}
        </dl>
      )}

      {decodeError ? (
        // The read succeeded but the stored value is unreadable. Show it rather
        // than an empty editor, which would look like an empty secret and let
        // the user overwrite real data with {}.
        <ErrorBanner
          message={`Stored value could not be decoded (${decodeError}). Editing is disabled to avoid overwriting it.`}
        />
      ) : jsonMode ? (
        <textarea
          value={jsonText}
          onChange={e => setJsonText(e.target.value)}
          rows={12}
          aria-label="JSON editor"
          spellCheck={false}
          className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-line-strong bg-surface text-ink focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500 resize-none"
        />
      ) : (
        <FieldEditor fields={fields} setFields={setFields} />
      )}

      <ErrorBanner message={save.error} onDismiss={save.clearError} />

      <div className="flex items-center gap-2">
        <Button size="sm" loading={save.pending} disabled={!!decodeError} onClick={onSave}>
          <Save className="w-3.5 h-3.5" aria-hidden="true" /> Save secret
        </Button>
        <Button variant="danger" size="sm" onClick={() => setDeleteOpen(true)}>
          <Trash2 className="w-3.5 h-3.5" aria-hidden="true" /> Delete secret
        </Button>
      </div>

      <ConfirmModal
        open={deleteOpen}
        onClose={() => {
          setDeleteOpen(false)
          del.clearError()
        }}
        onConfirm={onDelete}
        title="Delete secret"
        description={`Soft-delete the current version of "${path}"? Earlier versions are retained and the ciphertext is not erased.`}
        confirmText={path.split('/').pop()}
        confirmLabel="Delete"
        loading={del.pending}
        // A failed delete keeps the modal open, so the error must render inside
        // it — on the page behind, the backdrop hides it and the failure looks
        // like nothing happened.
        error={del.error}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Create

function NewSecretPanel({ onCreated }: { onCreated: (path: string) => void }) {
  const vaultMutate = useVaultMutate()
  const { mutate: globalMutate } = useSWRConfig()

  const [secretPath, setSecretPath] = useState('')
  const [fields, setFields] = useState<Field[]>(() => [{ id: nextFieldId(), k: '', v: '' }])
  const create = useAsyncAction()

  const onCreate = useCallback(() => {
    const trimmed = secretPath.trim().replace(/^\/+|\/+$/g, '')
    if (!trimmed) return
    void create.run(
      async () => {
        const data = Object.fromEntries(fields.filter(f => f.k.trim()).map(f => [f.k, f.v]))
        const encoded = encodeSecretBlob(data)
        if (!encoded.ok) throw new Error(encoded.error)
        await vaultMutate(api.secret.data(trimmed), 'POST', { data: encoded.value })
        await globalMutate(api.secret.list())
      },
      {
        fallback: 'Failed to create secret',
        onSuccess: () => onCreated(trimmed),
      },
    )
  }, [create, secretPath, fields, vaultMutate, globalMutate, onCreated])

  return (
    <div className="space-y-4">
      <div className="space-y-1.5">
        <label htmlFor="new-secret-path" className="block text-xs font-medium text-ink-muted">
          Path
        </label>
        <input
          id="new-secret-path"
          value={secretPath}
          onChange={e => setSecretPath(e.target.value)}
          placeholder="myapp/database"
          autoComplete="off"
          spellCheck={false}
          className="w-full px-3 py-2.5 text-sm font-mono rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
        />
        <p className="text-xs text-ink-muted">
          Slashes create folders — <span className="font-mono text-ink">prod/db/password</span>{' '}
          files it under <span className="font-mono text-ink">prod</span> ›{' '}
          <span className="font-mono text-ink">db</span>.
        </p>
      </div>

      <FieldEditor fields={fields} setFields={setFields} />

      <ErrorBanner message={create.error} onDismiss={create.clearError} />

      <div className="flex items-center gap-3">
        <Button loading={create.pending} onClick={onCreate} disabled={!secretPath.trim()}>
          Create secret
        </Button>
        {!secretPath.trim() && (
          <span className="text-xs text-ink-muted">Give it a path first.</span>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Page

export default function SecretsPage() {
  const listKey = api.secret.list()
  const { data: listData, error: listError, isLoading: listLoading } = useVaultSWR<SecretListResponse>(listKey)

  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())

  // Rebuild only when the path list actually changes — not on every keystroke
  // in the editor, which is what the old inline O(n²) build did.
  const paths = useMemo(() => listData?.paths ?? [], [listData?.paths])

  const [filter, setFilter] = useState('')
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    if (!q) return paths
    return paths.filter(p => p.toLowerCase().includes(q))
  }, [paths, filter])

  // Built from the FILTERED list, not filtered afterwards: pruning a finished
  // tree leaves folders whose children have all been removed, so a search for
  // "redis" would still render an empty "prod" branch to click into.
  const tree = useMemo(() => buildSecretTree(filtered), [filtered])

  // A search should show its results, not make the user expand three folders to
  // find them. Any active filter expands every branch on the way down.
  useEffect(() => {
    if (!filter.trim()) return
    const branches = new Set<string>()
    for (const p of filtered) {
      const parts = p.split('/')
      for (let i = 1; i < parts.length; i++) branches.add(parts.slice(0, i).join('/'))
    }
    setExpanded(prev => new Set([...prev, ...branches]))
  }, [filter, filtered])

  const onToggle = useCallback((path: string) => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path)
      else next.add(path)
      return next
    })
  }, [])

  const onSelect = useCallback((path: string) => {
    setSelectedPath(path)
    setCreating(false)
  }, [])

  const startCreating = useCallback(() => {
    setCreating(true)
    setSelectedPath(null)
  }, [])

  // Reveal and select a newly created secret, expanding its folders.
  const handleCreated = useCallback((path: string) => {
    setCreating(false)
    setSelectedPath(path)
    setExpanded(prev => new Set([...prev, ...ancestorsOf(path)]))
  }, [])

  const handleDeleted = useCallback(() => {
    setSelectedPath(null)
  }, [])

  // Auto-expand to the selection (e.g. after create) without clobbering
  // folders the user opened themselves.
  const lastAutoExpanded = useRef<string | null>(null)
  useEffect(() => {
    if (!selectedPath || lastAutoExpanded.current === selectedPath) return
    lastAutoExpanded.current = selectedPath
    const ancestors = ancestorsOf(selectedPath)
    if (ancestors.length > 0) {
      setExpanded(prev => new Set([...prev, ...ancestors]))
    }
  }, [selectedPath])

  return (
    <div className="max-w-7xl space-y-6">
      <PageHeader
        title="Secrets"
        description="Every password, key and certificate your organisation stores, encrypted and organised into folders."
        guide={
          <>
            <p>
              A <strong>secret</strong> is any value you would not want written down in
              plain text: a database password, an API key, a certificate.
            </p>
            <p>
              Everything here is encrypted before it is stored, with a key that
              belongs to your organisation alone. Nobody else can read these —
              not other tenants, and not someone with a copy of the database.
            </p>
            <p>
              Paths work like folders. <strong>prod/database/password</strong> keeps your
              production database password separate from
              <strong> staging/database/password</strong>.
            </p>
          </>
        }
        actions={
          <Button onClick={startCreating}>
            <Plus className="w-4 h-4" aria-hidden="true" />
            Create secret
          </Button>
        }
      />

      {/* A fixed 20rem rail rather than a third of the grid. Paths are deep and
          nest — at lg:col-span-1 "prod / postgres / primary" wrapped, while the
          editor beside it had width to spare. */}
      <div className="grid grid-cols-1 lg:grid-cols-[20rem_minmax(0,1fr)] gap-6 items-start">
        <Card className="lg:sticky lg:top-6">
          <CardHeader className="flex-col items-stretch gap-3 py-3">
            <div className="flex items-center justify-between">
              <CardTitle>Secret paths</CardTitle>
              {paths.length > 0 && (
                <span className="text-xs font-mono text-ink-faint tabular-nums">
                  {filter.trim() ? `${filtered.length}/${paths.length}` : paths.length}
                </span>
              )}
            </div>
            {/* Search earns its place the moment a tenant has more than a
                screenful: without it the only way to find a path is to expand
                every folder and read. */}
            {paths.length > 0 && (
              <div className="relative">
                <Search
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-faint"
                  aria-hidden="true"
                />
                <input
                  type="search"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  placeholder="Filter paths…"
                  aria-label="Filter secret paths"
                  className="w-full pl-9 pr-2.5 py-2 text-sm rounded-lg border border-line-strong bg-surface-2 text-ink placeholder:text-ink-faint transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
                />
              </div>
            )}
          </CardHeader>
          {/* Scrolls on its own so a long tree never pushes the editor off the
              page, and the two panels stay side by side however deep it gets. */}
          <CardBody className="max-h-[calc(100vh-16rem)] overflow-y-auto">
            {listLoading ? (
              <div className="text-xs text-ink-faint text-center py-8">Loading…</div>
            ) : listError ? (
              // Distinct from the empty state below: "no secrets" and "the list
              // request failed" look identical to a user otherwise, and the
              // second one is not something to fix by creating a secret.
              <LoadError error={listError} what="secrets" />
            ) : tree.length === 0 && filter.trim() ? (
              <EmptyState
                icon={Search}
                title="No matching paths"
                description={`Nothing under this vault matches “${filter.trim()}”.`}
                action={
                  <Button size="sm" variant="secondary" onClick={() => setFilter('')}>
                    Clear filter
                  </Button>
                }
              />
            ) : tree.length === 0 ? (
              <EmptyState
                icon={Lock}
                title="No secrets yet"
                description="No secrets under this prefix yet. Write your first secret to see it here."
                action={
                  <Button size="sm" onClick={startCreating}>
                    <Plus className="w-3.5 h-3.5" aria-hidden="true" /> Create secret
                  </Button>
                }
              />
            ) : (
              <ul className="space-y-0.5" role="tree" aria-label="Secret paths">
                {tree.map(node => (
                  <TreeRow
                    key={node.path}
                    node={node}
                    depth={0}
                    selected={selectedPath}
                    expanded={expanded}
                    onSelect={onSelect}
                    onToggle={onToggle}
                  />
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              {creating ? 'Create secret' : selectedPath ? 'Edit secret' : 'Select a secret'}
            </CardTitle>
          </CardHeader>
          <CardBody>
            {creating ? (
              <NewSecretPanel onCreated={handleCreated} />
            ) : selectedPath ? (
              // Remount on path change so no editor state leaks between secrets.
              <SecretEditor key={selectedPath} path={selectedPath} onDeleted={handleDeleted} />
            ) : (
              // Held at the editor's rough height so choosing a secret does not
              // make the panel jump from a stub to a full form.
              <div className="min-h-[20rem] flex items-center justify-center">
                <EmptyState
                  icon={Lock}
                  title="No secret selected"
                  description="Pick a path on the left to view or edit it — values stay masked until you reveal them."
                  action={
                    <Button size="sm" variant="secondary" onClick={startCreating}>
                      <Plus className="w-3.5 h-3.5" aria-hidden="true" /> Create secret
                    </Button>
                  }
                />
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
