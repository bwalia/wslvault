'use client'
import { useState } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { mutate } from '@/lib/fetcher'
import { useFetcher } from '@/hooks/useVaultSWR'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { EmptyState } from '@/components/ui/EmptyState'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { Plus, Lock, Unlock, FileSignature, CheckCircle, Cpu } from 'lucide-react'
import { formatDateTime } from '@/lib/utils'
import { cn } from '@/lib/utils'
import { useForm } from 'react-hook-form'

interface TransitKey {
  id: string
  name: string
  type: string
  version: number
  created_at: string
}

interface TransitKeyResponse {
  keys?: TransitKey[]
}

type Operation = 'encrypt' | 'decrypt' | 'sign' | 'verify'

interface OperationForm {
  plaintext?: string
  ciphertext?: string
  data?: string
  signature?: string
}

interface TransitResult {
  ciphertext?: string
  plaintext?: string
  signature?: string
  valid?: boolean
}

const TRANSIT_KEY = '/api/transit/v1/keys'

const opConfig: Record<Operation, { label: string; icon: React.ElementType; inputLabel: string; inputField: keyof OperationForm; endpoint: (name: string) => string; bodyField: string }> = {
  encrypt: {
    label: 'Encrypt',
    icon: Lock,
    inputLabel: 'Plaintext (base64)',
    inputField: 'plaintext',
    endpoint: name => `/api/transit/v1/encrypt/${name}`,
    bodyField: 'plaintext',
  },
  decrypt: {
    label: 'Decrypt',
    icon: Unlock,
    inputLabel: 'Ciphertext',
    inputField: 'ciphertext',
    endpoint: name => `/api/transit/v1/decrypt/${name}`,
    bodyField: 'ciphertext',
  },
  sign: {
    label: 'Sign',
    icon: FileSignature,
    inputLabel: 'Data (base64)',
    inputField: 'data',
    endpoint: name => `/api/transit/v1/sign/${name}`,
    bodyField: 'input',
  },
  verify: {
    label: 'Verify',
    icon: CheckCircle,
    inputLabel: 'Data (base64)',
    inputField: 'data',
    endpoint: name => `/api/transit/v1/verify/${name}`,
    bodyField: 'input',
  },
}

export default function TransitPage() {
  const { token } = useAuth()
  const fetcher = useFetcher()

  const { data: keysData, isLoading } = useSWR<TransitKeyResponse>(TRANSIT_KEY, fetcher)
  const keys = keysData?.keys ?? []

  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  const [selectedKey, setSelectedKey] = useState<TransitKey | null>(null)
  const [activeOp, setActiveOp] = useState<Operation>('encrypt')
  const [opInput, setOpInput] = useState('')
  const [sigInput, setSigInput] = useState('')
  const [opResult, setOpResult] = useState<TransitResult | null>(null)
  const [opLoading, setOpLoading] = useState(false)
  const [opError, setOpError] = useState('')

  const { register, handleSubmit, reset, formState: { errors } } = useForm<{ name: string; type: string }>({ defaultValues: { type: 'aes256-gcm96' } })

  const onCreate = async (values: { name: string; type: string }) => {
    setCreating(true)
    setCreateError('')
    try {
      await mutate(TRANSIT_KEY, 'POST', values, token)
      await swrMutate(TRANSIT_KEY)
      setCreateOpen(false)
      reset()
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create key')
    } finally {
      setCreating(false)
    }
  }

  const runOperation = async () => {
    if (!selectedKey) return
    setOpLoading(true)
    setOpError('')
    setOpResult(null)
    try {
      const cfg = opConfig[activeOp]
      const body: Record<string, string> = { [cfg.bodyField]: opInput }
      if (activeOp === 'verify' && sigInput) body.signature = sigInput
      const result = await mutate(cfg.endpoint(selectedKey.name), 'POST', body, token) as TransitResult
      setOpResult(result)
    } catch (err) {
      setOpError(err instanceof Error ? err.message : 'Operation failed')
    } finally {
      setOpLoading(false)
    }
  }

  const columns: Column<TransitKey>[] = [
    {
      field: 'name',
      label: 'Name',
      sortable: true,
      render: row => <span className="font-mono text-[13px] text-ink">{row.name}</span>,
    },
    {
      field: 'type',
      label: 'Type',
      render: row => <Badge variant="info">{row.type}</Badge>,
    },
    {
      field: 'version',
      label: 'Version',
      align: 'right',
      render: row => <span className="tabular text-sm text-ink">{row.version}</span>,
    },
    {
      field: 'created_at',
      label: 'Created',
      sortable: true,
      render: row => <span className="text-xs text-ink-faint tabular">{formatDateTime(row.created_at)}</span>,
    },
  ]

  return (
    <div className="max-w-7xl space-y-6">
      <PageHeader
        title="Transit Engine"
        description="Encryption as a service"
        guide={
          <>
            <p>
              Transit encrypts data on your behalf. You send a value, the vault
              returns it encrypted — the key itself never leaves.
            </p>
            <p>
              Useful when an application needs to protect something but should
              not be trusted to hold the key that protects it.
            </p>
          </>
        }
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" aria-hidden="true" />
            Create key
          </Button>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Key list */}
        <div>
          <DataTable
            columns={columns}
            data={(keys as unknown as Record<string, unknown>[]) ?? []}
            loading={isLoading}
            keyField="id"
            emptyMessage="No transit keys yet. Create a key to get started."
            onRowClick={row => { setSelectedKey(row as unknown as TransitKey); setOpResult(null); setOpInput('') }}
          />
        </div>

        {/* Playground */}
        <div>
          <Card>
            <CardHeader>
              <CardTitle>
                {selectedKey
                  ? <>Playground — <span className="font-mono text-[13px] font-normal">{selectedKey.name}</span></>
                  : 'Playground'}
              </CardTitle>
            </CardHeader>
            <CardBody className="space-y-4">
              {!selectedKey ? (
                <EmptyState
                  icon={Cpu}
                  title="No key selected"
                  description="Select a key from the table to use the encrypt / decrypt / sign / verify playground."
                />
              ) : (
                <>
                  {/* Operation tabs */}
                  <div
                    role="tablist"
                    aria-label="Transit operations"
                    className="flex rounded-lg overflow-hidden border border-line"
                  >
                    {(Object.keys(opConfig) as Operation[]).map(op => {
                      const Icon = opConfig[op].icon
                      const isActive = activeOp === op
                      return (
                        <button
                          key={op}
                          role="tab"
                          aria-selected={isActive}
                          onClick={() => { setActiveOp(op); setOpResult(null); setOpInput(''); setSigInput('') }}
                          className={cn(
                            'flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-medium transition-colors focus-ring',
                            isActive
                              ? 'bg-primary-600 text-white'
                              : 'text-ink-muted hover:bg-surface-2',
                          )}
                        >
                          <Icon className="w-3.5 h-3.5" aria-hidden="true" />
                          {opConfig[op].label}
                        </button>
                      )
                    })}
                  </div>

                  {/* Input */}
                  <div className="space-y-1.5">
                    <label
                      htmlFor="op-input"
                      className="block text-xs font-medium text-ink-muted"
                    >
                      {opConfig[activeOp].inputLabel}
                    </label>
                    <textarea
                      id="op-input"
                      value={opInput}
                      onChange={e => setOpInput(e.target.value)}
                      rows={4}
                      placeholder="Enter input…"
                      className="w-full px-3 py-2 text-[13px] font-mono rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500 resize-none"
                    />
                  </div>

                  {activeOp === 'verify' && (
                    <div className="space-y-1.5">
                      <label
                        htmlFor="sig-input"
                        className="block text-xs font-medium text-ink-muted"
                      >
                        Signature
                      </label>
                      <textarea
                        id="sig-input"
                        value={sigInput}
                        onChange={e => setSigInput(e.target.value)}
                        rows={3}
                        placeholder="vault:v1:…"
                        className="w-full px-3 py-2 text-[13px] font-mono rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500 resize-none"
                      />
                    </div>
                  )}

                  <Button
                    className="w-full"
                    loading={opLoading}
                    onClick={runOperation}
                    disabled={!opInput.trim()}
                  >
                    {opConfig[activeOp].label}
                  </Button>

                  {opError && (
                    <p className="text-sm text-danger-600">{opError}</p>
                  )}

                  {opResult && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-ink-muted uppercase tracking-wide">Result</p>
                      {opResult.valid !== undefined ? (
                        <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-line bg-surface-2">
                          <StatusBadge status={opResult.valid ? 'success' : 'failure'} />
                          <span className="text-sm text-ink">
                            {opResult.valid ? 'Signature valid' : 'Signature invalid'}
                          </span>
                        </div>
                      ) : (
                        <pre className="text-[13px] font-mono bg-surface-2 border border-line rounded-lg p-3 overflow-auto max-h-40 whitespace-pre-wrap break-all text-ink">
                          {opResult.ciphertext ?? opResult.plaintext ?? opResult.signature}
                        </pre>
                      )}
                    </div>
                  )}
                </>
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      {/* Create key modal */}
      <Modal
        open={createOpen}
        onClose={() => { setCreateOpen(false); reset(); setCreateError('') }}
        title="Create transit key"
        size="sm"
        footer={
          <>
            <Button variant="secondary" size="sm" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button size="sm" loading={creating} onClick={handleSubmit(onCreate)}>
              Create key
            </Button>
          </>
        }
      >
        <form className="space-y-4" onSubmit={handleSubmit(onCreate)}>
          {createError && (
            <p className="text-sm text-danger-600">{createError}</p>
          )}
          <Input
            label="Key name"
            placeholder="my-key"
            mono
            error={errors.name?.message}
            {...register('name', { required: 'Name is required' })}
          />
          <div className="space-y-1.5">
            <label
              htmlFor="key-type"
              className="block text-sm font-medium text-ink"
            >
              Key type
            </label>
            <select
              id="key-type"
              className="w-full px-3 py-2 rounded-lg border border-line-strong bg-surface text-ink text-sm focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
              {...register('type')}
            >
              <option value="aes256-gcm96">AES-256-GCM96 (default)</option>
              <option value="chacha20-poly1305">ChaCha20-Poly1305</option>
              <option value="ed25519">Ed25519 (signing)</option>
              <option value="ecdsa-p256">ECDSA P-256</option>
              <option value="rsa-2048">RSA-2048</option>
              <option value="rsa-4096">RSA-4096</option>
            </select>
          </div>
        </form>
      </Modal>
    </div>
  )
}
