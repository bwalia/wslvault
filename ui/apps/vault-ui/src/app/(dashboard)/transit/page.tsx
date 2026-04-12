'use client'
import { useState } from 'react'
import useSWR, { mutate as swrMutate } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate } from '@/lib/fetcher'
import { PageHeader } from '@/components/ui/PageHeader'
import { DataTable, Column } from '@/components/ui/DataTable'
import { Card, CardHeader, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { Cpu, Plus, Lock, Unlock, FileSignature, CheckCircle } from 'lucide-react'
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
  const { token, tenantId } = useAuth()
  const fetcher = createFetcher(token, tenantId)

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
      await mutate(TRANSIT_KEY, 'POST', values, token, tenantId)
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
      const result = await mutate(cfg.endpoint(selectedKey.name), 'POST', body, token, tenantId) as TransitResult
      setOpResult(result)
    } catch (err) {
      setOpError(err instanceof Error ? err.message : 'Operation failed')
    } finally {
      setOpLoading(false)
    }
  }

  const columns: Column<TransitKey>[] = [
    { field: 'name', label: 'Name', sortable: true, render: row => <span className="font-mono text-xs">{row.name}</span> },
    { field: 'type', label: 'Type', render: row => <Badge variant="info">{row.type}</Badge> },
    { field: 'version', label: 'Version', render: row => <span className="text-sm">{row.version}</span> },
    {
      field: 'created_at',
      label: 'Created',
      sortable: true,
      render: row => <span className="text-xs text-slate-500">{formatDateTime(row.created_at)}</span>,
    },
  ]

  return (
    <div>
      <PageHeader
        title="Transit Engine"
        description="Encryption as a service"
        icon={Cpu}
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="w-4 h-4" />
            New Key
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
            onRowClick={row => { setSelectedKey(row as unknown as TransitKey); setOpResult(null); setOpInput('') }}
          />
        </div>

        {/* Playground */}
        <div>
          <Card>
            <CardHeader>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                {selectedKey ? `Playground — ${selectedKey.name}` : 'Select a key to continue'}
              </h3>
            </CardHeader>
            <CardBody className="space-y-4">
              {!selectedKey ? (
                <p className="text-sm text-slate-400 text-center py-8">
                  Click a key from the list to use the playground.
                </p>
              ) : (
                <>
                  {/* Operation tabs */}
                  <div className="flex rounded-lg overflow-hidden border border-slate-200 dark:border-slate-700">
                    {(Object.keys(opConfig) as Operation[]).map(op => {
                      const Icon = opConfig[op].icon
                      return (
                        <button
                          key={op}
                          onClick={() => { setActiveOp(op); setOpResult(null); setOpInput(''); setSigInput('') }}
                          className={cn(
                            'flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-medium transition-colors',
                            activeOp === op
                              ? 'bg-primary-600 text-white'
                              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800',
                          )}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          {opConfig[op].label}
                        </button>
                      )
                    })}
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                      {opConfig[activeOp].inputLabel}
                    </label>
                    <textarea
                      value={opInput}
                      onChange={e => setOpInput(e.target.value)}
                      rows={4}
                      className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500/50 resize-none"
                      placeholder="Enter input…"
                    />
                  </div>

                  {activeOp === 'verify' && (
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                        Signature
                      </label>
                      <textarea
                        value={sigInput}
                        onChange={e => setSigInput(e.target.value)}
                        rows={3}
                        className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-primary-500/50 resize-none"
                        placeholder="vault:v1:…"
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
                    <p className="text-sm text-danger-600 dark:text-danger-400">{opError}</p>
                  )}

                  {opResult && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-slate-600 dark:text-slate-400">Result</p>
                      {opResult.valid !== undefined ? (
                        <div className={cn(
                          'flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium',
                          opResult.valid
                            ? 'bg-accent-50 text-accent-700 dark:bg-accent-900/20 dark:text-accent-400'
                            : 'bg-danger-50 text-danger-700 dark:bg-danger-900/20 dark:text-danger-400',
                        )}>
                          <CheckCircle className="w-4 h-4" />
                          {opResult.valid ? 'Signature valid' : 'Signature invalid'}
                        </div>
                      ) : (
                        <pre className="text-xs font-mono bg-slate-50 dark:bg-slate-800 rounded-lg p-3 overflow-auto max-h-40 whitespace-pre-wrap break-all">
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

      {/* Create Key modal */}
      <Modal
        open={createOpen}
        onClose={() => { setCreateOpen(false); reset(); setCreateError('') }}
        title="Create Transit Key"
        size="sm"
        footer={
          <>
            <Button variant="secondary" size="sm" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button size="sm" loading={creating} onClick={handleSubmit(onCreate)}>Create</Button>
          </>
        }
      >
        <form className="space-y-4" onSubmit={handleSubmit(onCreate)}>
          {createError && <p className="text-sm text-danger-600 dark:text-danger-400">{createError}</p>}
          <Input
            label="Key Name"
            placeholder="my-key"
            error={errors.name?.message}
            {...register('name', { required: 'Name is required' })}
          />
          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Key Type</label>
            <select
              className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500/50"
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
