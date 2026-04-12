'use client'
import { useState, useEffect } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { useTheme } from '@/contexts/ThemeContext'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { mutate } from '@/lib/fetcher'
import { Settings, Sun, Moon, Monitor, Save, CheckCircle } from 'lucide-react'
import { formatDateTime } from '@/lib/utils'
import { cn } from '@/lib/utils'
import { useForm } from 'react-hook-form'

interface ServiceUrls {
  IDENTITY_URL: string
  SECRET_URL: string
  TRANSIT_URL: string
  POLICY_URL: string
  AUDIT_URL: string
  LEASE_URL: string
}

const DEFAULT_URLS: ServiceUrls = {
  IDENTITY_URL: 'http://localhost:18082',
  SECRET_URL: 'http://localhost:8081',
  TRANSIT_URL: 'http://localhost:18086',
  POLICY_URL: 'http://localhost:8083',
  AUDIT_URL: 'http://localhost:18085',
  LEASE_URL: 'http://localhost:18084',
}

const STORAGE_KEY = 'vault_service_urls'

function loadUrls(): ServiceUrls {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored) return { ...DEFAULT_URLS, ...(JSON.parse(stored) as Partial<ServiceUrls>) }
  } catch {
    // fallback to defaults
  }
  return { ...DEFAULT_URLS }
}

interface BootstrapFormValues {
  tenant_slug: string
  tenant_name: string
  key_name: string
  key_policies: string
}

export default function SettingsPage() {
  const { theme, setTheme } = useTheme()
  const { token, tenantId, policies, expiresAt } = useAuth()

  const [savedUrls, setSavedUrls] = useState(false)

  const urlForm = useForm<ServiceUrls>({ defaultValues: DEFAULT_URLS })

  useEffect(() => {
    const loaded = loadUrls()
    urlForm.reset(loaded)
  }, [urlForm])

  const onSaveUrls = (values: ServiceUrls) => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(values))
    setSavedUrls(true)
    setTimeout(() => setSavedUrls(false), 2000)
  }

  // Bootstrap form
  const bootstrapForm = useForm<BootstrapFormValues>()
  const [bootstrapping, setBootstrapping] = useState(false)
  const [bootstrapResult, setBootstrapResult] = useState<{ tenant_id: string; api_key: string } | null>(null)
  const [bootstrapError, setBootstrapError] = useState('')

  const onBootstrap = async (values: BootstrapFormValues) => {
    setBootstrapping(true)
    setBootstrapError('')
    setBootstrapResult(null)
    try {
      // Create tenant
      const tenant = await mutate('/api/identity/v1/tenants', 'POST', {
        slug: values.tenant_slug,
        display_name: values.tenant_name,
        tier: 'shared',
      }, token, tenantId) as { id: string }

      // Create API key for new tenant
      const apiKey = await mutate('/api/identity/v1/api-keys', 'POST', {
        name: values.key_name,
        policies: values.key_policies.split(',').map(p => p.trim()),
        tenant_id: tenant.id,
      }, token, tenantId) as { key: string }

      setBootstrapResult({ tenant_id: tenant.id, api_key: apiKey.key })
      bootstrapForm.reset()
    } catch (err) {
      setBootstrapError(err instanceof Error ? err.message : 'Bootstrap failed')
    } finally {
      setBootstrapping(false)
    }
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <PageHeader title="Settings" description="Configure WSLVault admin UI" icon={Settings} />

      {/* Theme */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Appearance</h2>
        </CardHeader>
        <CardBody>
          <div className="flex items-center gap-2">
            {([
              ['light', 'Light', Sun],
              ['system', 'System', Monitor],
              ['dark', 'Dark', Moon],
            ] as const).map(([value, label, Icon]) => (
              <button
                key={value}
                onClick={() => setTheme(value)}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium border transition-colors',
                  theme === value
                    ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                    : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800',
                )}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </div>
        </CardBody>
      </Card>

      {/* Service URLs */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Service URLs</h2>
        </CardHeader>
        <CardBody>
          <form className="space-y-3" onSubmit={urlForm.handleSubmit(onSaveUrls)}>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              These override the default localhost URLs for backend services. Stored in localStorage.
            </p>
            {(Object.keys(DEFAULT_URLS) as (keyof ServiceUrls)[]).map(key => (
              <Input
                key={key}
                label={key.replace('_URL', '')}
                {...urlForm.register(key)}
              />
            ))}
            <Button type="submit" size="sm">
              {savedUrls ? <CheckCircle className="w-4 h-4" /> : <Save className="w-4 h-4" />}
              {savedUrls ? 'Saved!' : 'Save URLs'}
            </Button>
          </form>
        </CardBody>
      </Card>

      {/* Session info */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Session</h2>
        </CardHeader>
        <CardBody className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-slate-500">Tenant ID</span>
            <span className="font-mono text-xs">{tenantId ?? '—'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Policies</span>
            <span className="text-xs">{policies.join(', ') || '—'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Expires</span>
            <span className="text-xs">{expiresAt ? formatDateTime(new Date(expiresAt)) : '—'}</span>
          </div>
        </CardBody>
      </Card>

      {/* Bootstrap */}
      <Card>
        <CardHeader>
          <h2 className="text-sm font-semibold text-slate-900 dark:text-white">Bootstrap</h2>
        </CardHeader>
        <CardBody>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
            Quickly create a new tenant and API key in one step.
          </p>
          <form className="space-y-3" onSubmit={bootstrapForm.handleSubmit(onBootstrap)}>
            {bootstrapError && (
              <p className="text-sm text-danger-600 dark:text-danger-400">{bootstrapError}</p>
            )}
            {bootstrapResult && (
              <div className="p-3 rounded-lg bg-accent-50 dark:bg-accent-900/20 space-y-1">
                <p className="text-xs font-medium text-accent-700 dark:text-accent-400">Bootstrap complete!</p>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Tenant: <span className="font-mono">{bootstrapResult.tenant_id}</span>
                </p>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  API Key: <span className="font-mono break-all">{bootstrapResult.api_key}</span>
                </p>
              </div>
            )}
            <Input
              label="Tenant Slug"
              placeholder="my-tenant"
              error={bootstrapForm.formState.errors.tenant_slug?.message}
              {...bootstrapForm.register('tenant_slug', { required: 'Required' })}
            />
            <Input
              label="Tenant Display Name"
              placeholder="My Tenant"
              error={bootstrapForm.formState.errors.tenant_name?.message}
              {...bootstrapForm.register('tenant_name', { required: 'Required' })}
            />
            <Input
              label="API Key Name"
              placeholder="admin-key"
              error={bootstrapForm.formState.errors.key_name?.message}
              {...bootstrapForm.register('key_name', { required: 'Required' })}
            />
            <Input
              label="API Key Policies (comma-separated)"
              placeholder="admin, read-all"
              {...bootstrapForm.register('key_policies')}
            />
            <Button type="submit" size="sm" loading={bootstrapping}>
              Bootstrap Tenant + Key
            </Button>
          </form>
        </CardBody>
      </Card>
    </div>
  )
}
