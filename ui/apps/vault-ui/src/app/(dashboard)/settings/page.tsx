'use client'
import { useState, useEffect } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { useTheme } from '@/contexts/ThemeContext'
import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { mutate } from '@/lib/fetcher'
import { Sun, Moon, Monitor, Save, CheckCircle, Check, Copy, Smartphone } from 'lucide-react'
import { formatDateTime } from '@/lib/utils'
import { cn } from '@/lib/utils'
import { useForm } from 'react-hook-form'
import Link from 'next/link'

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

// ---------------------------------------------------------------------------
// One-time key reveal with copy affordance
// ---------------------------------------------------------------------------

function OneTimeKeyReveal({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    await navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="rounded-lg border border-line bg-surface-2 p-4 space-y-2">
      <p className="text-xs font-semibold text-warn-600 uppercase tracking-wide">
        Shown once — store it now
      </p>
      <div className="flex items-start gap-2">
        <pre
          className="flex-1 font-mono text-sm text-ink break-all whitespace-pre-wrap select-all leading-relaxed"
          aria-label="One-time API key"
        >
          {value}
        </pre>
        <button
          onClick={copy}
          className="shrink-0 p-1.5 rounded-md text-ink-faint hover:text-ink hover:bg-surface-3 transition-colors focus-ring"
          aria-label={copied ? 'Copied' : 'Copy API key'}
        >
          {copied ? (
            <Check className="w-4 h-4 text-success-600" />
          ) : (
            <Copy className="w-4 h-4" />
          )}
        </button>
      </div>
    </div>
  )
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
      }, token) as { id: string }

      // Create API key for new tenant
      const apiKey = await mutate('/api/identity/v1/api-keys', 'POST', {
        name: values.key_name,
        policies: values.key_policies.split(',').map(p => p.trim()),
        tenant_id: tenant.id,
      }, token) as { key: string }

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
      <PageHeader title="Settings" description="Configure WSLVault admin UI" />

      {/* Appearance */}
      <Card>
        <CardHeader>
          <CardTitle>Appearance</CardTitle>
        </CardHeader>
        <CardBody>
          <div className="flex items-center gap-3">
            {([
              ['light', 'Light', Sun],
              ['system', 'System', Monitor],
              ['dark', 'Dark', Moon],
            ] as const).map(([value, label, Icon]) => (
              <button
                key={value}
                onClick={() => setTheme(value)}
                className={cn(
                  'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium border transition-colors focus-ring',
                  theme === value
                    ? 'border-primary-500 ring-1 ring-primary-500/40 bg-surface text-ink'
                    : 'border-line text-ink-muted hover:bg-surface-2 hover:text-ink',
                )}
                aria-pressed={theme === value}
              >
                <Icon className="w-4 h-4" aria-hidden="true" />
                {label}
              </button>
            ))}
          </div>
        </CardBody>
      </Card>

      {/* Service URLs */}
      <Card>
        <CardHeader>
          <CardTitle>Service URLs</CardTitle>
        </CardHeader>
        <CardBody>
          <form className="space-y-3" onSubmit={urlForm.handleSubmit(onSaveUrls)}>
            <p className="text-xs text-ink-muted">
              Override the default localhost endpoints for each backend service. Values are stored in localStorage and take effect immediately.
            </p>
            {(Object.keys(DEFAULT_URLS) as (keyof ServiceUrls)[]).map(key => (
              <Input
                key={key}
                label={key.replace('_URL', '')}
                mono
                {...urlForm.register(key)}
              />
            ))}
            <Button type="submit" size="sm" variant={savedUrls ? 'secondary' : 'primary'}>
              {savedUrls ? <CheckCircle className="w-4 h-4" /> : <Save className="w-4 h-4" />}
              {savedUrls ? 'Saved' : 'Save URLs'}
            </Button>
          </form>
        </CardBody>
      </Card>

      {/* Session info */}
      <Card>
        <CardHeader>
          <CardTitle>Session</CardTitle>
        </CardHeader>
        <CardBody>
          <dl className="space-y-3">
            <div className="flex items-center justify-between gap-4">
              <dt className="text-sm text-ink-muted">Tenant ID</dt>
              <dd className="font-mono text-sm text-ink">{tenantId ?? '—'}</dd>
            </div>
            <div className="flex items-center justify-between gap-4">
              <dt className="text-sm text-ink-muted">Policies</dt>
              <dd className="font-mono text-sm text-ink">{policies.join(', ') || '—'}</dd>
            </div>
            <div className="flex items-center justify-between gap-4">
              <dt className="text-sm text-ink-muted">Expires</dt>
              <dd className="font-mono text-sm text-ink tabular">
                {expiresAt ? formatDateTime(new Date(expiresAt)) : '—'}
              </dd>
            </div>
          </dl>
        </CardBody>
      </Card>

      {/* MFA used to live here, several cards down. It has its own page now. */}
      <Card>
        <CardHeader>
          <CardTitle>Authenticator app</CardTitle>
        </CardHeader>
        <CardBody>
          <p className="text-sm text-ink-muted leading-relaxed">
            Adding a second factor to a key lives on the{' '}
            <Link
              href="/mfa"
              className="inline-flex items-center gap-1 font-medium text-primary-600 hover:underline focus-ring rounded"
            >
              <Smartphone className="w-3.5 h-3.5" aria-hidden="true" />
              MFA page
            </Link>
            . Confirming an enrolment is what switches the requirement on for
            that key.
          </p>
        </CardBody>
      </Card>

      {/* Bootstrap */}
      <Card>
        <CardHeader>
          <CardTitle>Bootstrap</CardTitle>
        </CardHeader>
        <CardBody>
          <p className="text-xs text-ink-muted mb-4">
            Create a new tenant and issue its first API key in one step. The key is shown once — copy it before navigating away.
          </p>
          <form className="space-y-3" onSubmit={bootstrapForm.handleSubmit(onBootstrap)}>
            {bootstrapError && (
              <p className="text-sm text-danger-600">{bootstrapError}</p>
            )}
            {bootstrapResult && (
              <div className="space-y-3">
                <div className="space-y-1">
                  <p className="text-xs font-medium text-ink-muted uppercase tracking-wide">Tenant ID</p>
                  <p className="font-mono text-sm text-ink">{bootstrapResult.tenant_id}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium text-ink-muted uppercase tracking-wide">API Key</p>
                  <OneTimeKeyReveal value={bootstrapResult.api_key} />
                </div>
              </div>
            )}
            <Input
              label="Tenant Slug"
              placeholder="my-tenant"
              mono
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
              mono
              error={bootstrapForm.formState.errors.key_name?.message}
              {...bootstrapForm.register('key_name', { required: 'Required' })}
            />
            <Input
              label="API Key Policies"
              placeholder="admin, read-all"
              hint="Comma-separated policy names to assign to the new key."
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
