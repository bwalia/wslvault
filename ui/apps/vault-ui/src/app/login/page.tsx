'use client'
import { useState } from 'react'
import { Lock, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { Button } from '@/components/ui/Button'

export default function LoginPage() {
  const { login } = useAuth()
  const [apiKey, setApiKey] = useState('')
  const [show, setShow] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(apiKey)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed. Check the key and try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen grid lg:grid-cols-2 bg-canvas">
      {/* Left panel — vault steel, the brand moment */}
      <div className="hidden lg:flex flex-col justify-between bg-steel p-10">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-primary-600 flex items-center justify-center">
            <Lock className="w-4.5 h-4.5 text-white" aria-hidden="true" />
          </div>
          <span className="text-lg font-semibold tracking-tight text-white">
            WSL<span className="text-primary-300">Vault</span>
          </span>
        </div>

        <div>
          <p className="font-mono text-sm text-steel-ink-dim mb-3">
            $ wslvault kv get prod/db/creds
          </p>
          <h1 className="text-3xl font-semibold tracking-tight text-white leading-tight max-w-md">
            Secrets, encrypted per tenant.
            <br />
            Rotated on schedule.
          </h1>
          <p className="mt-4 text-sm text-steel-ink max-w-sm leading-relaxed">
            Envelope encryption with a per-tenant key hierarchy, automated
            rotation, and a full audit trail — replicated across regions.
          </p>
        </div>

        <p className="font-mono text-xs text-steel-ink-dim">
          AES-256-GCM · per-tenant KEK · multi-region
        </p>
      </div>

      {/* Right panel — the form */}
      <div className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm">
          {/* Compact logo for small screens */}
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <div className="w-9 h-9 rounded-lg bg-primary-600 flex items-center justify-center">
              <Lock className="w-4.5 h-4.5 text-white" aria-hidden="true" />
            </div>
            <span className="text-lg font-semibold tracking-tight text-ink">
              WSL<span className="text-primary-600">Vault</span>
            </span>
          </div>

          <h2 className="text-2xl font-semibold tracking-tight text-ink">Sign in</h2>
          <p className="text-sm text-ink-muted mt-1 mb-6">
            Use an API key issued by your vault operator.
          </p>

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 p-3 mb-4 rounded-lg border border-danger-100 bg-danger-50 dark:bg-danger-600/10 dark:border-danger-600/30 text-danger-700 dark:text-danger-400 text-sm"
            >
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" aria-hidden="true" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="api-key" className="block text-sm font-medium text-ink mb-1.5">
                API key
              </label>
              <div className="relative">
                <input
                  id="api-key"
                  type={show ? 'text' : 'password'}
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  placeholder="wslv_…"
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full px-3 py-2.5 pr-10 rounded-lg border border-line-strong bg-surface text-ink font-mono text-[13px] placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShow(s => !s)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-ink-faint hover:text-ink-muted focus-ring rounded"
                  aria-label={show ? 'Hide API key' : 'Show API key'}
                >
                  {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="mt-1.5 text-xs text-ink-faint">
                Keys start with <span className="font-mono">wslv_</span> and are shown once at creation.
              </p>
            </div>
            <Button type="submit" className="w-full" size="lg" loading={loading}>
              Sign in
            </Button>
          </form>
        </div>
      </div>
    </div>
  )
}
