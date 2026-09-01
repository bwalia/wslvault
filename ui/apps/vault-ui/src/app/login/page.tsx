'use client'
import { useState } from 'react'
import { Lock, Eye, EyeOff, AlertCircle, ShieldCheck } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { Button } from '@/components/ui/Button'
import BuildStamp from '@/components/BuildStamp'

export default function LoginPage() {
  const { login, verifyMfa } = useAuth()
  const [apiKey, setApiKey] = useState('')
  const [show, setShow] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  /** Set once the key is accepted and an authenticator code is outstanding. */
  const [challenge, setChallenge] = useState<string | null>(null)
  const [code, setCode] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const pending = await login(apiKey)
      if (pending) {
        // The key was right; the login just is not finished. Move to the code
        // step rather than reporting anything as an error.
        setChallenge(pending.challenge)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed. Check the key and try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!challenge) return
    setError('')
    setLoading(true)
    try {
      await verifyMfa(challenge, code)
    } catch (err) {
      // A challenge is single-use, so a wrong code invalidates it. Send the
      // user back to the key rather than letting them retype into a challenge
      // the server has already discarded.
      setChallenge(null)
      setCode('')
      setError(
        err instanceof Error
          ? `${err.message} Enter your API key again to retry.`
          : 'That code was not accepted. Enter your API key again to retry.',
      )
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

        <div>
          <p className="font-mono text-xs text-steel-ink-dim">
            AES-256-GCM · per-tenant KEK · multi-region
          </p>
          <BuildStamp className="mt-1.5 text-xs" />
        </div>
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

          <h2 className="text-2xl font-semibold tracking-tight text-ink">
            {challenge ? 'Two-factor authentication' : 'Sign in'}
          </h2>
          <p className="text-sm text-ink-muted mt-1 mb-6">
            {challenge
              ? 'Enter the 6-digit code from your authenticator app.'
              : 'Use an API key issued by your vault operator.'}
          </p>

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 p-3 mb-4 rounded-lg border border-danger-100 bg-danger-50 dark:bg-danger-600/10 dark:border-danger-600/30 text-danger-700 dark:text-danger-400 text-sm"
            >
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
              {error}
            </div>
          )}

          {challenge ? (
            <form onSubmit={handleVerify} className="space-y-4">
              <div>
                <label htmlFor="mfa-code" className="block text-sm font-medium text-ink mb-1.5">
                  Authenticator code
                </label>
                <div className="relative">
                  <ShieldCheck
                    className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-faint"
                    aria-hidden="true"
                  />
                  <input
                    id="mfa-code"
                    // `text` with a numeric inputMode: `number` would render
                    // spinners and strip a leading zero, and codes can start with one.
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    value={code}
                    onChange={e => setCode(e.target.value.replace(/[^0-9A-Za-z-]/g, ''))}
                    placeholder="123456"
                    // eslint-disable-next-line jsx-a11y/no-autofocus -- the only
                    // field on this step; not autofocusing costs every user a click.
                    autoFocus
                    spellCheck={false}
                    className="w-full pl-9 pr-3 py-2.5 rounded-lg border border-line-strong bg-surface text-ink font-mono text-base tracking-[0.3em] placeholder:tracking-normal placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
                    required
                  />
                </div>
                <p className="mt-1.5 text-xs text-ink-faint">
                  Lost your device? Enter one of your recovery codes instead.
                </p>
              </div>
              <Button type="submit" className="w-full" size="lg" loading={loading}>
                Verify
              </Button>
              <button
                type="button"
                onClick={() => {
                  setChallenge(null)
                  setCode('')
                  setError('')
                }}
                className="w-full text-sm text-ink-muted hover:text-ink focus-ring rounded py-1"
              >
                Back
              </button>
            </form>
          ) : (
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
          )}
        </div>
      </div>
    </div>
  )
}
