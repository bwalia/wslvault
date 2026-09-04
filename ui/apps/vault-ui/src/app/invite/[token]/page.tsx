'use client'

import { use, useCallback, useEffect, useState } from 'react'
import QRCode from 'react-qr-code'
import {
  AlertCircle,
  ArrowRight,
  Check,
  Copy,
  Download,
  KeyRound,
  LifeBuoy,
  Lock,
  Smartphone,
  QrCode,
  ShieldCheck,
} from 'lucide-react'

import { Button } from '@/components/ui/Button'
import { api } from '@/lib/api'
import { errorMessage, mutate } from '@/lib/fetcher'

/**
 * The invitation wizard — what a brand-new tenant user actually sees.
 *
 * ## Why this route is public
 *
 * The recipient has no credential yet; obtaining one is the point. The link is
 * guarded instead by a 256-bit single-use token that expires, looked up by hash
 * server-side. Nothing here is enumerable.
 *
 * ## Ordering, and why it is not negotiable
 *
 * The key is minted at step 2 and shown exactly once — it is never recoverable.
 * So the flow refuses to move past it until the recipient confirms they have
 * saved it, and the browser back button cannot return to a step whose secret is
 * already gone. The same applies to recovery codes at step 5.
 *
 * Enrolment is deliberately *after* the key exists, and MFA only becomes
 * mandatory when `mfa_store::confirm` lands — so someone who abandons halfway
 * still holds a working key rather than a locked-out one. That is why the
 * wizard can be closed at any point after step 2 without stranding anybody.
 */

interface Preview {
  tenant_name: string
  expires_at: string
  should_enrol_mfa: boolean
}

interface Accepted {
  api_key: string
  tenant_id: string
  tenant_name: string
  should_enrol_mfa: boolean
}

interface Enrolment {
  secret: string
  otpauth_uri: string
  recovery_codes: string[]
}

type Step = 'welcome' | 'key' | 'install' | 'scan' | 'codes' | 'confirm' | 'done'

const STEP_ORDER: Step[] = ['welcome', 'key', 'install', 'scan', 'codes', 'confirm', 'done']

/** Copy button that confirms it worked, and says so when it did not. */
function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const [failed, setFailed] = useState(false)

  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setCopied(true)
          setFailed(false)
          setTimeout(() => setCopied(false), 2000)
        } catch {
          // Fails on an insecure origin or a denied permission. Unhandled, the
          // recipient believes a one-time secret is on their clipboard when it
          // is not — and it is never shown again.
          setFailed(true)
        }
      }}
      className="shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-line-strong hover:bg-surface-2 text-ink-muted hover:text-ink transition-colors focus-ring"
      aria-label={copied ? `${label} copied` : `Copy ${label}`}
    >
      {copied ? <Check className="w-3.5 h-3.5 text-success-600" /> : <Copy className="w-3.5 h-3.5" />}
      {failed ? 'Select and copy manually' : copied ? 'Copied' : 'Copy'}
    </button>
  )
}

function StepShell({
  n,
  total,
  icon: Icon,
  title,
  lede,
  children,
}: {
  n: number
  total: number
  icon: React.ElementType
  title: string
  lede?: string
  children: React.ReactNode
}) {
  return (
    <div>
      <div
        className="flex items-center gap-2 mb-6"
        role="progressbar"
        aria-valuenow={n}
        aria-valuemin={1}
        aria-valuemax={total}
        aria-label={`Step ${n} of ${total}`}
      >
        {Array.from({ length: total }, (_, i) => (
          <span
            key={i}
            className={`h-1.5 flex-1 rounded-full ${i < n ? 'bg-primary-600' : 'bg-surface-3'}`}
          />
        ))}
      </div>

      <div className="flex items-center gap-2.5 mb-2">
        <Icon className="w-5 h-5 text-primary-600 shrink-0" aria-hidden="true" />
        <h1 className="text-2xl font-semibold tracking-tight text-ink text-balance">{title}</h1>
      </div>
      {lede && <p className="text-base leading-relaxed text-ink-muted mb-6 max-w-prose">{lede}</p>}
      {children}
    </div>
  )
}

export default function InvitePage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = use(params)

  const [step, setStep] = useState<Step>('welcome')
  const [preview, setPreview] = useState<Preview | null>(null)
  const [accepted, setAccepted] = useState<Accepted | null>(null)
  const [enrolment, setEnrolment] = useState<Enrolment | null>(null)
  const [code, setCode] = useState('')
  const [savedKey, setSavedKey] = useState(false)
  const [savedCodes, setSavedCodes] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [fatal, setFatal] = useState('')

  const stepIndex = STEP_ORDER.indexOf(step)
  const total = STEP_ORDER.length - 1

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        // Plain fetch: `mutate` covers only the writing verbs, and this is the
        // one read on the page.
        const res = await fetch(api.identity.invitationPreview(token), { cache: 'no-store' })
        const body = await res.json().catch(() => ({}))
        if (cancelled) return
        if (!res.ok) {
          // The server distinguishes invalid from spent from expired, and its
          // wording is written for the recipient — pass it through rather than
          // flattening all three into one unhelpful sentence.
          setFatal(
            (body as { message?: string }).message ??
              'This invitation could not be checked. Ask whoever invited you for a new link.',
          )
          return
        }
        setPreview(body as Preview)
      } catch {
        if (!cancelled) {
          setFatal('Could not reach the server. Check your connection and try again.')
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [token])

  const accept = useCallback(async () => {
    setBusy(true)
    setError('')
    try {
      const res = (await mutate(api.identity.invitationAccept(token), 'POST', {}, null)) as
        | Accepted
        | null
      if (!res?.api_key) throw new Error('The server did not return a key. Nothing was created.')
      setAccepted(res)
      setStep('key')
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }, [token])

  const enrol = useCallback(async () => {
    if (!accepted) return
    setBusy(true)
    setError('')
    try {
      const res = (await mutate(
        api.identity.mfaEnroll(),
        'POST',
        { api_key: accepted.api_key },
        null,
      )) as Enrolment | null
      if (!res?.otpauth_uri) throw new Error('Could not start the authenticator setup.')
      setEnrolment(res)
      setStep('scan')
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }, [accepted])

  const confirm = useCallback(async () => {
    if (!accepted) return
    setBusy(true)
    setError('')
    try {
      await mutate(api.identity.mfaConfirm(), 'POST', { api_key: accepted.api_key, code }, null)
      setStep('done')
    } catch (e) {
      setError(errorMessage(e))
      setCode('')
    } finally {
      setBusy(false)
    }
  }, [accepted, code])

  if (fatal) {
    return (
      <Centred>
        <div className="flex items-start gap-3 p-4 rounded-xl border border-danger-100 bg-danger-50 dark:bg-danger-600/10 dark:border-danger-600/30">
          <AlertCircle className="w-5 h-5 shrink-0 mt-0.5 text-danger-700 dark:text-danger-400" aria-hidden="true" />
          <div>
            <h1 className="font-semibold text-ink mb-1">This link cannot be used</h1>
            <p className="text-sm text-ink-muted leading-relaxed">{fatal}</p>
          </div>
        </div>
      </Centred>
    )
  }

  if (!preview) {
    return (
      <Centred>
        <p className="text-ink-muted">Checking your invitation…</p>
      </Centred>
    )
  }

  return (
    <Centred>
      {error && (
        <div
          role="alert"
          className="flex items-start gap-2 p-3 mb-6 rounded-lg border border-danger-100 bg-danger-50 dark:bg-danger-600/10 dark:border-danger-600/30 text-danger-700 dark:text-danger-400 text-sm"
        >
          <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
          {error}
        </div>
      )}

      {step === 'welcome' && (
        <StepShell
          n={1}
          total={total}
          icon={ShieldCheck}
          title={`Welcome to ${preview.tenant_name}`}
          lede="You have been invited to set up your access. It takes about five minutes, and you will need your phone."
        >
          <ul className="space-y-3 mb-8 text-base text-ink-muted">
            <li className="flex gap-3">
              <KeyRound className="w-5 h-5 text-primary-600 shrink-0 mt-0.5" aria-hidden="true" />
              We will give you an access key — your password for this system.
            </li>
            <li className="flex gap-3">
              <Smartphone className="w-5 h-5 text-primary-600 shrink-0 mt-0.5" aria-hidden="true" />
              Then you will connect an app on your phone that produces a 6-digit code.
            </li>
            <li className="flex gap-3">
              <LifeBuoy className="w-5 h-5 text-primary-600 shrink-0 mt-0.5" aria-hidden="true" />
              Finally we will give you backup codes, in case you lose the phone.
            </li>
          </ul>
          <Button size="lg" className="w-full" loading={busy} onClick={accept}>
            Get started
            <ArrowRight className="w-4 h-4" />
          </Button>
          <p className="mt-3 text-xs text-ink-faint text-center">
            This link works once. Finish in one sitting if you can.
          </p>
        </StepShell>
      )}

      {step === 'key' && accepted && (
        <StepShell
          n={2}
          total={total}
          icon={KeyRound}
          title="Save your access key"
          lede="This is shown once and can never be shown again. Copy it somewhere safe now — a password manager is ideal."
        >
          <div className="flex items-start gap-2 p-3 rounded-lg border border-line bg-surface-2 mb-3">
            <code className="flex-1 font-mono text-sm text-ink break-all select-all leading-relaxed">
              {accepted.api_key}
            </code>
            <CopyButton value={accepted.api_key} label="access key" />
          </div>

          <label className="flex items-start gap-2.5 mb-6 cursor-pointer">
            <input
              type="checkbox"
              checked={savedKey}
              onChange={e => setSavedKey(e.target.checked)}
              className="mt-0.5 w-4 h-4 rounded border-line-strong text-primary-600 focus-ring"
            />
            <span className="text-sm text-ink-muted leading-snug">
              I have saved my access key somewhere safe.
            </span>
          </label>

          <Button
            size="lg"
            className="w-full"
            disabled={!savedKey}
            loading={busy}
            onClick={() => setStep('install')}
          >
            Continue
            <ArrowRight className="w-4 h-4" />
          </Button>
        </StepShell>
      )}

      {step === 'install' && (
        <StepShell
          n={3}
          total={total}
          icon={Smartphone}
          title="Install an authenticator app"
          lede="This app lives on your phone and produces a 6-digit number that changes every 30 seconds. You will type that number when you sign in."
        >
          <p className="text-base text-ink-muted mb-3">
            If you already have one, skip ahead. Otherwise open the{' '}
            <strong className="text-ink font-medium">App Store</strong> on an iPhone or{' '}
            <strong className="text-ink font-medium">Google Play</strong> on Android and install any
            one of these — they all work the same way and are free:
          </p>
          <ul className="list-disc pl-5 space-y-1 text-base text-ink-muted mb-8">
            <li>Google Authenticator</li>
            <li>Microsoft Authenticator</li>
            <li>Authy</li>
          </ul>
          <Button size="lg" className="w-full" loading={busy} onClick={enrol}>
            I have the app — continue
            <ArrowRight className="w-4 h-4" />
          </Button>
        </StepShell>
      )}

      {step === 'scan' && enrolment && (
        <StepShell
          n={4}
          total={total}
          icon={QrCode}
          title="Scan this with your phone"
          lede="In your authenticator app, tap + and choose “Scan a QR code”. Point your camera at the square below. If it asks to use your camera, say yes."
        >
          {/* White plate in both themes: contrast here is a scanning
              requirement, not a styling preference. */}
          <div className="flex justify-center mb-5">
            <div className="p-4 bg-white rounded-xl">
              <QRCode value={enrolment.otpauth_uri} size={180} />
            </div>
          </div>

          <details className="mb-6">
            <summary className="text-sm text-ink-muted cursor-pointer hover:text-ink focus-ring rounded">
              The camera will not scan it
            </summary>
            <div className="mt-3 p-3 rounded-lg border border-line bg-surface-2">
              <p className="text-sm text-ink-muted mb-2">
                In your app, choose to enter a setup key by hand, then type this in:
              </p>
              <div className="flex items-start gap-2">
                <code className="flex-1 font-mono text-sm text-ink break-all select-all">
                  {enrolment.secret}
                </code>
                <CopyButton value={enrolment.secret} label="setup key" />
              </div>
            </div>
          </details>

          <Button size="lg" className="w-full" onClick={() => setStep('codes')}>
            My account is showing in the app
            <ArrowRight className="w-4 h-4" />
          </Button>
        </StepShell>
      )}

      {step === 'codes' && enrolment && (
        <StepShell
          n={5}
          total={total}
          icon={LifeBuoy}
          title="Save your backup codes"
          lede="If you lose your phone, these are the only way back in. Nobody can restore your account without them — not even the person who invited you."
        >
          <div className="p-4 rounded-lg border border-line bg-surface-2 mb-3">
            <div className="grid grid-cols-2 gap-2 font-mono text-sm text-ink select-all">
              {enrolment.recovery_codes.map(c => (
                <span key={c}>{c}</span>
              ))}
            </div>
          </div>

          <div className="flex gap-2 mb-5">
            <CopyButton value={enrolment.recovery_codes.join('\n')} label="backup codes" />
            <button
              type="button"
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-line-strong hover:bg-surface-2 text-ink-muted hover:text-ink transition-colors focus-ring"
            >
              <Download className="w-3.5 h-3.5" />
              Print
            </button>
          </div>

          <p className="text-sm text-ink-muted mb-5 leading-relaxed">
            Keep them somewhere that is <strong className="text-ink font-medium">not your phone</strong> —
            a drawer at home, or a password manager. Each one works once.
          </p>

          <label className="flex items-start gap-2.5 mb-6 cursor-pointer">
            <input
              type="checkbox"
              checked={savedCodes}
              onChange={e => setSavedCodes(e.target.checked)}
              className="mt-0.5 w-4 h-4 rounded border-line-strong text-primary-600 focus-ring"
            />
            <span className="text-sm text-ink-muted leading-snug">
              I have saved my backup codes. I understand they will not be shown again.
            </span>
          </label>

          <Button
            size="lg"
            className="w-full"
            disabled={!savedCodes}
            onClick={() => setStep('confirm')}
          >
            Continue
            <ArrowRight className="w-4 h-4" />
          </Button>
        </StepShell>
      )}

      {step === 'confirm' && (
        <StepShell
          n={6}
          total={total}
          icon={Lock}
          title="Enter the code to finish"
          lede="Read the current 6-digit number from your authenticator app and type it below. This proves the connection worked."
        >
          <form
            onSubmit={e => {
              e.preventDefault()
              void confirm()
            }}
          >
            <input
              // text with a numeric inputMode: `number` renders spinners and
              // strips a leading zero, and codes can start with one.
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={e => setCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
              placeholder="123456"
              aria-label="Six-digit code from your authenticator app"
              className="w-full px-3 py-3 mb-2 rounded-lg border border-line-strong bg-surface text-ink font-mono text-lg tracking-[0.3em] text-center placeholder:tracking-normal placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
            />
            <p className="text-xs text-ink-faint mb-6">
              The number changes every 30 seconds — that is normal. If it is rejected, wait for a
              fresh one and type that.
            </p>
            <Button
              type="submit"
              size="lg"
              className="w-full"
              loading={busy}
              disabled={code.length !== 6}
            >
              Finish setup
            </Button>
          </form>
        </StepShell>
      )}

      {step === 'done' && accepted && (
        <StepShell
          n={7}
          total={total}
          icon={Check}
          title="You are all set"
          lede={`Your access to ${accepted.tenant_name} is ready. From now on, signing in asks for your access key and then the code from your app.`}
        >
          <a
            href="/login"
            className="inline-flex items-center justify-center gap-2 w-full px-4 py-3 rounded-lg bg-primary-600 hover:bg-primary-700 text-white font-medium transition-colors focus-ring"
          >
            Go to sign in
            <ArrowRight className="w-4 h-4" />
          </a>
        </StepShell>
      )}

      {stepIndex > 0 && step !== 'done' && (
        <p className="mt-8 text-xs text-ink-faint text-center">
          Step {stepIndex} of {total}
        </p>
      )}
    </Centred>
  )
}

function Centred({ children }: { children: React.ReactNode }) {
  return (
    <main className="min-h-screen bg-canvas flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        <div className="flex items-center gap-3 mb-8">
          <div className="w-9 h-9 rounded-lg bg-primary-600 flex items-center justify-center">
            <Lock className="w-4.5 h-4.5 text-white" aria-hidden="true" />
          </div>
          <span className="text-lg font-semibold tracking-tight text-ink">
            WSL<span className="text-primary-600">Vault</span>
          </span>
        </div>
        {children}
      </div>
    </main>
  )
}
