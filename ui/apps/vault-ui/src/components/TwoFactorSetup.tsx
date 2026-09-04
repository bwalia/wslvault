'use client'

import { useState } from 'react'
import QRCode from 'react-qr-code'
import { Check, Copy, Download, KeyRound, ShieldCheck, TriangleAlert } from 'lucide-react'

import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { api } from '@/lib/api'
import { errorMessage, mutate } from '@/lib/fetcher'

/**
 * Self-service TOTP enrolment.
 *
 * The backend has had the whole flow since 026_mfa_totp.sql, and there was no
 * way to reach it from here: a key with `mfa_required` and nothing enrolled was
 * answered `403` at login with the text "enrol one via
 * /v1/auth/mfa/totp/enroll", an endpoint the UI never called. Setting up a
 * second factor meant reaching for curl.
 *
 * ## Why this asks for the API key
 *
 * Enrolment is authorised by the key itself, not by the session token
 * (`services/identity-service/src/api_keys.rs::handle_mfa_enroll`), and this
 * component follows that rather than working around it. Two reasons it is the
 * right contract:
 *
 *  1. The second factor protects one specific key, so possession of that key is
 *     the thing worth proving. A session token could have been minted by a
 *     different key in the same tenant.
 *  2. A key that already requires MFA cannot obtain a token at all — that is the
 *     403 above. A token-authorised enrolment endpoint would be unreachable in
 *     exactly the situation where it is needed.
 *
 * `AuthContext` deliberately never persists the raw key (it stores only the
 * token, tenant, policies and expiry), so there is nothing to read back and the
 * key has to be typed. It is held in component state for the length of the flow
 * and dropped on completion — never written to storage.
 */

interface EnrolResponse {
  secret: string
  otpauth_uri: string
  recovery_codes: string[]
  warning: string
}

type Stage = 'start' | 'scan' | 'done'

/** Copy-to-clipboard button that confirms it worked. */
function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard access is denied over plain HTTP and in some embedded
      // browsers. The value is on screen and selectable either way, so a failed
      // copy is not worth an error state — it just does not confirm.
    }
  }

  return (
    <button
      type="button"
      onClick={copy}
      className="p-2 rounded-md hover:bg-surface-2 text-ink-muted hover:text-ink transition-colors"
      aria-label={copied ? 'Copied' : label}
    >
      {copied ? <Check className="w-4 h-4 text-success-600" /> : <Copy className="w-4 h-4" />}
    </button>
  )
}

export function TwoFactorSetup() {
  const [stage, setStage] = useState<Stage>('start')
  const [apiKey, setApiKey] = useState('')
  const [enrolment, setEnrolment] = useState<EnrolResponse | null>(null)
  const [code, setCode] = useState('')
  const [savedCodes, setSavedCodes] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const beginEnrolment = async () => {
    setBusy(true)
    setError('')
    try {
      // Token is null: this endpoint authorises on the key in the body.
      const body = (await mutate(api.identity.mfaEnroll(), 'POST', { api_key: apiKey }, null)) as
        | EnrolResponse
        | null
      if (!body) throw new Error('the server returned an empty enrolment')
      setEnrolment(body)
      setStage('scan')
    } catch (err) {
      setError(errorMessage(err, 'Could not start enrolment'))
    } finally {
      setBusy(false)
    }
  }

  const confirmEnrolment = async () => {
    setBusy(true)
    setError('')
    try {
      await mutate(api.identity.mfaConfirm(), 'POST', { api_key: apiKey, code }, null)
      setStage('done')
      // The key has done its job. Drop it rather than leaving a live credential
      // sitting in component state for as long as the page stays open.
      setApiKey('')
      setCode('')
      setEnrolment(null)
    } catch (err) {
      // A wrong code leaves the enrolment pending and re-triable, so the user
      // stays on this step rather than being sent back to re-scan.
      setError(errorMessage(err, 'That code was not accepted'))
    } finally {
      setBusy(false)
    }
  }

  const downloadCodes = () => {
    if (!enrolment) return
    const body = [
      'WSLVault recovery codes',
      'Each code works once. Store them where you can reach them without this vault.',
      '',
      ...enrolment.recovery_codes,
      '',
    ].join('\n')
    const url = URL.createObjectURL(new Blob([body], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'wslvault-recovery-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
    setSavedCodes(true)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <span className="inline-flex items-center gap-2">
            <ShieldCheck className="w-4 h-4" />
            Two-factor authentication
          </span>
        </CardTitle>
      </CardHeader>

      <CardBody className="space-y-5">
        {error && (
          <div
            role="alert"
            className="flex gap-2 items-start rounded-md border border-danger-600/40 bg-danger-600/10 p-3 text-sm text-ink"
          >
            <TriangleAlert className="w-4 h-4 mt-0.5 shrink-0 text-danger-600" />
            <span>{error}</span>
          </div>
        )}

        {stage === 'start' && (
          <>
            <p className="text-sm text-ink-muted">
              Add a time-based code from an authenticator app — Authy, Google
              Authenticator, 1Password, or any other TOTP app — to an API key.
              Once confirmed, that key needs a code as well as the key itself to
              sign in.
            </p>
            <Input
              label="API key"
              type="password"
              autoComplete="off"
              placeholder="wslv_…"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              hint="Enrolment is authorised by the key it protects, so it has to be entered here. It is never stored."
            />
            <Button onClick={beginEnrolment} loading={busy} disabled={!apiKey.trim() || busy}>
              <KeyRound className="w-4 h-4 mr-2" />
              Set up authenticator
            </Button>
          </>
        )}

        {stage === 'scan' && enrolment && (
          <>
            <div>
              <h3 className="text-sm font-medium text-ink mb-1">1. Scan this code</h3>
              <p className="text-sm text-ink-muted mb-3">
                Open your authenticator app and scan the QR code, or enter the
                key below by hand.
              </p>
              {/* White plate regardless of theme: QR contrast is a scanning
                  requirement, not a styling choice, and a dark-on-dark render
                  will not scan. */}
              <div className="inline-block bg-white p-4 rounded-lg border border-line">
                <QRCode value={enrolment.otpauth_uri} size={168} />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-ink mb-1.5">
                Or enter this key manually
              </label>
              <div className="flex items-center gap-1">
                <code className="flex-1 font-mono text-sm break-all rounded-md bg-surface-2 border border-line px-3 py-2 text-ink">
                  {enrolment.secret}
                </code>
                <CopyButton value={enrolment.secret} label="Copy setup key" />
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-ink mb-1">2. Save your recovery codes</h3>
              <p className="text-sm text-ink-muted mb-3">{enrolment.warning}</p>
              <div className="grid grid-cols-2 gap-2 rounded-md bg-surface-2 border border-line p-3">
                {enrolment.recovery_codes.map((c) => (
                  <code key={c} className="font-mono text-sm text-ink">
                    {c}
                  </code>
                ))}
              </div>
              <div className="flex items-center gap-2 mt-2">
                <Button variant="secondary" size="sm" onClick={downloadCodes}>
                  <Download className="w-4 h-4 mr-2" />
                  Download
                </Button>
                <CopyButton
                  value={enrolment.recovery_codes.join('\n')}
                  label="Copy recovery codes"
                />
                <label className="flex items-center gap-2 text-sm text-ink-muted ml-1">
                  <input
                    type="checkbox"
                    checked={savedCodes}
                    onChange={(e) => setSavedCodes(e.target.checked)}
                    className="rounded border-line-strong"
                  />
                  I have saved these
                </label>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-medium text-ink mb-1">3. Confirm it works</h3>
              <p className="text-sm text-ink-muted mb-3">
                Enrolment stays inactive until a generated code proves the app is
                set up, so a half-finished attempt cannot lock you out.
              </p>
              <Input
                label="6-digit code"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                mono
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              />
              <div className="flex items-center gap-2 mt-3">
                <Button
                  onClick={confirmEnrolment}
                  loading={busy}
                  // Gated on the codes being acknowledged: they are shown once
                  // and stored only as hashes, so finishing without them means
                  // losing the only way back in if the authenticator is lost.
                  disabled={code.length !== 6 || !savedCodes || busy}
                >
                  Confirm and enable
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setStage('start')
                    setEnrolment(null)
                    setCode('')
                    setSavedCodes(false)
                    setError('')
                  }}
                  disabled={busy}
                >
                  Cancel
                </Button>
              </div>
              {!savedCodes && code.length === 6 && (
                <p className="text-sm text-ink-muted mt-2">
                  Confirm you have saved the recovery codes to continue.
                </p>
              )}
            </div>
          </>
        )}

        {stage === 'done' && (
          <div className="flex gap-3 items-start">
            <div className="rounded-full bg-success-600/15 p-2">
              <Check className="w-4 h-4 text-success-600" />
            </div>
            <div>
              <h3 className="text-sm font-medium text-ink">Authenticator enabled</h3>
              <p className="text-sm text-ink-muted mt-1">
                Signing in with this key now asks for a code. Keep the recovery
                codes somewhere you can reach without this vault.
              </p>
              <Button
                variant="secondary"
                size="sm"
                className="mt-3"
                onClick={() => {
                  setStage('start')
                  setSavedCodes(false)
                }}
              >
                Set up another key
              </Button>
            </div>
          </div>
        )}
      </CardBody>
    </Card>
  )
}
