'use client'

import { useState } from 'react'
import { Download, LifeBuoy, TriangleAlert } from 'lucide-react'

import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { OtpInput } from '@/components/ui/OtpInput'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { api } from '@/lib/api'
import { errorMessage, mutate } from '@/lib/fetcher'
import { keyLabel, recoveryCodeDocument, recoveryCodeFilename } from '@/lib/recovery-codes'

/**
 * Replace a key's recovery codes.
 *
 * Recovery codes were only ever minted during enrolment, and enrolment refuses
 * to run a second time once confirmed. So a holder who spent their eight codes
 * — or, far more often, lost track of which set belonged to which key — had no
 * route to more. The authenticator still worked; the backstop for losing it did
 * not, and nothing in the product would say so.
 *
 * The control asks for the second factor it is replacing, because that is the
 * whole basis on which it is allowed to hand out a new one.
 */
export function RecoveryCodeReissue() {
  const [apiKey, setApiKey] = useState('')
  const [code, setCode] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)
  const [codes, setCodes] = useState<string[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const reissue = async () => {
    setBusy(true)
    setError('')
    try {
      const res = (await mutate(
        api.identity.mfaRecoveryCodes(),
        'POST',
        { api_key: apiKey, code },
        null,
      )) as { recovery_codes?: string[] } | null
      if (!res?.recovery_codes?.length) {
        throw new Error('The server did not return any codes. Nothing was changed.')
      }
      setCodes(res.recovery_codes)
      setCode('')
    } catch (err) {
      setError(errorMessage(err, 'Could not issue new codes'))
    } finally {
      setBusy(false)
    }
  }

  const account = keyLabel(apiKey)

  const download = () => {
    if (!codes) return
    const url = URL.createObjectURL(
      new Blob([recoveryCodeDocument(account, codes)], { type: 'text/plain' }),
    )
    const a = document.createElement('a')
    a.href = url
    a.download = recoveryCodeFilename(account)
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <LifeBuoy className="w-4 h-4 text-brass-dim dark:text-brass" aria-hidden="true" />
          Lost your backup codes?
        </CardTitle>
      </CardHeader>
      <CardBody className="space-y-4">
        {codes ? (
          <>
            <div className="flex items-start gap-2.5 p-3 rounded-lg border border-warn-500/30 bg-warn-500/[0.08]">
              <TriangleAlert
                className="w-4 h-4 shrink-0 mt-0.5 text-warn-600 dark:text-warn-500"
                aria-hidden="true"
              />
              <p className="text-sm text-ink-muted leading-relaxed">
                These replace your previous codes, which no longer work. They are shown
                once — save them before you leave this page.
              </p>
            </div>

            <div className="rounded-xl border border-line bg-surface-2 overflow-hidden">
              <p className="px-4 py-2.5 border-b border-line text-xs text-ink-muted">
                For <strong className="text-ink font-semibold">{account ?? 'this key'}</strong>
                {' — they will not work for any other key.'}
              </p>
              <div className="p-4 grid grid-cols-2 gap-2 font-mono text-sm text-ink select-all">
                {codes.map(c => (
                  <span key={c}>{c}</span>
                ))}
              </div>
            </div>

            <Button variant="secondary" onClick={download}>
              <Download className="w-4 h-4" aria-hidden="true" />
              Download
            </Button>
          </>
        ) : (
          <>
            <p className="text-sm text-ink-muted leading-relaxed">
              Get a fresh set of eight. You will need either a current code from your
              authenticator app, or one of the backup codes you still have —{' '}
              <strong className="text-ink font-medium">the key on its own is not enough</strong>,
              since it is the thing the codes protect. Your previous codes stop working.
            </p>

            <Input
              label="API key"
              type="password"
              mono
              placeholder="wslv_…"
              autoComplete="off"
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
              hint="The key whose codes you are replacing."
            />

            <div>
              <p className="block text-sm font-medium text-ink mb-3">
                {useRecovery ? 'A backup code you still have' : 'Code from your authenticator app'}
              </p>
              {useRecovery ? (
                <Input
                  mono
                  placeholder="XXXX-XXXX"
                  autoCapitalize="characters"
                  autoCorrect="off"
                  spellCheck={false}
                  value={code}
                  onChange={e => setCode(e.target.value.replace(/[^0-9A-Za-z-]/g, ''))}
                />
              ) : (
                <OtpInput value={code} onChange={setCode} disabled={busy} invalid={Boolean(error)} />
              )}
              <button
                type="button"
                onClick={() => {
                  setUseRecovery(r => !r)
                  setCode('')
                  setError('')
                }}
                className="mt-3 text-sm text-ink-muted hover:text-ink underline underline-offset-2 focus-ring rounded"
              >
                {useRecovery
                  ? 'Use my authenticator app instead'
                  : 'Use one of my remaining backup codes'}
              </button>
            </div>

            {error && (
              <p role="alert" className="text-sm text-danger-600 dark:text-danger-400">
                {error}
              </p>
            )}

            <Button onClick={reissue} loading={busy} disabled={!apiKey.trim() || !code.trim()}>
              Issue new backup codes
            </Button>
          </>
        )}
      </CardBody>
    </Card>
  )
}
