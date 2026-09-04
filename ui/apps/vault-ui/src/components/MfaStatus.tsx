'use client'

import { ShieldCheck, ShieldAlert, ShieldQuestion, LifeBuoy } from 'lucide-react'

import { useVaultSWR } from '@/hooks/useVaultSWR'
import { Card, CardBody } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'
import { api } from '@/lib/api'

export interface MfaState {
  enrolled: boolean
  confirmed: boolean
  confirmed_at?: string | null
  recovery_codes_total?: number
  recovery_codes_remaining?: number
}

/**
 * Where the MFA page starts: whether the key you are signed in with already
 * has an authenticator.
 *
 * The page could not say. Enrolment is authorised by a pasted key rather than
 * by the session, so nothing on screen knew anything about the caller, and
 * "Set up authenticator" was offered unconditionally — to people who set it up
 * weeks ago, on a key that had been demanding a code at every sign-in since.
 * Being shown a setup form for something already done reads as the setup
 * having failed.
 *
 * It also surfaces how many backup codes are left, which is the number nobody
 * has and everybody needs: they are spent one at a time, silently, and the
 * moment you notice is the moment you have none.
 */
export function MfaStatus({ onState }: { onState?: (s: MfaState) => void }) {
  const { data, error, isLoading } = useVaultSWR<MfaState>(api.identity.mfaStatus(), {
    // A key that cannot report its own status is not a reason to keep asking.
    shouldRetryOnError: false,
    onSuccess: onState,
  })

  if (isLoading) {
    return (
      <Card>
        <CardBody className="flex items-center gap-3">
          <Skeleton className="w-9 h-9 rounded-lg" />
          <div className="flex-1">
            <Skeleton className="h-4 w-48 mb-2" />
            <Skeleton className="h-4 w-72" />
          </div>
        </CardBody>
      </Card>
    )
  }

  // Never a blocker: this panel is context for the page, not the page. A
  // credential that cannot be asked about — the bootstrap token, say — should
  // still be able to enrol a key below.
  if (error || !data) {
    return (
      <Card>
        <CardBody className="flex items-start gap-3">
          <span className="shrink-0 w-9 h-9 rounded-lg bg-surface-2 border border-line flex items-center justify-center">
            <ShieldQuestion className="w-4 h-4 text-ink-faint" aria-hidden="true" />
          </span>
          <div>
            <p className="font-display font-semibold text-ink">
              Could not check this session
            </p>
            <p className="text-sm text-ink-muted mt-0.5 leading-relaxed">
              Everything below still works — it just cannot tell you in advance whether
              this key is already set up.
            </p>
          </div>
        </CardBody>
      </Card>
    )
  }

  const remaining = data.recovery_codes_remaining ?? 0
  const low = data.confirmed && remaining <= 2

  if (data.confirmed) {
    return (
      <Card className={low ? 'border-warn-500/40' : 'border-accent-600/40'}>
        <CardBody className="flex items-start gap-3">
          <span
            className={`shrink-0 w-9 h-9 rounded-lg flex items-center justify-center ${
              low ? 'bg-warn-500/12 text-warn-600 dark:text-warn-500' : 'bg-accent-600/12 text-accent-600'
            }`}
          >
            <ShieldCheck className="w-[18px] h-[18px]" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <p className="font-display font-semibold text-ink">
              Two-factor authentication is on for this key
            </p>
            <p className="text-sm text-ink-muted mt-0.5 leading-relaxed">
              {data.confirmed_at
                ? `Set up on ${new Date(data.confirmed_at).toLocaleDateString(undefined, {
                    day: 'numeric',
                    month: 'long',
                    year: 'numeric',
                  })}. `
                : ''}
              Signing in with it asks for a code from your authenticator app. There is
              nothing more to do here.
            </p>
            <p className="text-sm mt-2 flex items-center gap-1.5 text-ink-muted">
              <LifeBuoy className="w-4 h-4 shrink-0" aria-hidden="true" />
              <span>
                <strong className={low ? 'text-warn-700 dark:text-warn-500' : 'text-ink'}>
                  {remaining} of {data.recovery_codes_total ?? 0}
                </strong>{' '}
                backup codes left
                {low ? ' — issue a fresh set below before you run out.' : '.'}
              </span>
            </p>
          </div>
        </CardBody>
      </Card>
    )
  }

  return (
    <Card className="border-warn-500/40">
      <CardBody className="flex items-start gap-3">
        <span className="shrink-0 w-9 h-9 rounded-lg bg-warn-500/12 text-warn-600 dark:text-warn-500 flex items-center justify-center">
          <ShieldAlert className="w-[18px] h-[18px]" aria-hidden="true" />
        </span>
        <div>
          <p className="font-display font-semibold text-ink">
            {data.enrolled
              ? 'Set-up was started but never finished'
              : 'This key has no authenticator yet'}
          </p>
          <p className="text-sm text-ink-muted mt-0.5 leading-relaxed">
            {data.enrolled
              ? 'A secret was issued but no code was ever confirmed, so it does not protect anything. Start again below — the old secret is replaced.'
              : 'The key on its own is enough to sign in. Add an authenticator below to change that.'}
          </p>
        </div>
      </CardBody>
    </Card>
  )
}
