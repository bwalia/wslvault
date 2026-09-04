'use client'

import { PageHeader } from '@/components/ui/PageHeader'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { TwoFactorSetup } from '@/components/TwoFactorSetup'
import { RecoveryCodeReissue } from '@/components/RecoveryCodeReissue'
import { ShieldCheck, Smartphone, LifeBuoy, ExternalLink } from 'lucide-react'

/**
 * Multi-factor authentication, as its own destination.
 *
 * The enrolment flow lived only on the Settings page, several cards down, which
 * made "turn on MFA" something you had to already know was there. It is the one
 * security control an operator is most likely to be looking for by name, so it
 * gets a name in the sidebar.
 *
 * The order here is deliberate: sign in with a key alone, then come here and add
 * the second factor. Confirming an enrolment sets `mfa_required` on that key
 * (`mfa_store::confirm`), so enrolling is what switches the protection on —
 * there is no separate toggle to forget, and no window where a key demands a
 * factor that has not been set up yet.
 */
export default function MfaPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Multi-factor authentication"
        description="Add an authenticator app to a key, so the key alone is not enough to sign in"
      />

      <Card>
        <CardHeader>
          <CardTitle>How this works</CardTitle>
        </CardHeader>
        <CardBody>
          <ol className="space-y-4">
            <li className="flex gap-3">
              <Smartphone
                className="w-5 h-5 text-primary-600 shrink-0 mt-0.5"
                aria-hidden="true"
              />
              <div className="text-sm leading-relaxed">
                <p className="font-medium text-ink">Install an authenticator app</p>
                <p className="text-ink-muted mt-0.5">
                  Google Authenticator, Microsoft Authenticator or Authy — any of them
                  works. They are free, on both the App Store and Google Play.
                </p>
              </div>
            </li>
            <li className="flex gap-3">
              <ShieldCheck
                className="w-5 h-5 text-primary-600 shrink-0 mt-0.5"
                aria-hidden="true"
              />
              <div className="text-sm leading-relaxed">
                <p className="font-medium text-ink">Enrol the key below</p>
                <p className="text-ink-muted mt-0.5">
                  Enrolment is authorised by the key itself, not by this session, so you
                  are asked to paste it. That is what lets someone whose key already
                  demands a code — and who therefore cannot sign in at all — still set
                  one up.
                </p>
              </div>
            </li>
            <li className="flex gap-3">
              <LifeBuoy
                className="w-5 h-5 text-primary-600 shrink-0 mt-0.5"
                aria-hidden="true"
              />
              <div className="text-sm leading-relaxed">
                <p className="font-medium text-ink">Keep the recovery codes</p>
                <p className="text-ink-muted mt-0.5">
                  They are shown once and stored only as hashes. Without them, a lost
                  phone means a lost key — nobody can restore it for you.
                </p>
              </div>
            </li>
          </ol>

          <p className="mt-5 pt-4 border-t border-line text-sm text-ink-muted leading-relaxed">
            Finishing enrolment switches the requirement on for that key. From then on
            signing in with it asks for a 6-digit code.
          </p>
        </CardBody>
      </Card>

      <TwoFactorSetup />

      <RecoveryCodeReissue />

      <Card>
        <CardHeader>
          <CardTitle>Onboarding someone else</CardTitle>
        </CardHeader>
        <CardBody>
          <p className="text-sm text-ink-muted leading-relaxed">
            People you issue keys to cannot reach this page — it is behind the sign-in
            they have not completed yet. Send them{' '}
            <a
              href="/enroll"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-medium text-primary-600 hover:underline focus-ring rounded"
            >
              the public enrolment page
              <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
            </a>{' '}
            instead. It carries the same flow wrapped in step-by-step instructions
            written for someone who has never used an authenticator app, and it holds no
            secret, so the link itself is safe to send anywhere.
          </p>
        </CardBody>
      </Card>
    </div>
  )
}
