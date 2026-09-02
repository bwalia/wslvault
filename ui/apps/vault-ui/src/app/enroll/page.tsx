'use client'

import { Suspense } from 'react'
import { useSearchParams } from 'next/navigation'
import { Lock, Smartphone, QrCode, KeyRound, LifeBuoy, CircleHelp } from 'lucide-react'

import { TwoFactorSetup } from '@/components/TwoFactorSetup'

/**
 * The page an operator sends a brand-new user.
 *
 * ## Why this route is public
 *
 * It has to be. A key with `mfa_required` and nothing enrolled cannot obtain a
 * token — that is the whole point of the flag — so anything behind the
 * dashboard's auth guard is unreachable by exactly the person who needs it.
 * This route sits outside the `(dashboard)` group for that reason, and it is
 * safe to: enrolment is authorised by the API key the visitor types, so an
 * unauthenticated visitor with no key sees an empty form and nothing else.
 *
 * ## Why the link carries no secret
 *
 * The URL is the same for everyone. It was tempting to mint a one-time
 * enrolment token and embed it, which would save the user a paste — but a link
 * that by itself authorises binding a second factor *is* a credential, and URLs
 * leak in ways credentials must not: browser history, server and proxy logs,
 * `Referer` headers, and the link previews chat apps generate by fetching them.
 * The operator sends the key through a channel meant for secrets; this link can
 * go anywhere.
 *
 * `?tenant=` is read for display only. It is never sent to the API and grants
 * nothing, so a visitor editing it changes only the words on the page.
 */

/** One numbered step. The number is a real ordinal — this is a sequence. */
function Step({
  n,
  title,
  icon: Icon,
  children,
}: {
  n: number
  title: string
  icon: React.ElementType
  children: React.ReactNode
}) {
  return (
    <li className="flex gap-4">
      <div
        className="shrink-0 w-9 h-9 rounded-full bg-primary-600 text-white flex items-center justify-center text-base font-semibold tabular-nums"
        aria-hidden="true"
      >
        {n}
      </div>
      <div className="pt-1">
        <h3 className="flex items-center gap-2 text-lg font-semibold text-ink">
          <Icon className="w-5 h-5 text-primary-600 shrink-0" aria-hidden="true" />
          {title}
        </h3>
        <div className="mt-2 space-y-2 text-base leading-relaxed text-ink-muted">{children}</div>
      </div>
    </li>
  )
}

function EnrollGuide({ tenant }: { tenant: string | null }) {
  return (
    <div className="space-y-10">
      <header>
        <div className="flex items-center gap-3 mb-6">
          <div className="w-9 h-9 rounded-lg bg-primary-600 flex items-center justify-center">
            <Lock className="w-4.5 h-4.5 text-white" aria-hidden="true" />
          </div>
          <span className="text-lg font-semibold tracking-tight text-ink">
            WSL<span className="text-primary-600">Vault</span>
          </span>
        </div>

        <h1 className="text-3xl font-semibold tracking-tight text-ink text-balance">
          Set up your authenticator app
        </h1>
        <p className="mt-3 text-lg leading-relaxed text-ink-muted max-w-prose">
          {tenant ? `Welcome to ${tenant}. ` : ''}
          Before you can sign in, you need to connect an app on your phone to your
          account. It gives you a 6-digit number to type in each time you sign in,
          so that your key alone is not enough for someone else to get in.
        </p>
        <p className="mt-3 text-base leading-relaxed text-ink-muted max-w-prose">
          It takes about five minutes. You will need your phone and the API key
          your administrator sent you.
        </p>
      </header>

      <section aria-labelledby="how-to">
        <h2 id="how-to" className="text-xl font-semibold text-ink mb-6">
          What to do
        </h2>

        <ol className="space-y-8">
          <Step n={1} title="Install an authenticator app on your phone" icon={Smartphone}>
            <p>
              If you already use one, skip this step. Otherwise open the{' '}
              <strong className="text-ink font-medium">App Store</strong> on an iPhone,
              or <strong className="text-ink font-medium">Google Play</strong> on an
              Android phone, and search for one of these:
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>Google Authenticator</li>
              <li>Microsoft Authenticator</li>
              <li>Authy</li>
            </ul>
            <p>
              Any of them works and it does not matter which you choose. They are all
              free. Install it and open it once, then come back to this page.
            </p>
          </Step>

          <Step n={2} title="Enter your API key below" icon={KeyRound}>
            <p>
              Your administrator sent you a long key starting with{' '}
              <code className="px-1.5 py-0.5 rounded bg-surface-2 font-mono text-sm">
                wslv_
              </code>
              . Copy it and paste it into the box at the bottom of this page, then
              press{' '}
              <strong className="text-ink font-medium">Set up authenticator</strong>.
            </p>
            <p>
              If you do not have a key yet, stop here and ask the person who sent you
              this link for one.
            </p>
          </Step>

          <Step n={3} title="Scan the square pattern with your phone" icon={QrCode}>
            <p>
              A black-and-white square will appear on this screen. In your
              authenticator app, look for a{' '}
              <strong className="text-ink font-medium">+</strong> button, or a button
              that says <strong className="text-ink font-medium">Add</strong> or{' '}
              <strong className="text-ink font-medium">Scan a QR code</strong>. Point
              your phone&rsquo;s camera at the square.
            </p>
            <p>
              The app will ask for permission to use your camera the first time — say
              yes. When it works, your account appears in the app with a 6-digit
              number under it.
            </p>
            <p className="text-ink">
              <strong className="font-medium">If the camera will not scan it:</strong>{' '}
              there is a line of letters and numbers shown underneath the square. In
              your app, choose to enter a setup key by hand instead, and type that
              line in.
            </p>
          </Step>

          <Step n={4} title="Save your recovery codes" icon={LifeBuoy}>
            <p>
              You will be shown a short list of codes. These are your way back in if
              you ever lose your phone. Without them, a lost phone means a lost
              account and nobody can restore it for you — not even your administrator.
            </p>
            <p>
              Print them, or write them on paper. Keep them somewhere safe that is{' '}
              <strong className="text-ink font-medium">not your phone</strong> — a
              drawer at home, or a password manager. Each one works only once.
            </p>
            <p>This is the only time they are shown.</p>
          </Step>

          <Step n={5} title="Type the 6-digit number to finish" icon={Lock}>
            <p>
              Read the current 6-digit number from your authenticator app and type it
              into the last box. This proves the connection worked.
            </p>
            <p>
              That is everything. From now on, signing in asks for your key and then
              for whatever number your app is showing at that moment.
            </p>
          </Step>
        </ol>
      </section>

      <section
        aria-labelledby="trouble"
        className="rounded-xl border border-line bg-surface p-6"
      >
        <h2
          id="trouble"
          className="flex items-center gap-2 text-xl font-semibold text-ink mb-4"
        >
          <CircleHelp className="w-5 h-5 text-primary-600 shrink-0" aria-hidden="true" />
          If something looks wrong
        </h2>
        <dl className="space-y-4 text-base leading-relaxed">
          <div>
            <dt className="font-medium text-ink">The number keeps changing.</dt>
            <dd className="text-ink-muted">
              That is normal. It changes every 30 seconds on purpose. Type whichever
              number is showing when you get there.
            </dd>
          </div>
          <div>
            <dt className="font-medium text-ink">It said my code was wrong.</dt>
            <dd className="text-ink-muted">
              Wait for the app to show a fresh number, then type that one. It is easy
              to be typing while the old one runs out.
            </dd>
          </div>
          <div>
            <dt className="font-medium text-ink">Every code is rejected.</dt>
            <dd className="text-ink-muted">
              Your phone&rsquo;s clock is probably a little off. In your phone&rsquo;s
              settings, find the date and time and turn on the automatic setting. Then
              try again.
            </dd>
          </div>
          <div>
            <dt className="font-medium text-ink">I lost my phone.</dt>
            <dd className="text-ink-muted">
              Use one of your recovery codes instead of the 6-digit number when you
              sign in. If you do not have those either, ask your administrator to
              issue you a new key — your old one can no longer be used.
            </dd>
          </div>
          <div>
            <dt className="font-medium text-ink">
              It says this key already has an authenticator.
            </dt>
            <dd className="text-ink-muted">
              Someone has already set one up for this key. If that was not you, tell
              your administrator straight away.
            </dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="setup-form">
        <h2 id="setup-form" className="text-xl font-semibold text-ink mb-4">
          Start here
        </h2>
        <TwoFactorSetup />
      </section>
    </div>
  )
}

/** `useSearchParams` suspends during prerender, so it needs a boundary. */
function EnrollContent() {
  const tenant = useSearchParams().get('tenant')
  return <EnrollGuide tenant={tenant} />
}

export default function EnrollPage() {
  return (
    <main className="min-h-screen bg-canvas">
      <div className="mx-auto max-w-2xl px-6 py-12 lg:py-16">
        <Suspense fallback={<EnrollGuide tenant={null} />}>
          <EnrollContent />
        </Suspense>
      </div>
    </main>
  )
}
