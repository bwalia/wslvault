'use client'
import { useCallback, useState } from 'react'
import { Eye, EyeOff, AlertCircle, ShieldCheck, KeyRound } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { Button } from '@/components/ui/Button'
import { motion } from 'framer-motion'
import { panel } from '@/lib/motion'
import { VaultDoor } from '@/components/VaultDoor'
import { OtpInput } from '@/components/ui/OtpInput'

export default function LoginPage() {
  const { login, verifyMfa } = useAuth()
  const [apiKey, setApiKey] = useState('')
  const [show, setShow] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  /** Set once the key is accepted and an authenticator code is outstanding. */
  const [challenge, setChallenge] = useState<string | null>(null)
  const [code, setCode] = useState('')
  /**
   * Whether the user is entering a recovery code instead of an app code.
   *
   * The two cannot share a control. A recovery code is base32 with a hyphen and
   * longer than six characters, so it does not fit six digit boxes — and this
   * field is the only way back in for someone whose phone is gone. Boxes for
   * the common case, a plain field one click away for the case that matters
   * most when it happens.
   */
  const [useRecovery, setUseRecovery] = useState(false)

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

  const submitCode = useCallback(
    async (entered: string) => {
      if (!challenge) return

      // Refuse to spend the challenge on something that cannot be right. It is
      // single-use, so submitting three typed digits does not just fail — it
      // destroys the challenge and sends the user back to re-enter their key,
      // which reads as "my key stopped working" rather than "finish typing".
      const looksComplete =
        /^\d{6}$/.test(entered) || /^[0-9A-Za-z]{4,}-?[0-9A-Za-z]{4,}$/.test(entered)
      if (!looksComplete) {
        setError('Enter the full 6-digit code, or a complete recovery code.')
        return
      }

      setError('')
      setLoading(true)
      try {
        await verifyMfa(challenge, entered)
      } catch (err) {
        // A challenge is single-use, so a wrong code invalidates it. Send the
        // user back to the key rather than letting them retype into a challenge
        // the server has already discarded.
        setChallenge(null)
        setCode('')
        setUseRecovery(false)
        setError(
          err instanceof Error
            ? `${err.message} Enter your API key again to retry.`
            : 'That code was not accepted. Enter your API key again to retry.',
        )
      } finally {
        setLoading(false)
      }
    },
    [challenge, verifyMfa],
  )

  const handleVerify = (e: React.FormEvent) => {
    e.preventDefault()
    void submitCode(code)
  }

  // The key is valid and demands a second factor, but none is enrolled — the
  // API answers 403 naming the endpoint to call (api_keys.rs:1571). That is an
  // instruction a person cannot act on, so it is replaced with a link. Matched
  // on the endpoint path rather than the whole sentence: the wording may be
  // reworded, the route is what the message is about.
  const needsEnrolment = error.includes('mfa/totp/enroll')

  return (
    <motion.div
      variants={panel}
      initial="hidden"
      animate="visible"
      className="w-full max-w-md"
    >
      {/* Below lg the vault panel is hidden, so this is the only mark the
              user sees — the real door, small, rather than a generic padlock. */}
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <VaultDoor className="w-11 h-11" />
            <span className="font-display text-lg font-semibold tracking-tight text-ink">
              WSL<span className="text-brass-dim dark:text-brass">Vault</span>
            </span>
          </div>

          <h2 className="font-display text-[2rem] font-semibold tracking-tight text-ink">
            {challenge ? 'One more step' : 'Sign in'}
          </h2>
          <p className="text-base text-ink-muted mt-1.5 mb-7 leading-relaxed">
            {challenge
              ? 'Open your authenticator app and enter the 6-digit number it is showing.'
              : 'Use the API key your vault operator gave you.'}
          </p>

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 p-3 mb-4 rounded-lg border border-danger-100 bg-danger-50 dark:bg-danger-600/10 dark:border-danger-600/30 text-danger-700 dark:text-danger-400 text-sm"
            >
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" aria-hidden="true" />
              {needsEnrolment ? (
                <span>
                  This account needs an authenticator app before you can sign in.{' '}
                  <a href="/enroll" className="font-medium underline underline-offset-2 focus-ring rounded">
                    Set up your authenticator app
                  </a>
                </span>
              ) : (
                error
              )}
            </div>
          )}

          {challenge ? (
            <form onSubmit={handleVerify} className="space-y-4">
              <div>
                <label
                  htmlFor={useRecovery ? 'recovery-code' : undefined}
                  className="block text-sm font-medium text-ink mb-3"
                >
                  {useRecovery ? 'Recovery code' : 'Authenticator code'}
                </label>

                {useRecovery ? (
                  <div className="relative">
                    <ShieldCheck
                      className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-faint"
                      aria-hidden="true"
                    />
                    <input
                      id="recovery-code"
                      type="text"
                      // Full keyboard: recovery codes are base32 with a hyphen,
                      // and a digits-only keypad makes the one credential a
                      // person reaches for after losing their phone physically
                      // untypeable on the device they still have.
                      inputMode="text"
                      autoCapitalize="characters"
                      autoCorrect="off"
                      spellCheck={false}
                      value={code}
                      onChange={e => setCode(e.target.value.replace(/[^0-9A-Za-z-]/g, ''))}
                      placeholder="XXXX-XXXX"
                      // The only field on this step.
                      autoFocus
                      className="w-full pl-10 pr-3 py-3.5 rounded-xl border border-line-strong bg-surface text-ink font-mono text-lg tracking-widest text-center placeholder:text-ink-faint transition-colors duration-200 focus:outline-none focus:border-brass focus:ring-4 focus:ring-brass/15"
                      required
                    />
                  </div>
                ) : (
                  <OtpInput
                    value={code}
                    onChange={setCode}
                    // Submits itself on the sixth digit. Typing six digits and
                    // then hunting for a button is a step nobody wants; the
                    // button stays for keyboard and assistive-tech users.
                    onComplete={submitCode}
                    disabled={loading}
                    autoFocus
                    invalid={Boolean(error)}
                  />
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
                    ? 'Use the code from my authenticator app'
                    : "I do not have my phone — use a recovery code"}
                </button>
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
                <KeyRound
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-faint"
                  aria-hidden="true"
                />
                <input
                  id="api-key"
                  type={show ? 'text' : 'password'}
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  placeholder="wslv_…"
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full pl-9 pr-11 py-3 rounded-xl border border-line-strong bg-surface text-ink font-mono text-sm placeholder:text-ink-faint transition-colors duration-200 focus:outline-none focus:border-brass focus:ring-4 focus:ring-brass/15"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShow(s => !s)}
                  className="absolute right-1 top-1/2 -translate-y-1/2 p-2.5 text-ink-faint hover:text-ink transition-colors focus-ring rounded-lg"
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
    </motion.div>
  )
}
