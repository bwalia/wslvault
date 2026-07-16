'use client'

import { useCallback, useRef, useState, useEffect } from 'react'
import { ApiError, errorMessage } from '@/lib/fetcher'
import { useAuth } from '@/contexts/AuthContext'

/**
 * The single way to run an async user action.
 *
 * Hand-written `try/catch` in every handler is how the silent-delete bug
 * survived: one handler had `catch { // ignore }` and nobody noticed, because
 * nothing forces a handler to deal with rejection. This hook makes the safe
 * path the shortest one — you cannot use it and still forget the catch.
 *
 * It provides, for free:
 *   - try/catch around the whole action
 *   - `pending` state (so buttons disable and can't be double-fired)
 *   - a human-readable `error` string
 *   - re-entrancy guard: a second call while one is in flight is dropped
 *   - unmount guard: no setState after the component is gone
 *   - 401 → automatic logout, since every other error message is a lie once
 *     the token has expired
 *
 * Usage:
 *   const del = useAsyncAction()
 *   ...
 *   <Button loading={del.pending} onClick={() => del.run(async () => {
 *     const res = await vaultMutate(url, 'POST', body)
 *     if (res.count === 0) throw new Error('Deleted nothing')
 *   })} />
 *   {del.error && <p role="alert">{del.error}</p>}
 */
export interface AsyncAction {
  /** Run `fn` guarded. Resolves true on success, false if it threw. */
  run: <T>(fn: () => Promise<T>, opts?: RunOptions<T>) => Promise<boolean>
  pending: boolean
  error: string
  clearError: () => void
}

export interface RunOptions<T> {
  /** Runs only on success, inside the same guard. */
  onSuccess?: (value: T) => void | Promise<void>
  /** Overrides the default message. Return a string to display. */
  onError?: (err: unknown) => string | void
  /** Message shown when the thrown value has none. */
  fallback?: string
}

export function useAsyncAction(): AsyncAction {
  const [pending, setPending] = useState(false)
  const [error, setError] = useState('')
  const { logout } = useAuth()

  // Guards against setState-after-unmount, which React warns about and which
  // hides the real error behind a console warning.
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  // Re-entrancy guard. `pending` cannot do this job: state updates are async,
  // so two fast clicks both observe pending === false and both fire.
  const inFlight = useRef(false)

  const run = useCallback(
    async <T,>(fn: () => Promise<T>, opts?: RunOptions<T>): Promise<boolean> => {
      if (inFlight.current) return false
      inFlight.current = true

      if (mounted.current) {
        setPending(true)
        setError('')
      }

      try {
        const value = await fn()
        if (opts?.onSuccess) await opts.onSuccess(value)
        return true
      } catch (err) {
        // An expired token makes every other message misleading — the user
        // has not been "denied", they have been logged out.
        if (err instanceof ApiError && err.isAuthError) {
          logout()
          return false
        }

        const custom = opts?.onError?.(err)
        if (mounted.current) {
          setError(custom || errorMessage(err, opts?.fallback ?? 'Something went wrong'))
        }
        // Keep the detail in the console for operators; the UI shows the
        // short form.
        console.error('[action failed]', err)
        return false
      } finally {
        inFlight.current = false
        if (mounted.current) setPending(false)
      }
    },
    [logout],
  )

  const clearError = useCallback(() => setError(''), [])

  return { run, pending, error, clearError }
}
