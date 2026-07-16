'use client'

import { AlertCircle, X } from 'lucide-react'

/**
 * Inline, dismissible error line for a failed action.
 *
 * `role="alert"` matters: a screen reader user who presses Delete and gets a
 * silently-rendered red line has no idea anything happened. This announces.
 */
export function ErrorBanner({
  message,
  onDismiss,
}: {
  message: string
  onDismiss?: () => void
}) {
  if (!message) return null
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-lg border border-danger-600/30 bg-danger-600/5 px-3 py-2"
    >
      <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-danger-600" aria-hidden="true" />
      <p className="flex-1 text-xs text-danger-600">{message}</p>
      {onDismiss && (
        <button
          onClick={onDismiss}
          aria-label="Dismiss error"
          className="focus-ring shrink-0 rounded text-danger-600/70 transition-colors hover:text-danger-600"
        >
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      )}
    </div>
  )
}

/**
 * Error state for a failed data load, with a retry.
 *
 * The gap this fills: a `useSWR` page that ignores `error` renders its empty
 * state on failure — "No secrets yet" when the truth is "the request 403'd".
 * That is indistinguishable from success to the user, which is the same class
 * of lie as a delete that reports 200 and does nothing.
 */
export function LoadError({
  error,
  onRetry,
  what = 'data',
}: {
  error: unknown
  onRetry?: () => void
  what?: string
}) {
  const message = error instanceof Error ? error.message : `Could not load ${what}`
  return (
    <div role="alert" className="py-10 text-center">
      <AlertCircle className="mx-auto mb-2 h-5 w-5 text-danger-600" aria-hidden="true" />
      <p className="text-sm text-ink">Could not load {what}</p>
      <p className="mx-auto mt-1 max-w-md text-xs text-ink-muted">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="focus-ring mt-3 rounded-lg px-2 py-1 text-xs font-medium text-primary-700 transition-colors hover:bg-surface-2"
        >
          Retry
        </button>
      )}
    </div>
  )
}
