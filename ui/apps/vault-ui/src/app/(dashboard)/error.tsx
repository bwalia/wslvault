'use client'

import { useEffect } from 'react'
import { Button } from '@/components/ui/Button'
import { AlertTriangle } from 'lucide-react'

/**
 * Route-level error boundary for the dashboard.
 *
 * Without this, a render error in any page unmounts the whole App Router
 * subtree and the operator gets a blank screen with nothing in the UI to act
 * on. Note what is deliberately absent: `error.message` is not rendered. A
 * thrown error in a secrets UI can carry a path, a key name, or a fragment of
 * a decrypted value, and this boundary is exactly where that would get painted
 * onto the page. The digest is enough to correlate with the server log.
 */
export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    // Console only — never ship error text to a third-party collector from a
    // secrets UI without scrubbing it first.
    console.error('[dashboard] render error:', error)
  }, [error])

  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="rounded-full bg-danger-600/10 p-3 mb-4">
        <AlertTriangle className="w-6 h-6 text-danger-600" aria-hidden="true" />
      </div>
      <h2 className="text-base font-semibold text-ink mb-1">Something broke rendering this page</h2>
      <p className="text-sm text-ink-muted max-w-md mb-1">
        The error was logged to the browser console. Your data was not modified.
      </p>
      {error.digest && (
        <p className="text-xs text-ink-faint font-mono mb-4">digest: {error.digest}</p>
      )}
      <div className="flex items-center gap-2 mt-2">
        <Button size="sm" onClick={reset}>
          Try again
        </Button>
        <Button size="sm" variant="ghost" onClick={() => window.location.reload()}>
          Reload page
        </Button>
      </div>
    </div>
  )
}
