'use client'

import { useEffect } from 'react'

/**
 * Last-resort boundary — catches errors thrown in the root layout itself,
 * which `(dashboard)/error.tsx` sits inside of and therefore cannot catch.
 *
 * This replaces the entire document, so it must render its own <html>/<body>
 * and cannot use the app's providers, fonts, or Tailwind theme tokens (the
 * failure may well be in one of those). Styles are inline for that reason.
 *
 * As in the dashboard boundary, `error.message` is deliberately not rendered:
 * in a secrets UI a thrown message can carry a path or a value.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error('[global] fatal error:', error)
  }, [error])

  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'system-ui, -apple-system, sans-serif',
          background: '#0f1115',
          color: '#e6e8eb',
        }}
      >
        <div style={{ textAlign: 'center', padding: '2rem', maxWidth: '32rem' }}>
          <h1 style={{ fontSize: '1.125rem', fontWeight: 600, margin: '0 0 0.5rem' }}>
            WSLVault failed to load
          </h1>
          <p style={{ fontSize: '0.875rem', color: '#9aa4b2', margin: '0 0 0.25rem' }}>
            A fatal error occurred while rendering. Details were written to the browser console.
            Your data was not modified.
          </p>
          {error.digest && (
            <p
              style={{
                fontSize: '0.75rem',
                color: '#6b7280',
                fontFamily: 'ui-monospace, monospace',
                margin: '0 0 1.25rem',
              }}
            >
              digest: {error.digest}
            </p>
          )}
          <button
            onClick={reset}
            style={{
              background: '#0f766e',
              color: '#fff',
              border: 0,
              borderRadius: '0.5rem',
              padding: '0.5rem 1rem',
              fontSize: '0.875rem',
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
        </div>
      </body>
    </html>
  )
}
