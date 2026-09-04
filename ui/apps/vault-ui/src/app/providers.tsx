'use client'

import { SWRConfig } from 'swr'
import { useEffect, type ReactNode } from 'react'
import { VaultTransitionHost } from '@/components/VaultTransitionHost'
import { ApiError } from '@/lib/fetcher'
import { useAuth } from '@/contexts/AuthContext'

/**
 * Catch-all for promise rejections nobody handled.
 *
 * Every async path *should* go through `useAsyncAction`. This exists for the
 * ones that don't yet, and for rejections thrown from library internals. Without
 * it an unhandled rejection is invisible outside devtools — the click appears to
 * do nothing, which is exactly how the silent-delete bug felt to use.
 */
function useGlobalRejectionHandler() {
  useEffect(() => {
    const onRejection = (event: PromiseRejectionEvent) => {
      console.error('[unhandled rejection]', event.reason)
    }
    const onError = (event: ErrorEvent) => {
      console.error('[uncaught error]', event.error ?? event.message)
    }
    window.addEventListener('unhandledrejection', onRejection)
    window.addEventListener('error', onError)
    return () => {
      window.removeEventListener('unhandledrejection', onRejection)
      window.removeEventListener('error', onError)
    }
  }, [])
}

/**
 * Global SWR defaults.
 *
 * SWR is deliberately the *only* cache in this app. Secret material must not
 * enter Next.js's Data Cache or Full Route Cache — those persist to disk under
 * `.next/cache` and survive process restarts, which is not somewhere decrypted
 * secrets belong. Keeping reads client-side in an in-memory SWR store means the
 * cache dies with the tab, which is the correct lifetime for this data.
 */
export function Providers({ children }: { children: ReactNode }) {
  useGlobalRejectionHandler()
  const { logout, isAuthenticated } = useAuth()

  return (
    <SWRConfig
      value={{
        // Vault data changes out-of-band (CLI, SDK, other operators), so
        // refresh on focus — but dedupe bursts from remounting components.
        revalidateOnFocus: true,
        revalidateOnReconnect: true,
        dedupingInterval: 2000,
        errorRetryCount: 2,

        // Never retry what will never succeed: 401 needs re-auth, 403 needs a
        // policy change, 404 means it's gone. Hammering them wastes requests
        // and buries the real message behind a spinner.
        shouldRetryOnError: (err: unknown) => {
          if (err instanceof ApiError) {
            return !err.isAuthError && !err.isPermissionError && !err.isNotFound
          }
          return true
        },

        onError: (err: unknown, key: string) => {
          console.error(`[swr] ${key}:`, err)
          // A dead token must dump the session. Otherwise the Leases page (and
          // every other GET) shows a red error while the chrome still looks
          // logged in — revoke/expire would look like a broken table.
          if (isAuthenticated && err instanceof ApiError && err.isAuthError) {
            logout()
          }
        },

        // Show the previous page of data while a new key loads instead of
        // flashing a skeleton — keeps the tree stable while switching secrets.
        keepPreviousData: true,
      }}
    >
      {children}
      <VaultTransitionHost />
    </SWRConfig>
  )
}
