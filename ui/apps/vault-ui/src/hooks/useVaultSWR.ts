'use client'

import { useCallback, useMemo } from 'react'
import useSWR, { type SWRConfiguration, type SWRResponse } from 'swr'
import { useAuth } from '@/contexts/AuthContext'
import { createFetcher, mutate as rawMutate, ApiError } from '@/lib/fetcher'

/**
 * Credential-bound data hooks.
 *
 * Every page previously called `createFetcher(token, tenantId)` inline during
 * render. That allocates a new function on every render, and SWR keys part of
 * its dedup/revalidation behaviour off fetcher identity — so the "cache" was
 * doing far less than it appeared to. Memoizing on `[token, tenantId]` gives
 * SWR a stable fetcher that only changes when the credentials actually do.
 */

/** A fetcher bound to the current session, stable across renders. */
export function useFetcher() {
  const { token, tenantId } = useAuth()
  return useMemo(() => createFetcher(token, tenantId), [token, tenantId])
}

/**
 * `useSWR` with the session fetcher pre-bound.
 *
 * Pass `null` as the key to skip the request (SWR's conditional-fetch
 * convention) — e.g. while no secret is selected.
 */
export function useVaultSWR<T = unknown>(
  key: string | null,
  config?: SWRConfiguration<T, ApiError>,
): SWRResponse<T, ApiError> {
  const fetcher = useFetcher()
  return useSWR<T, ApiError>(key, fetcher as (url: string) => Promise<T>, config)
}

/**
 * A mutation function bound to the current session, stable across renders.
 *
 * Returns the parsed response body so callers can inspect endpoints that report
 * work done in the body rather than the status code.
 */
export function useVaultMutate() {
  const { token, tenantId } = useAuth()
  return useCallback(
    <T = unknown>(url: string, method: 'POST' | 'PUT' | 'PATCH' | 'DELETE', body?: unknown) =>
      rawMutate<T>(url, method, body ?? null, token, tenantId),
    [token, tenantId],
  )
}
