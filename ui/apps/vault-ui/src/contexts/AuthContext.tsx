'use client'
import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  type ReactNode,
} from 'react'
import { useRouter } from 'next/navigation'
import { mutate as swrMutate } from 'swr'
import type { VaultDirection } from '@/components/VaultTransition'
import { safeStorage, safeJsonParse } from '@/lib/safe'
import { api } from '@/lib/api'
import { ApiError } from '@/lib/fetcher'

interface AuthState {
  token: string | null
  tenantId: string | null
  policies: string[]
  expiresAt: number | null // timestamp ms
  /** Lease created at login. Missing when lease-manager was down (degraded). */
  leaseId: string | null
}

/** Returned when the key is right but a second factor is still needed. */
export interface MfaChallenge {
  challenge: string
  expiresInSeconds: number
}

interface AuthContextType extends AuthState {
  /**
   * Exchange an API key for a session.
   *
   * Resolves to an `MfaChallenge` when the key requires an authenticator code —
   * the key was accepted, but no session exists yet. Resolves to `null` when the
   * session is established. Machine keys never see a challenge.
   */
  login(apiKey: string): Promise<MfaChallenge | null>
  /** Complete a login by answering its challenge with a code. */
  verifyMfa(challenge: string, code: string): Promise<void>
  /** Which end-of-session animation is running, if any. Rendered at the app
   *  root so it covers whichever layout the user happens to be in — sign-out
   *  starts from the dashboard, where the auth layout is not mounted. */
  vaultTransition: VaultDirection | null
  logout(): void
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextType | null>(null)

const STORAGE_KEYS = [
  'vault_token',
  'vault_tenant_id',
  'vault_policies',
  'vault_expires_at',
  'vault_lease_id',
] as const

/** How long the vault-opening sequence runs before the dashboard replaces it.
 *  Must stay in step with VaultOpening's choreography — the confirmation lands
 *  at ~1.15s, and this leaves a beat to read it. */
const UNLOCK_ANIMATION_MS = 1900

/** Sign-out. Was 1500ms, which cut the "Vault sealed" line off mid-fade: it
 *  finished appearing at 1650ms, so it never reached full opacity before the
 *  route changed. Long enough now for the message to be read, and no longer. */
const SEAL_ANIMATION_MS = 1950

/** How long the overlay outlives the `router.push` that it is covering.
 *
 *  Navigation is not instantaneous, and unmounting the overlay the moment it is
 *  requested reveals whatever is still underneath. This holds it for a few
 *  frames past the push so the new route is what appears when it lifts. */
const OVERLAP_MS = 350

const EMPTY_STATE: AuthState = {
  token: null,
  tenantId: null,
  policies: [],
  expiresAt: null,
  leaseId: null,
}

/** Remove every session key. Partial clears leave a half-session behind. */
function clearStoredSession(): void {
  STORAGE_KEYS.forEach(k => safeStorage.remove(k))
}

/** Read a session back from storage, or null if absent/expired/corrupt. */
/**
 * The token's own lifetime in milliseconds, from its `iat`/`exp` claims.
 *
 * Both are stamped by the same server clock, so their difference is the true
 * TTL no matter how far this device's clock sits from the server's. Callers
 * start the countdown at the moment of receipt, so session validity is measured
 * entirely in local time — immune to clock skew between browser and server.
 * Comparing the server's *absolute* `expires_at` to `Date.now()` was not: a
 * browser clock running ahead of the server made a freshly issued token look
 * already expired, and the dashboard guard bounced the user back to /login.
 *
 * Returns null for a malformed token, so the caller can fall back to the
 * absolute expiry rather than fail login outright.
 */
function jwtLifetimeMs(token: string): number | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    b64 += '='.repeat((4 - (b64.length % 4)) % 4)
    const claims = JSON.parse(atob(b64)) as { iat?: unknown; exp?: unknown }
    const iat = typeof claims.iat === 'number' ? claims.iat : null
    const exp = typeof claims.exp === 'number' ? claims.exp : null
    if (iat !== null && exp !== null && exp > iat) return (exp - iat) * 1000
  } catch {
    /* malformed payload — fall back to the absolute expiry */
  }
  return null
}

function readStoredSession(): AuthState | null {
  const token = safeStorage.get('vault_token')
  if (!token) return null

  const expiresAt = Number(safeStorage.get('vault_expires_at') ?? '0')
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return null

  // `vault_policies` is just a localStorage key — anything on the machine can
  // write junk to it. Parse defensively rather than trusting the shape.
  const parsed = safeJsonParse<unknown>(safeStorage.get('vault_policies') ?? '[]')
  const policies =
    parsed.ok && Array.isArray(parsed.value)
      ? (parsed.value as unknown[]).filter((p): p is string => typeof p === 'string')
      : []

  return {
    token,
    tenantId: safeStorage.get('vault_tenant_id'),
    policies,
    expiresAt,
    leaseId: safeStorage.get('vault_lease_id') || null,
  }
}

interface AuthResponse {
  token: string
  tenant_id: string
  policies: string[]
  expires_at: string
  lease_id?: string
}

/** The body returned instead of a token when a second factor is required. */
interface ChallengeResponse {
  mfa_required: true
  challenge: string
  expires_in_seconds: number
}

function isChallenge(body: unknown): body is ChallengeResponse {
  return (
    typeof body === 'object' &&
    body !== null &&
    (body as { mfa_required?: unknown }).mfa_required === true &&
    typeof (body as { challenge?: unknown }).challenge === 'string'
  )
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter()
  const [isMounted, setIsMounted] = useState(false)
  const [vaultTransition, setVaultTransition] = useState<VaultDirection | null>(null)
  const [state, setState] = useState<AuthState>(EMPTY_STATE)

  // Restore on mount. This runs before any error boundary exists, so every
  // step of it must be total — see `readStoredSession`.
  useEffect(() => {
    setIsMounted(true)
    const restored = readStoredSession()
    if (restored) setState(restored)
    else clearStoredSession()
  }, [])

  const logout = useCallback(() => {
    clearStoredSession()
    setState(EMPTY_STATE)

    // Drop every cached response, without revalidating. The cache is keyed by
    // URL and those URLs are identical across tenants — `/v1/api-keys` is
    // `/v1/api-keys` whoever asks — so anything left behind is rendered to
    // whoever signs in next. `keepPreviousData` in the SWR config means it is
    // shown eagerly rather than behind a spinner, and on a shared machine that
    // is one tenant's secrets appearing in another tenant's window.
    void swrMutate(() => true, undefined, { revalidate: false })

    // The session is already gone by this point — the animation covers the
    // navigation, it does not gate it. If anything here failed, the user would
    // still be signed out.
    const wantsMotion =
      typeof window !== 'undefined' &&
      !window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

    if (!wantsMotion) {
      router.push('/login')
      return
    }

    setVaultTransition('closing')
    window.setTimeout(() => {
      router.push('/login')
      window.setTimeout(() => setVaultTransition(null), OVERLAP_MS)
    }, SEAL_ANIMATION_MS)
  }, [router])

  /** Turn a successful auth response into a live session. */
  const establishSession = useCallback(
    (data: AuthResponse | null) => {
      if (!data?.token) {
        throw new ApiError('Malformed response from identity-service', 502)
      }

      // Count the session down from the token's own lifetime against THIS
      // device's clock, not the server's absolute expiry against our clock —
      // otherwise a browser clock ahead of the server makes a fresh token look
      // expired and the dashboard guard bounces the user back to /login. See
      // jwtLifetimeMs. Falls back to the absolute expiry for a malformed token.
      const lifetimeMs = jwtLifetimeMs(data.token)
      const expiresAt =
        lifetimeMs !== null ? Date.now() + lifetimeMs : new Date(data.expires_at).getTime()
      if (!Number.isFinite(expiresAt)) {
        throw new ApiError('Identity-service returned an invalid expiry', 502)
      }

      const policies = Array.isArray(data.policies) ? data.policies : []

      // A failed write is not fatal — the session works for this tab, it just
      // won't survive a reload. Better than blocking login outright.
      const leaseId = data.lease_id?.trim() ? data.lease_id.trim() : null
      const persisted =
        safeStorage.set('vault_token', data.token) &&
        safeStorage.set('vault_tenant_id', data.tenant_id ?? '') &&
        safeStorage.set('vault_policies', JSON.stringify(policies)) &&
        safeStorage.set('vault_expires_at', String(expiresAt)) &&
        (leaseId
          ? safeStorage.set('vault_lease_id', leaseId)
          : (safeStorage.remove('vault_lease_id'), true))
      if (!persisted) {
        console.warn('[auth] session could not be persisted; it will not survive a reload')
      }

      setState({
        token: data.token,
        tenantId: data.tenant_id ?? null,
        policies,
        expiresAt,
        leaseId,
      })

      // Hold on the opening sequence before navigating. The session is already
      // live at this point, so nothing is being delayed except the view — and
      // the pause covers the dashboard's first fetch, which would otherwise be
      // a screen of skeletons.
      //
      // Skipped entirely under reduced motion: someone who has asked for less
      // motion should not also be asked to wait for it.
      const wantsMotion =
        typeof window !== 'undefined' &&
        !window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

      if (!wantsMotion) {
        router.push('/dashboard')
        return
      }

      setVaultTransition('opening')
      window.setTimeout(() => {
        // Navigate FIRST, clear after. Clearing first unmounted the overlay
        // while the push was still in flight, uncovering the login form for a
        // few frames — the flash of the page you just left, right at the end
        // of an animation whose whole job is to hide the swap.
        router.push('/dashboard')
        window.setTimeout(() => setVaultTransition(null), OVERLAP_MS)
      }, UNLOCK_ANIMATION_MS)
    },
    [router],
  )

  /** POST a body to an auth endpoint, distinguishing "API is down" from "rejected". */
  const postAuth = useCallback(async (url: string, body: unknown): Promise<unknown> => {
    let res: Response
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        cache: 'no-store',
      })
    } catch {
      // fetch() rejects only on network failure. Without this the login page
      // shows "Authentication failed" when the truth is the API is down —
      // sending the user to re-check a key that was never the problem.
      throw new ApiError('Cannot reach the vault API. Is the backend running?', 0)
    }

    if (!res.ok) {
      const err = (await res.json().catch(() => ({}))) as { message?: string }
      throw new ApiError(err.message ?? 'Authentication failed', res.status)
    }
    return await res.json().catch(() => null)
  }, [])

  const login = useCallback(
    async (apiKey: string): Promise<MfaChallenge | null> => {
      const body = await postAuth(api.identity.authApiKey(), { api_key: apiKey })

      // The key was accepted but a second factor is outstanding. Hand the
      // challenge back rather than throwing: this is a step in the flow, not a
      // failure, and the caller needs it to complete the login.
      if (isChallenge(body)) {
        return { challenge: body.challenge, expiresInSeconds: body.expires_in_seconds }
      }

      establishSession(body as AuthResponse | null)
      return null
    },
    [postAuth, establishSession],
  )

  const verifyMfa = useCallback(
    async (challenge: string, code: string) => {
      const body = await postAuth(api.identity.mfaTotp(), { challenge, code })
      establishSession(body as AuthResponse | null)
    },
    [postAuth, establishSession],
  )

  // Log out the moment the token expires rather than waiting for the next
  // request to 401. Otherwise the UI keeps rendering as if authenticated and
  // every action fails with a confusing message.
  useEffect(() => {
    if (!state.expiresAt) return
    const ms = state.expiresAt - Date.now()
    if (ms <= 0) {
      logout()
      return
    }
    // setTimeout clamps above ~24.8 days; vault tokens are hours, but guard
    // anyway so a bogus expiry can't fire immediately.
    const timer = setTimeout(logout, Math.min(ms, 2_147_483_647))
    return () => clearTimeout(timer)
  }, [state.expiresAt, logout])

  const isAuthenticated = isMounted && !!state.token && (state.expiresAt ?? 0) > Date.now()

  // Without useMemo this object is new every render, so every useAuth consumer
  // re-renders on every AuthProvider render — and any hook that depends on
  // `logout` (e.g. useAsyncAction) gets a fresh identity each time, defeating
  // its own memoization.
  const value = useMemo<AuthContextType>(
    () => ({ ...state, login, verifyMfa, logout, isAuthenticated, vaultTransition }),
    [state, login, verifyMfa, logout, isAuthenticated, vaultTransition],
  )

  if (!isMounted) return null

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
