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
    router.push('/login')
  }, [router])

  /** Turn a successful auth response into a live session. */
  const establishSession = useCallback(
    (data: AuthResponse | null) => {
      if (!data?.token) {
        throw new ApiError('Malformed response from identity-service', 502)
      }

      const expiresAt = new Date(data.expires_at).getTime()
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
      router.push('/dashboard')
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
    () => ({ ...state, login, verifyMfa, logout, isAuthenticated }),
    [state, login, verifyMfa, logout, isAuthenticated],
  )

  if (!isMounted) return null

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
