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
}

interface AuthContextType extends AuthState {
  login(apiKey: string): Promise<void>
  logout(): void
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextType | null>(null)

const STORAGE_KEYS = ['vault_token', 'vault_tenant_id', 'vault_policies', 'vault_expires_at'] as const

const EMPTY_STATE: AuthState = { token: null, tenantId: null, policies: [], expiresAt: null }

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
  }
}

interface AuthResponse {
  token: string
  tenant_id: string
  policies: string[]
  expires_at: string
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

  const login = useCallback(
    async (apiKey: string) => {
      let res: Response
      try {
        res = await fetch(api.identity.authApiKey(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ api_key: apiKey }),
          cache: 'no-store',
        })
      } catch {
        // fetch() rejects only on network failure. Without this the login page
        // shows "Authentication failed" when the truth is the API is down —
        // sending the user to re-check a key that was never the problem.
        throw new ApiError('Cannot reach the vault API. Is the backend running?', 0)
      }

      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { message?: string }
        throw new ApiError(body.message ?? 'Authentication failed', res.status)
      }

      const data = (await res.json().catch(() => null)) as AuthResponse | null
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
      const persisted =
        safeStorage.set('vault_token', data.token) &&
        safeStorage.set('vault_tenant_id', data.tenant_id ?? '') &&
        safeStorage.set('vault_policies', JSON.stringify(policies)) &&
        safeStorage.set('vault_expires_at', String(expiresAt))
      if (!persisted) {
        console.warn('[auth] session could not be persisted; it will not survive a reload')
      }

      setState({ token: data.token, tenantId: data.tenant_id ?? null, policies, expiresAt })
      router.push('/dashboard')
    },
    [router],
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
    () => ({ ...state, login, logout, isAuthenticated }),
    [state, login, logout, isAuthenticated],
  )

  if (!isMounted) return null

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
