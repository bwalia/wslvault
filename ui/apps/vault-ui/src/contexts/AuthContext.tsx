'use client'
import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useRouter } from 'next/navigation'

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

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter()
  const [isMounted, setIsMounted] = useState(false)
  const [state, setState] = useState<AuthState>({
    token: null,
    tenantId: null,
    policies: [],
    expiresAt: null,
  })

  useEffect(() => {
    setIsMounted(true)
    const token = localStorage.getItem('vault_token')
    const tenantId = localStorage.getItem('vault_tenant_id')
    const policies = JSON.parse(localStorage.getItem('vault_policies') ?? '[]') as string[]
    const expiresAt = Number(localStorage.getItem('vault_expires_at') ?? '0')
    if (token && expiresAt > Date.now()) {
      setState({ token, tenantId, policies, expiresAt })
    } else {
      localStorage.removeItem('vault_token')
    }
  }, [])

  const login = async (apiKey: string) => {
    const res = await fetch('/api/identity/v1/auth/api-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: apiKey }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error((err as { message?: string }).message ?? 'Authentication failed')
    }
    const data = await res.json() as {
      token: string
      tenant_id: string
      policies: string[]
      expires_at: string
    }
    const expiresAt = new Date(data.expires_at).getTime()
    localStorage.setItem('vault_token', data.token)
    localStorage.setItem('vault_tenant_id', data.tenant_id)
    localStorage.setItem('vault_policies', JSON.stringify(data.policies))
    localStorage.setItem('vault_expires_at', String(expiresAt))
    setState({
      token: data.token,
      tenantId: data.tenant_id,
      policies: data.policies,
      expiresAt,
    })
    router.push('/dashboard')
  }

  const logout = () => {
    ;['vault_token', 'vault_tenant_id', 'vault_policies', 'vault_expires_at'].forEach(k =>
      localStorage.removeItem(k),
    )
    setState({ token: null, tenantId: null, policies: [], expiresAt: null })
    router.push('/login')
  }

  const isAuthenticated = isMounted && !!state.token && (state.expiresAt ?? 0) > Date.now()

  if (!isMounted) return null

  return (
    <AuthContext.Provider value={{ ...state, login, logout, isAuthenticated }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
