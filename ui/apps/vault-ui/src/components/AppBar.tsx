'use client'
import { useState } from 'react'
import { Menu, Sun, Moon, Monitor, LogOut, ChevronDown, Timer } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { useVaultSWR } from '@/hooks/useVaultSWR'
import { api } from '@/lib/api'
import { useTheme } from '@/contexts/ThemeContext'
import { cn } from '@/lib/utils'
import { getRemainingSeconds, formatDuration } from '@/lib/utils'

export default function AppBar({ onMenuClick }: { onMenuClick(): void }) {
  const { logout, tenantId, policies, expiresAt } = useAuth()

  // Resolve the tenant's human name. A raw UUID in the chrome tells a
  // non-technical user nothing — "Vault 01a065e6" is not an answer to "whose
  // data am I looking at".
  //
  // The lookup needs the administrator policy, so an ordinary member gets a
  // 403. That is expected rather than an error: the short id is a correct, if
  // duller, answer, and SWR is told not to retry so a member's session does not
  // re-request a forbidden endpoint on every navigation.
  const { data: tenant } = useVaultSWR<{ display_name?: string }>(
    tenantId ? api.identity.tenant(tenantId) : null,
    { shouldRetryOnError: false },
  )
  const tenantLabel =
    tenant?.display_name?.trim() || (tenantId ? tenantId.slice(0, 8) : '')
  const { theme, setTheme } = useTheme()
  const [userOpen, setUserOpen] = useState(false)

  const remaining = expiresAt
    ? getRemainingSeconds(new Date(expiresAt).toISOString())
    : 0
  // Quiet by default; amber only inside the final 15 minutes, red inside 5.
  const expiryColor =
    remaining > 900
      ? 'text-ink-muted'
      : remaining > 300
        ? 'text-warn-600 dark:text-warn-500'
        : 'text-danger-600 dark:text-danger-400'

  return (
    <header className="sticky top-0 z-30 flex items-center gap-3 h-14 px-6 bg-canvas/90 backdrop-blur border-b border-line">
      <button
        onClick={onMenuClick}
        className="p-1.5 rounded-lg hover:bg-surface-2 text-ink-muted focus-ring"
        aria-label="Toggle menu"
      >
        <Menu className="w-5 h-5" />
      </button>

      {/* Which vault you are in. Surfaced in the bar rather than buried in a
          menu: on a product whose premise is tenant isolation, "whose data am
          I looking at" is the one thing the chrome must always answer. */}
      {tenantId && (
        <div className="hidden md:flex items-center gap-2 pl-1">
          <span
            className="w-1.5 h-1.5 rounded-full bg-accent-500"
            aria-hidden="true"
          />
          <span className="text-sm text-ink-muted">
            <span className="text-ink-faint">Vault</span>{' '}
            <span className="font-medium text-ink">{tenantLabel}</span>
          </span>
        </div>
      )}

      <span className="flex-1" />

      {/* Session expiry — labeled, not a bare number */}
      {expiresAt && (
        <span
          className={cn('inline-flex items-center gap-1.5 text-xs font-mono tabular', expiryColor)}
          title="Session time remaining"
        >
          <Timer className="w-3.5 h-3.5" aria-hidden="true" />
          {formatDuration(remaining)}
        </span>
      )}

      {/* Theme toggle */}
      <div className="flex items-center rounded-lg border border-line p-0.5" role="group" aria-label="Theme">
        {(['light', 'system', 'dark'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTheme(t)}
            aria-label={`Set theme to ${t}`}
            aria-pressed={theme === t}
            className={cn(
              'p-1.5 rounded-md transition-colors focus-ring',
              theme === t
                ? 'bg-surface-3 text-ink'
                : 'text-ink-faint hover:text-ink-muted',
            )}
          >
            {t === 'light' ? (
              <Sun className="w-4 h-4" />
            ) : t === 'dark' ? (
              <Moon className="w-4 h-4" />
            ) : (
              <Monitor className="w-4 h-4" />
            )}
          </button>
        ))}
      </div>

      {/* User menu */}
      <div className="relative">
        <button
          onClick={() => setUserOpen(o => !o)}
          aria-expanded={userOpen}
          aria-haspopup="menu"
          className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg hover:bg-surface-2 text-sm text-ink focus-ring"
        >
          <span className="w-7 h-7 rounded-full bg-brass flex items-center justify-center text-steel text-xs font-bold">
            {policies[0]?.[0]?.toUpperCase() ?? 'U'}
          </span>
          <span className="hidden sm:block max-w-32 truncate">{policies[0] ?? 'user'}</span>
          <ChevronDown className="w-4 h-4 text-ink-faint" />
        </button>
        {userOpen && (
          <div className="absolute right-0 mt-1 w-60 bg-surface rounded-xl shadow-2xl border border-line py-1 z-50">
            <div className="px-3 py-2 border-b border-line">
              <p className="text-xs text-ink-faint">Tenant</p>
              <p className="text-sm font-mono truncate text-ink" title={tenantId ?? undefined}>
                {tenantId ?? '—'}
              </p>
            </div>
            <div className="px-3 py-2 border-b border-line">
              <p className="text-xs text-ink-faint mb-1.5">Policies</p>
              <div className="flex flex-wrap gap-1">
                {policies.map(p => (
                  <span
                    key={p}
                    className="text-xs font-mono bg-surface-2 border border-line text-ink-muted px-1.5 py-0.5 rounded"
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
            <button
              onClick={logout}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-danger-600 dark:text-danger-400 hover:bg-danger-50 dark:hover:bg-danger-600/10 transition-colors"
            >
              <LogOut className="w-4 h-4" />
              Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  )
}
