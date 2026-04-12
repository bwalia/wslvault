'use client'
import { useState } from 'react'
import { Menu, Sun, Moon, Monitor, LogOut, ChevronDown } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { useTheme } from '@/contexts/ThemeContext'
import { cn } from '@/lib/utils'
import { getRemainingSeconds, formatDuration } from '@/lib/utils'

export default function AppBar({ onMenuClick }: { onMenuClick(): void }) {
  const { logout, tenantId, policies, expiresAt } = useAuth()
  const { theme, setTheme } = useTheme()
  const [userOpen, setUserOpen] = useState(false)

  const remaining = expiresAt
    ? getRemainingSeconds(new Date(expiresAt).toISOString())
    : 0
  const expiryColor =
    remaining > 3600
      ? 'text-accent-600'
      : remaining > 300
        ? 'text-warn-600'
        : 'text-danger-600'

  return (
    <header className="sticky top-0 z-30 flex items-center gap-3 h-14 px-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur border-b border-slate-200 dark:border-slate-800">
      <button
        onClick={onMenuClick}
        className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500"
        aria-label="Toggle menu"
      >
        <Menu className="w-5 h-5" />
      </button>

      <span className="flex-1" />

      {/* Token expiry */}
      {expiresAt && (
        <span className={cn('text-xs font-mono', expiryColor)}>{formatDuration(remaining)}</span>
      )}

      {/* Theme toggle */}
      <div className="flex items-center rounded-lg border border-slate-200 dark:border-slate-700 p-0.5">
        {(['light', 'system', 'dark'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTheme(t)}
            aria-label={`Set theme to ${t}`}
            className={cn(
              'p-1.5 rounded-md transition-colors',
              theme === t
                ? 'bg-primary-100 dark:bg-primary-900/40 text-primary-600 dark:text-primary-400'
                : 'text-slate-400 hover:text-slate-600',
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
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-sm text-slate-700 dark:text-slate-300"
        >
          <span className="w-7 h-7 rounded-full bg-primary-100 dark:bg-primary-900/40 flex items-center justify-center text-primary-700 dark:text-primary-300 text-xs font-bold">
            {policies[0]?.[0]?.toUpperCase() ?? 'U'}
          </span>
          <span className="hidden sm:block max-w-32 truncate">{policies[0] ?? 'user'}</span>
          <ChevronDown className="w-4 h-4" />
        </button>
        {userOpen && (
          <div className="absolute right-0 mt-1 w-56 bg-white dark:bg-slate-900 rounded-lg shadow-lg border border-slate-200 dark:border-slate-800 py-1 z-50">
            <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800">
              <p className="text-xs text-slate-500">Tenant</p>
              <p className="text-sm font-mono truncate">{tenantId ?? '—'}</p>
            </div>
            <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800">
              <p className="text-xs text-slate-500 mb-1">Policies</p>
              <div className="flex flex-wrap gap-1">
                {policies.map(p => (
                  <span
                    key={p}
                    className="text-xs bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300 px-1.5 py-0.5 rounded"
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
            <button
              onClick={logout}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm text-danger-600 hover:bg-danger-50 dark:hover:bg-danger-900/20 transition-colors"
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
