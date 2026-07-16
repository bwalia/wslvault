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
import { safeStorage } from '@/lib/safe'

type Theme = 'light' | 'dark' | 'system'

interface ThemeContextType {
  theme: Theme
  setTheme(t: Theme): void
  resolvedTheme: 'light' | 'dark'
}

const ThemeContext = createContext<ThemeContextType | null>(null)

const THEMES: readonly Theme[] = ['light', 'dark', 'system']
const isTheme = (v: unknown): v is Theme => typeof v === 'string' && THEMES.includes(v as Theme)

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>('system')
  const [resolved, setResolved] = useState<'light' | 'dark'>('light')

  useEffect(() => {
    // Validate rather than cast: the old code cast whatever was in storage to
    // `Theme`, so a junk value silently became an unhandled theme.
    const stored = safeStorage.get('vault_theme')
    if (isTheme(stored)) setThemeState(stored)
  }, [])

  useEffect(() => {
    const isDark =
      theme === 'dark' ||
      (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches)
    document.documentElement.classList.toggle('dark', isDark)
    setResolved(isDark ? 'dark' : 'light')

    // safeStorage, not localStorage.setItem: this provider wraps the entire app
    // and sits above every error boundary. A raw setItem throws in Safari
    // private mode, which took the whole app to a white screen — over a theme
    // preference.
    safeStorage.set('vault_theme', theme)
  }, [theme])

  // Follow the OS while on 'system' — previously this was read once at mount,
  // so switching the OS to dark mid-session did nothing until a reload.
  useEffect(() => {
    if (theme !== 'system') return
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (e: MediaQueryListEvent) => {
      document.documentElement.classList.toggle('dark', e.matches)
      setResolved(e.matches ? 'dark' : 'light')
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [theme])

  const setTheme = useCallback((t: Theme) => setThemeState(t), [])

  const value = useMemo<ThemeContextType>(
    () => ({ theme, setTheme, resolvedTheme: resolved }),
    [theme, setTheme, resolved],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider')
  return ctx
}
