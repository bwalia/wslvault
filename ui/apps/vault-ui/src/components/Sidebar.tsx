'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import {
  LayoutDashboard,
  Key,
  Shield,
  Users,
  Activity,
  Settings,
  Lock,
  Cpu,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  Globe,
  Server,
  UserCog,
} from 'lucide-react'

const navGroups = [
  {
    label: 'Vault',
    items: [
      { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { href: '/secrets', label: 'Secrets', icon: Lock },
      { href: '/transit', label: 'Transit', icon: Cpu },
    ],
  },
  {
    label: 'Access',
    items: [
      { href: '/policies', label: 'Policies', icon: Shield },
      { href: '/identity', label: 'Identity', icon: Users },
      { href: '/leases', label: 'Leases', icon: Key },
      { href: '/scim', label: 'SCIM', icon: UserCog },
    ],
  },
  {
    label: 'Infrastructure',
    items: [
      { href: '/regions', label: 'Regions', icon: Globe },
      { href: '/cluster', label: 'Cluster', icon: Server },
    ],
  },
  {
    label: 'Manage',
    items: [
      { href: '/tenants', label: 'Tenants', icon: ShieldCheck },
      { href: '/audit', label: 'Audit log', icon: Activity },
      { href: '/settings', label: 'Settings', icon: Settings },
    ],
  },
]

interface SidebarProps {
  open: boolean
  onToggle(): void
}

/**
 * "Vault steel" sidebar — dark in both themes. The one deliberately bold
 * surface in the app; everything inside the content plane stays quiet.
 */
export default function Sidebar({ open, onToggle }: SidebarProps) {
  const pathname = usePathname()

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 h-full z-40 flex flex-col',
        'bg-steel border-r border-steel-line',
        'transition-all duration-200',
        open ? 'w-60' : 'w-16',
      )}
    >
      {/* Wordmark */}
      <div className="flex items-center h-14 px-4 border-b border-steel-line gap-3">
        <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-primary-600 flex items-center justify-center">
          <Lock className="w-4 h-4 text-white" aria-hidden="true" />
        </div>
        {open && (
          <span className="font-semibold tracking-tight text-white truncate">
            WSL<span className="text-primary-300">Vault</span>
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 space-y-5 px-3" aria-label="Primary">
        {navGroups.map(group => (
          <div key={group.label}>
            {open && (
              <p className="mb-1.5 px-2 text-[11px] font-medium uppercase tracking-widest text-steel-ink-dim">
                {group.label}
              </p>
            )}
            <ul className="space-y-0.5">
              {group.items.map(item => {
                const active =
                  pathname === item.href || pathname.startsWith(item.href + '/')
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      title={!open ? item.label : undefined}
                      aria-current={active ? 'page' : undefined}
                      className={cn(
                        'relative flex items-center gap-3 px-2.5 py-2 rounded-lg text-sm transition-colors',
                        active
                          ? 'bg-steel-raised text-white font-medium'
                          : 'text-steel-ink hover:bg-steel-raised hover:text-white',
                      )}
                    >
                      {/* Active tick — a thin primary rule, not a filled pill */}
                      {active && (
                        <span
                          className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 rounded-full bg-primary-400"
                          aria-hidden="true"
                        />
                      )}
                      <item.icon
                        className={cn('w-[18px] h-[18px] flex-shrink-0', active && 'text-primary-300')}
                        aria-hidden="true"
                      />
                      {open && <span className="truncate">{item.label}</span>}
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>

      {/* Toggle button */}
      <button
        onClick={onToggle}
        className="m-3 flex items-center justify-center h-9 rounded-lg text-steel-ink-dim hover:bg-steel-raised hover:text-steel-ink transition-colors focus-ring"
        aria-label={open ? 'Collapse sidebar' : 'Expand sidebar'}
      >
        {open ? <ChevronLeft className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
      </button>
    </aside>
  )
}
