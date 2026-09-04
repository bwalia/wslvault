'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import { useAuth } from '@/contexts/AuthContext'
import BuildStamp from '@/components/BuildStamp'
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
  Smartphone,
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
      { href: '/policies', label: 'Policies', icon: Shield, adminOnly: true },
      { href: '/identity', label: 'Identity', icon: Users, adminOnly: true },
      { href: '/leases', label: 'Leases', icon: Key },
      { href: '/mfa', label: 'MFA', icon: Smartphone },
      { href: '/scim', label: 'SCIM', icon: UserCog, adminOnly: true },
    ],
  },
  {
    label: 'Infrastructure',
    items: [
      { href: '/regions', label: 'Regions', icon: Globe, adminOnly: true },
      { href: '/cluster', label: 'Cluster', icon: Server, adminOnly: true },
    ],
  },
  {
    label: 'Manage',
    items: [
      { href: '/tenants', label: 'Tenants', icon: ShieldCheck, adminOnly: true },
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
 * Whether to offer the administrator-only destinations.
 *
 * This is presentation only, and must never be mistaken for access control.
 * `policies` is restored from localStorage, which anything on the machine can
 * edit — so a determined visitor can make every link appear. That is harmless:
 * the server re-checks on every request and answers 403, which is where the
 * actual boundary lives.
 *
 * What it fixes is the ordinary case. A tenant member was previously shown
 * Tenants, Identity, Policies, SCIM, Regions and Cluster, and every one of them
 * failed with a permissions error the moment it loaded — the app advertised six
 * destinations that existed only to refuse them.
 *
 * Both spellings are accepted because the required policy is deployment
 * configuration (`VAULT_ADMIN_POLICY`): the compiled default is
 * `wslvault:platform-admin`, while the chart currently pins `admin`. The UI
 * cannot see which is in force, and guessing wrong in the hiding direction
 * would strand a real administrator.
 */
function canAdminister(policies: string[]): boolean {
  return policies.some(p => p === 'wslvault:platform-admin' || p === 'admin' || p === 'root')
}

/**
 * "Vault steel" sidebar — dark in both themes. The one deliberately bold
 * surface in the app; everything inside the content plane stays quiet.
 */
export default function Sidebar({ open, onToggle }: SidebarProps) {
  const pathname = usePathname()
  const { policies } = useAuth()
  const isAdmin = canAdminister(policies)

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 h-full z-40 flex flex-col',
        'bg-steel border-r border-steel-line',
        'transition-all duration-200',
        open ? 'w-64' : 'w-[4.5rem]',
      )}
    >
      {/* Wordmark */}
      <div className="flex items-center h-16 px-4 border-b border-steel-line gap-3">
        <div className="shrink-0 w-9 h-9 rounded-lg bg-primary-700 ring-1 ring-brass/30 flex items-center justify-center">
          <Lock className="w-[18px] h-[18px] text-brass" aria-hidden="true" />
        </div>
        {open && (
          <span className="font-display text-lg font-semibold tracking-tight text-white truncate">
            WSL<span className="text-brass">Vault</span>
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 space-y-5 px-3" aria-label="Primary">
        {navGroups.map(group => {
          const items = group.items.filter(item => isAdmin || !item.adminOnly)
          // Infrastructure is entirely administrative, so for a tenant member
          // the whole group empties. Rendering its heading over nothing would
          // read as a loading failure.
          if (items.length === 0) return null
          return (
          <div key={group.label}>
            {open && (
              <p className="mb-2 px-2 font-display text-xs font-semibold uppercase tracking-[0.12em] text-steel-ink">
                {group.label}
              </p>
            )}
            <ul className="space-y-0.5">
              {items.map(item => {
                const active =
                  pathname === item.href || pathname.startsWith(item.href + '/')
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      title={!open ? item.label : undefined}
                      aria-current={active ? 'page' : undefined}
                      className={cn(
                        'relative flex items-center gap-3 px-2.5 py-2.5 rounded-lg text-sm transition-colors',
                        active
                          ? 'bg-steel-raised text-white font-medium'
                          : 'text-steel-ink hover:bg-steel-raised hover:text-white',
                      )}
                    >
                      {/* Active tick — brass, matching the CTA and the vault mark */}
                      {active && (
                        <span
                          className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-full bg-brass"
                          aria-hidden="true"
                        />
                      )}
                      <item.icon
                        className={cn('w-5 h-5 shrink-0', active && 'text-brass')}
                        aria-hidden="true"
                      />
                      {open && <span className="truncate">{item.label}</span>}
                    </Link>
                  </li>
                )
              })}
            </ul>
          </div>
          )
        })}
      </nav>

      {/* Toggle button */}
      <button
        onClick={onToggle}
        className="m-3 flex items-center justify-center h-9 rounded-lg text-steel-ink-dim hover:bg-steel-raised hover:text-steel-ink transition-colors focus-ring"
        aria-label={open ? 'Collapse sidebar' : 'Expand sidebar'}
      >
        {open ? <ChevronLeft className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
      </button>
      <BuildStamp collapsed={!open} className={open ? 'mx-3 mb-3 text-xs' : 'mx-1 mb-3 text-[11px]'} />
    </aside>
  )
}
