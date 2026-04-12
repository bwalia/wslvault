'use client'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { cn } from '@/lib/utils'
import {
  LayoutDashboard,
  Key,
  FileText,
  Shield,
  Users,
  Activity,
  Settings,
  Lock,
  Cpu,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react'

// FileText is imported to keep the icon list complete; used for future extensions
void FileText

const navGroups = [
  {
    label: 'Navigation',
    items: [
      { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { href: '/secrets', label: 'Secrets', icon: Lock },
      { href: '/transit', label: 'Transit', icon: Cpu },
    ],
  },
  {
    label: 'Access Control',
    items: [
      { href: '/policies', label: 'Policies', icon: Shield },
      { href: '/identity', label: 'Identity', icon: Users },
      { href: '/leases', label: 'Leases', icon: Key },
    ],
  },
  {
    label: 'Management',
    items: [
      { href: '/tenants', label: 'Tenants', icon: ShieldCheck },
      { href: '/audit', label: 'Audit Log', icon: Activity },
      { href: '/settings', label: 'Settings', icon: Settings },
    ],
  },
]

interface SidebarProps {
  open: boolean
  onToggle(): void
}

export default function Sidebar({ open, onToggle }: SidebarProps) {
  const pathname = usePathname()

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 h-full z-40 flex flex-col',
        'bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800',
        'transition-all duration-300',
        open ? 'w-64' : 'w-18',
      )}
    >
      {/* Logo */}
      <div className="flex items-center h-14 px-4 border-b border-slate-200 dark:border-slate-800 gap-3">
        <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-primary-600 flex items-center justify-center">
          <Lock className="w-4 h-4 text-white" />
        </div>
        {open && (
          <span className="font-semibold text-slate-900 dark:text-white truncate">WSLVault</span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 space-y-6 px-3">
        {navGroups.map(group => (
          <div key={group.label}>
            {open && (
              <p className="mb-2 px-2 text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                {group.label}
              </p>
            )}
            <ul className="space-y-1">
              {group.items.map(item => {
                const active =
                  pathname === item.href || pathname.startsWith(item.href + '/')
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      title={!open ? item.label : undefined}
                      className={cn(
                        'flex items-center gap-3 px-2 py-2 rounded-lg text-sm font-medium transition-colors',
                        active
                          ? 'border-l-2 border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300 pl-[6px]'
                          : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100',
                      )}
                    >
                      <item.icon className="w-5 h-5 flex-shrink-0" />
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
        className="m-3 flex items-center justify-center h-9 rounded-lg text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
        aria-label={open ? 'Collapse sidebar' : 'Expand sidebar'}
      >
        {open ? <ChevronLeft className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
      </button>
    </aside>
  )
}
