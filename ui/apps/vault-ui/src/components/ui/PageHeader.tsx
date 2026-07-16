import { LucideIcon } from 'lucide-react'

interface PageHeaderProps {
  title: string
  description?: string
  /** Deprecated — headers are typographic now; icon is ignored. Kept so
      existing call sites compile until they're cleaned up. */
  icon?: LucideIcon
  iconColor?: string
  actions?: React.ReactNode
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="flex items-end justify-between gap-4 mb-6">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{title}</h1>
        {description && <p className="text-sm text-ink-muted mt-1">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </div>
  )
}
