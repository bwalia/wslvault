import { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface EmptyStateProps {
  icon?: LucideIcon
  title?: string
  description?: string
  action?: React.ReactNode
  className?: string
}

export function EmptyState({
  icon: Icon,
  title = 'Nothing here yet',
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-16 px-4', className)}>
      {Icon && (
        <div className="w-11 h-11 rounded-lg border border-dashed border-line-strong flex items-center justify-center mb-4">
          <Icon className="w-5 h-5 text-ink-faint" aria-hidden="true" />
        </div>
      )}
      <p className="text-sm font-medium text-ink">{title}</p>
      {description && (
        <p className="text-xs text-ink-muted mt-1 text-center max-w-sm leading-relaxed">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
