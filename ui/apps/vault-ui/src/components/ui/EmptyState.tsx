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
  title = 'No data',
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-16 px-4', className)}>
      {Icon && (
        <div className="w-12 h-12 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4">
          <Icon className="w-6 h-6 text-slate-400 dark:text-slate-500" />
        </div>
      )}
      <p className="text-sm font-medium text-slate-700 dark:text-slate-300">{title}</p>
      {description && (
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-1 text-center max-w-sm">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
