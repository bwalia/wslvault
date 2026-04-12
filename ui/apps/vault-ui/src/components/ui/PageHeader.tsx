import { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface PageHeaderProps {
  title: string
  description?: string
  icon?: LucideIcon
  iconColor?: string
  actions?: React.ReactNode
}

export function PageHeader({
  title,
  description,
  icon: Icon,
  iconColor = 'bg-primary-100 text-primary-600 dark:bg-primary-900/20 dark:text-primary-400',
  actions,
}: PageHeaderProps) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div className="flex items-center gap-4">
        {Icon && (
          <div className={cn('w-10 h-10 rounded-lg flex items-center justify-center', iconColor)}>
            <Icon className="w-5 h-5" />
          </div>
        )}
        <div>
          <h1 className="text-xl font-semibold text-slate-900 dark:text-white">{title}</h1>
          {description && (
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">{description}</p>
          )}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}
