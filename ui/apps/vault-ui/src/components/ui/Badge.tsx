import { cn } from '@/lib/utils'

const variants = {
  default: 'bg-surface-2 text-ink-muted border-line',
  info: 'bg-primary-50 text-primary-700 border-primary-200 dark:bg-primary-950 dark:text-primary-300 dark:border-primary-800',
  success:
    'bg-success-50 text-success-700 border-success-100 dark:bg-success-700/15 dark:text-success-500 dark:border-success-700/30',
  warning:
    'bg-warn-50 text-warn-700 border-warn-100 dark:bg-warn-600/15 dark:text-warn-500 dark:border-warn-600/30',
  danger:
    'bg-danger-50 text-danger-700 border-danger-100 dark:bg-danger-600/15 dark:text-danger-400 dark:border-danger-600/30',
  outline: 'border-line-strong text-ink-muted',
}

interface BadgeProps {
  variant?: keyof typeof variants
  size?: 'sm' | 'md'
  className?: string
  children: React.ReactNode
}

export function Badge({ variant = 'default', size = 'md', className, children }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border font-medium',
        size === 'sm' ? 'px-1.5 py-px text-xs' : 'px-2 py-0.5 text-xs',
        variants[variant],
        className,
      )}
    >
      {children}
    </span>
  )
}
