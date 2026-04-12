import { cn } from '@/lib/utils'

const variants = {
  default: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
  info: 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300',
  success: 'bg-accent-50 text-accent-700 dark:bg-accent-900/20 dark:text-accent-600',
  warning: 'bg-warn-50 text-warn-700 dark:bg-warn-900/20 dark:text-warn-500',
  danger: 'bg-danger-50 text-danger-700 dark:bg-danger-900/20 dark:text-danger-400',
  outline: 'border border-current',
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
        'inline-flex items-center rounded-md font-medium',
        size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-1 text-xs',
        variants[variant],
        className,
      )}
    >
      {children}
    </span>
  )
}
