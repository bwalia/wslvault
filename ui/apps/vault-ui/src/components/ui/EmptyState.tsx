import { LucideIcon, Inbox } from 'lucide-react'
import { cn } from '@/lib/utils'

interface EmptyStateProps {
  icon?: LucideIcon
  title?: string
  description?: string
  action?: React.ReactNode
  className?: string
}

/**
 * What a page shows before it has anything in it.
 *
 * Treated as a first-run experience rather than an error, because for a new
 * tenant it is literally the first thing they see on most pages. The old
 * version said "Nothing here yet" in small grey text, which tells someone that
 * the page is empty — something they can already see — and nothing about what
 * to do next.
 *
 * So: an empty compartment drawn with the vault's own vocabulary, a title in
 * the display face, and room for a real sentence and an action. The dashed
 * ring is brass at low opacity — the compartment is there and waiting, not
 * broken.
 */
export function EmptyState({
  icon: Icon = Inbox,
  title = 'Nothing here yet',
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-16 px-4', className)}>
      <div className="relative mb-5">
        {/* Outer ring: the compartment wall. */}
        <div
          aria-hidden="true"
          className="absolute -inset-3 rounded-2xl border border-dashed border-brass/25"
        />
        <div className="relative w-14 h-14 rounded-xl bg-surface-2 border border-line-strong flex items-center justify-center">
          <Icon className="w-6 h-6 text-ink-faint" aria-hidden="true" />
        </div>
      </div>

      <p className="font-display text-base font-semibold text-ink">{title}</p>
      {description && (
        <p className="text-sm text-ink-muted mt-1.5 text-center max-w-sm leading-relaxed">
          {description}
        </p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}
