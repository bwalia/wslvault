import { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface StatCardProps {
  label: string
  value: string | number
  /** Deprecated — stat tiles are typographic now; icon is ignored. */
  icon?: LucideIcon
  color?: string
  trend?: string
  /** Small mono annotation under the value (e.g. "across 3 regions"). */
  detail?: string
}

/**
 * Typographic stat tile: the number IS the design. No icon-in-a-box.
 * A hairline primary rule at the top anchors the tile to the brand.
 */
export function StatCard({ label, value, trend, detail }: StatCardProps) {
  return (
    <div className="relative bg-surface rounded-xl border border-line px-5 pt-4 pb-4 overflow-hidden">
      <div className="absolute top-0 left-5 right-5 h-px bg-primary-500/60" aria-hidden="true" />
      <p className="text-xs font-medium uppercase tracking-wide text-ink-faint">{label}</p>
      <p className={cn('mt-1.5 text-3xl font-semibold tracking-tight text-ink tabular')}>
        {value}
      </p>
      {(trend || detail) && (
        <p className="mt-1 text-xs text-ink-muted font-mono">{trend ?? detail}</p>
      )}
    </div>
  )
}
