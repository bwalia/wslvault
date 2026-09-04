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
    <div
      className={cn(
        'group relative bg-surface rounded-xl border border-line px-5 pt-4 pb-4 overflow-hidden',
        'shadow-[inset_0_1px_0_0_rgb(255_255_255/0.6)] dark:shadow-[inset_0_1px_0_0_rgb(255_255_255/0.04)]',
        'transition-colors duration-200 hover:border-brass/40',
      )}
    >
      {/* Brass rule along the top edge. These tiles are the first thing on the
          dashboard, so they carry the accent; deeper cards stay quiet. */}
      <div
        className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-brass/70 via-brass/30 to-transparent"
        aria-hidden="true"
      />
      <p className="text-xs font-medium uppercase tracking-[0.08em] text-ink-muted">
        {label}
      </p>
      {/* tabular-nums so a figure changing from 9 to 10 does not shift the
          layout of every tile beside it. */}
      <p className="mt-2 font-display text-[2.25rem] leading-none font-semibold tracking-tight text-ink tabular-nums">
        {value}
      </p>
      {(trend || detail) && (
        <p className="mt-2 text-xs text-ink-muted font-mono">{trend ?? detail}</p>
      )}
    </div>
  )
}
