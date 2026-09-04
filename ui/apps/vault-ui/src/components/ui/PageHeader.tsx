'use client'

import { useState } from 'react'
import { LucideIcon, HelpCircle, ChevronDown } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '@/lib/utils'

interface PageHeaderProps {
  title: string
  description?: string
  /** Deprecated — headers are typographic; icon is ignored. Kept so existing
      call sites compile until they are cleaned up. */
  icon?: LucideIcon
  iconColor?: string
  actions?: React.ReactNode
  /**
   * Plain-language explanation of what this page is for.
   *
   * Collapsed by default and opened by a single control. Two audiences use
   * this console and they want opposite things: an operator who works here
   * daily is slowed down by a paragraph they have read a hundred times, and
   * someone sent a link by their administrator is stranded without one.
   * Progressive disclosure serves both — the answer is one click away and
   * nobody has to scroll past it.
   *
   * Write it for the second audience. Say what the page is for and what the
   * reader can do here, in the words they would use, not the system's.
   */
  guide?: React.ReactNode
}

export function PageHeader({ title, description, actions, guide }: PageHeaderProps) {
  const [open, setOpen] = useState(false)

  return (
    <div className="mb-7">
      <div className="flex items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {/* Display face and a step up in size: on a page of dense tables the
                title is the only thing establishing where you are. */}
            <h1 className="font-display text-[1.6rem] leading-tight font-semibold tracking-tight text-ink">
              {title}
            </h1>
            {guide && (
              <button
                type="button"
                onClick={() => setOpen(o => !o)}
                aria-expanded={open}
                className={cn(
                  'inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium transition-colors focus-ring',
                  open
                    ? 'bg-brass/15 text-brass-dim dark:text-brass'
                    : 'text-ink-faint hover:bg-surface-2 hover:text-ink-muted',
                )}
              >
                <HelpCircle className="w-3.5 h-3.5" aria-hidden="true" />
                {open ? 'Hide' : 'What is this?'}
                <ChevronDown
                  className={cn('w-3 h-3 transition-transform duration-200', open && 'rotate-180')}
                  aria-hidden="true"
                />
              </button>
            )}
          </div>
          {description && (
            <p className="text-sm text-ink-muted mt-1.5 max-w-2xl leading-relaxed">
              {description}
            </p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
      </div>

      <AnimatePresence initial={false}>
        {guide && open && (
          <motion.div
            // Height is animated here rather than transformed, which the motion
            // guidance normally forbids. It is the one case that has no
            // alternative: the panel's height is unknown until it renders, and
            // a scale would distort the text inside it. Confined to a single
            // element, so the layout cost stays bounded.
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <div className="mt-4 rounded-xl border border-brass/25 bg-brass/[0.06] px-4 py-3.5">
              <div className="text-[13px] leading-relaxed text-ink-muted [&_strong]:text-ink [&_strong]:font-medium space-y-2">
                {guide}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* A hairline under the header. Separates chrome from content without
          spending a full border on it. */}
      <div className="mt-5 h-px bg-gradient-to-r from-line via-line to-transparent" />
    </div>
  )
}
