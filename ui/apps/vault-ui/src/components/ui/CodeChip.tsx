'use client'
import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { cn } from '@/lib/utils'

interface CodeChipProps {
  value: string
  /** Truncate display to this many chars (full value still copied). */
  truncate?: number
  copyable?: boolean
  className?: string
}

/**
 * Inline monospace identifier — secret paths, tenant IDs, key IDs, tokens.
 * The one-glance rule: if it's machine-issued, it wears mono.
 */
export function CodeChip({ value, truncate, copyable = false, className }: CodeChipProps) {
  const [copied, setCopied] = useState(false)
  const [failed, setFailed] = useState(false)

  const display =
    truncate && value.length > truncate ? `${value.slice(0, truncate)}…` : value

  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    // clipboard.writeText rejects on an insecure origin (plain HTTP, which the
    // dev gateway serves) or a denied permission. Unhandled it was an invisible
    // promise rejection: the icon never changed and the user assumed the click
    // missed. Reflect the failure in the control itself.
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setFailed(false)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setFailed(true)
      setTimeout(() => setFailed(false), 2500)
    }
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 font-mono text-sm text-ink bg-surface-2 border border-line rounded px-1.5 py-0.5',
        className,
      )}
      title={truncate ? value : undefined}
    >
      {display}
      {copyable && (
        <button
          onClick={copy}
          className={cn(
            'transition-colors focus-ring rounded',
            failed ? 'text-danger-600' : 'text-ink-faint hover:text-ink',
          )}
          aria-label={
            failed ? 'Copy failed — select the text manually' : copied ? 'Copied' : `Copy ${value}`
          }
          title={failed ? 'Copy failed — select the text manually' : undefined}
        >
          {copied ? <Check className="w-3 h-3 text-success-600" /> : <Copy className="w-3 h-3" />}
        </button>
      )}
    </span>
  )
}
