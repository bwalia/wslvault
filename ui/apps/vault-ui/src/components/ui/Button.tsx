import { Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ButtonHTMLAttributes, forwardRef } from 'react'

/**
 * Brass is the action colour, navy is the structure.
 *
 * The two halves of the sign-in screen disagreed before this: a brass vault on
 * the left, a navy button on the right, so the thing you were meant to press
 * was the one element not wearing the product's colour.
 *
 * Dark text on brass rather than white — white on #c9a227 is about 2.3:1 and
 * fails outright, while steel on brass is ~8:1. It also happens to be how
 * brass hardware actually looks: dark engraving on a warm plate.
 */
const variants = {
  primary:
    'bg-brass hover:bg-brass/90 active:bg-brass-dim text-steel font-semibold shadow-sm shadow-brass/20',
  secondary:
    'bg-surface border border-line-strong text-ink hover:bg-surface-2 active:bg-surface-3',
  danger: 'bg-danger-600 hover:bg-danger-700 text-white',
  ghost: 'text-ink-muted hover:bg-surface-2 hover:text-ink',
}

const sizes = {
  sm: 'px-3 text-xs h-8',
  md: 'px-4 text-sm h-9',
  lg: 'px-5 text-sm h-10',
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variants
  size?: keyof typeof sizes
  loading?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', loading, disabled, className, children, ...props }, ref) => (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={cn(
        'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors focus-ring',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    >
      {loading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
      {children}
    </button>
  ),
)
Button.displayName = 'Button'
