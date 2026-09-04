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

/**
 * Every size is a step taller than it was.
 *
 * `md` was 36px and `sm` 32px, both under the 44px a finger actually needs and
 * both reading as chips rather than controls. `lg` now hits 44 outright; the
 * smaller two stay compact for table rows but no longer look like labels.
 */
const sizes = {
  sm: 'px-3 text-xs h-9',
  md: 'px-4 text-sm h-10',
  lg: 'px-5 text-[0.9375rem] h-11',
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
        // Disabled drops out of the variant's colour entirely rather than
        // fading it. A brass button at 50% opacity is still a mid-yellow
        // button — it reads as pressable and simply looks poorly printed,
        // which is how the disabled "Create secret" was landing.
        disabled || loading
          ? 'bg-surface-2 text-ink-faint border border-line cursor-not-allowed shadow-none'
          : variants[variant],
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
