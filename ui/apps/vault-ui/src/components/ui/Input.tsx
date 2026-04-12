import { cn } from '@/lib/utils'
import { InputHTMLAttributes, forwardRef } from 'react'

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  error?: string
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, className, id, ...props }, ref) => {
    const inputId = id ?? label?.toLowerCase().replace(/\s+/g, '-')
    return (
      <div className="space-y-1.5">
        {label && (
          <label
            htmlFor={inputId}
            className="block text-sm font-medium text-slate-700 dark:text-slate-300"
          >
            {label}
          </label>
        )}
        <input
          ref={ref}
          id={inputId}
          className={cn(
            'w-full px-3 py-2 rounded-lg border bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 text-sm',
            'placeholder:text-slate-400 transition-colors',
            error
              ? 'border-danger-500 focus:ring-danger-500/50 focus:border-danger-500'
              : 'border-slate-200 dark:border-slate-700 focus:border-primary-500',
            'focus:outline-none focus:ring-2 focus:ring-primary-500/50',
            className,
          )}
          {...props}
        />
        {error && <p className="text-xs text-danger-600 dark:text-danger-400">{error}</p>}
      </div>
    )
  },
)
Input.displayName = 'Input'
