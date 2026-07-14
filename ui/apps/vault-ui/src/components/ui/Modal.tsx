'use client'
import { useEffect, useRef, ReactNode } from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'

interface ModalProps {
  open: boolean
  onClose(): void
  title: string
  children: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl'
  footer?: ReactNode
}

const sizeClasses = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
  xl: 'max-w-2xl',
}

export function Modal({ open, onClose, title, children, size = 'md', footer }: ModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null)

  // Close on Escape; move focus into the dialog on open.
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handler)
    dialogRef.current?.focus()
    return () => document.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden="true" />
      {/* Dialog — overlays are the only surfaces that carry shadow */}
      <div
        ref={dialogRef}
        tabIndex={-1}
        className={cn(
          'relative w-full bg-surface rounded-xl shadow-2xl border border-line outline-none',
          sizeClasses[size],
        )}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-line">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-ink-faint hover:text-ink hover:bg-surface-2 transition-colors focus-ring"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="px-5 py-4 max-h-[70vh] overflow-y-auto">{children}</div>
        {footer && (
          <div className="flex items-center justify-end gap-2 px-5 py-3.5 border-t border-line bg-surface-2 rounded-b-xl">
            {footer}
          </div>
        )}
      </div>
    </div>
  )
}
