import { cn } from '@/lib/utils'
import { HTMLAttributes } from 'react'

/**
 * A compartment in the vault.
 *
 * The inset top highlight is what does the work: a one-pixel lighter line along
 * the upper edge reads as a bevelled metal panel catching light, which is the
 * whole difference between "a box" and "a door in a vault". It costs one
 * box-shadow and no image.
 */
function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'bg-surface rounded-xl border border-line',
        'shadow-[inset_0_1px_0_0_rgb(255_255_255/0.6)] dark:shadow-[inset_0_1px_0_0_rgb(255_255_255/0.04)]',
        className,
      )}
      {...props}
    />
  )
}

function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('px-5 py-3.5 border-b border-line flex items-center justify-between gap-3', className)}
      {...props}
    />
  )
}

/** Standard heading inside CardHeader. */
function CardTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h2
      className={cn('font-display text-sm font-semibold tracking-tight text-ink', className)}
      {...props}
    />
  )
}

function CardBody({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-5 py-4', className)} {...props} />
}

function CardFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('px-5 py-3.5 border-t border-line bg-surface-2 rounded-b-xl', className)}
      {...props}
    />
  )
}

export { Card, CardHeader, CardTitle, CardBody, CardFooter }
