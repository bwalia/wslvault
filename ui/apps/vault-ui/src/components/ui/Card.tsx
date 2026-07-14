import { cn } from '@/lib/utils'
import { HTMLAttributes } from 'react'

function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('bg-surface rounded-xl border border-line', className)}
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
  return <h2 className={cn('text-sm font-semibold text-ink', className)} {...props} />
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
