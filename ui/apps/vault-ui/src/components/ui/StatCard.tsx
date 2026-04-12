import { LucideIcon } from 'lucide-react'
import { Card, CardBody } from './Card'

interface StatCardProps {
  label: string
  value: string | number
  icon: LucideIcon
  color?: string
  trend?: string
}

export function StatCard({
  label,
  value,
  icon: Icon,
  color = 'text-primary-600 bg-primary-50 dark:bg-primary-900/20 dark:text-primary-400',
  trend,
}: StatCardProps) {
  return (
    <Card>
      <CardBody className="flex items-center gap-4">
        <div
          className={`w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0 ${color}`}
        >
          <Icon className="w-6 h-6" />
        </div>
        <div className="min-w-0">
          <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
          <p className="text-2xl font-bold text-slate-900 dark:text-white">{value}</p>
          {trend && <p className="text-xs text-accent-600 mt-0.5">{trend}</p>}
        </div>
      </CardBody>
    </Card>
  )
}
