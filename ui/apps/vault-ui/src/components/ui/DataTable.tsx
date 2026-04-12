'use client'
import { useState, useMemo, useEffect, ReactNode } from 'react'
import { ChevronUp, ChevronDown, Search, ChevronLeft, ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { TableSkeleton } from './Skeleton'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface Column<T = any> {
  field: string
  label: string
  sortable?: boolean
  render?: (row: T) => ReactNode
}

interface DataTableProps<T extends Record<string, unknown>> {
  // Accept Column<any> to allow strongly-typed column definitions from pages
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  columns: Column<any>[]
  data?: T[]
  loading?: boolean
  onRowClick?: (row: T) => void
  keyField?: string
  emptyMessage?: string
}

const PAGE_SIZES = [10, 25, 50]

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data = [],
  loading = false,
  onRowClick,
  keyField = 'id',
  emptyMessage = 'No records found',
}: DataTableProps<T>) {
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [sortField, setSortField] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(PAGE_SIZES[0])

  // Debounce search input by 300ms to avoid filtering on every keystroke
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 300)
    return () => clearTimeout(timer)
  }, [search])

  // Reset to first page whenever search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const filtered = useMemo(() => {
    if (!debouncedSearch) return data
    const q = debouncedSearch.toLowerCase()
    return data.filter(row =>
      Object.values(row).some(v => String(v ?? '').toLowerCase().includes(q)),
    )
  }, [data, debouncedSearch])

  const sorted = useMemo(() => {
    if (!sortField) return filtered
    return [...filtered].sort((a, b) => {
      const av = String(a[sortField] ?? '')
      const bv = String(b[sortField] ?? '')
      const cmp = av.localeCompare(bv, undefined, { numeric: true })
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [filtered, sortField, sortDir])

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize))
  const currentPage = Math.min(page, totalPages)
  const paginated = sorted.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  return (
    <div className="flex flex-col gap-3">
      {/* Search + page size */}
      <div className="flex items-center justify-between gap-3">
        <div className="relative flex-1 max-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="search"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search…"
            className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary-500/50 focus:border-primary-500"
          />
        </div>
        <select
          value={pageSize}
          onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
          className="px-2 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
        >
          {PAGE_SIZES.map(s => (
            <option key={s} value={s}>{s} per page</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 dark:bg-slate-800/50">
            <tr>
              {columns.map(col => (
                <th
                  key={col.field}
                  className={cn(
                    'px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400',
                    col.sortable && 'cursor-pointer select-none hover:text-slate-700 dark:hover:text-slate-200',
                  )}
                  onClick={() => col.sortable && handleSort(col.field)}
                >
                  <span className="inline-flex items-center gap-1">
                    {col.label}
                    {col.sortable && (
                      <span className="flex flex-col">
                        <ChevronUp
                          className={cn(
                            'w-3 h-3 -mb-1',
                            sortField === col.field && sortDir === 'asc'
                              ? 'text-primary-600'
                              : 'text-slate-300 dark:text-slate-600',
                          )}
                        />
                        <ChevronDown
                          className={cn(
                            'w-3 h-3',
                            sortField === col.field && sortDir === 'desc'
                              ? 'text-primary-600'
                              : 'text-slate-300 dark:text-slate-600',
                          )}
                        />
                      </span>
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-slate-900 divide-y divide-slate-100 dark:divide-slate-800/50">
            {loading ? (
              <TableSkeleton rows={10} cols={columns.length} />
            ) : paginated.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-6 py-12 text-center text-sm text-slate-400 dark:text-slate-500"
                >
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              paginated.map((row, i) => (
                <tr
                  key={String(row[keyField] ?? i)}
                  onClick={() => onRowClick?.(row)}
                  className={cn(
                    'transition-colors',
                    onRowClick && 'cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/30',
                  )}
                >
                  {columns.map(col => (
                    <td
                      key={col.field}
                      className="px-6 py-3 text-slate-700 dark:text-slate-300"
                    >
                      {col.render ? col.render(row) : String(row[col.field] ?? '—')}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {!loading && sorted.length > 0 && (
        <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
          <span>
            {sorted.length === 0
              ? 'No records'
              : `${(currentPage - 1) * pageSize + 1}–${Math.min(currentPage * pageSize, sorted.length)} of ${sorted.length}`}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1.5 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const p = Math.max(1, Math.min(totalPages - 4, currentPage - 2)) + i
              return (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  className={cn(
                    'w-7 h-7 rounded-md text-xs font-medium transition-colors',
                    p === currentPage
                      ? 'bg-primary-600 text-white'
                      : 'hover:bg-slate-100 dark:hover:bg-slate-800',
                  )}
                >
                  {p}
                </button>
              )
            })}
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1.5 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
