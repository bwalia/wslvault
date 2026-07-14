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
  /** Right-align (numeric columns). */
  align?: 'left' | 'right'
  /** Render cell content in monospace (identifiers, paths, durations). */
  mono?: boolean
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
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-faint" />
          <input
            type="search"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter rows…"
            aria-label="Filter table rows"
            className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border border-line-strong bg-surface text-ink placeholder:text-ink-faint focus:outline-none focus:ring-2 focus:ring-primary-500/40 focus:border-primary-500"
          />
        </div>
        <select
          value={pageSize}
          onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
          aria-label="Rows per page"
          className="px-2 py-2 text-sm rounded-lg border border-line-strong bg-surface text-ink-muted focus:outline-none focus:ring-2 focus:ring-primary-500/40"
        >
          {PAGE_SIZES.map(s => (
            <option key={s} value={s}>{s} per page</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-line overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-surface-2">
            <tr>
              {columns.map(col => (
                <th
                  key={col.field}
                  aria-sort={
                    sortField === col.field
                      ? sortDir === 'asc' ? 'ascending' : 'descending'
                      : undefined
                  }
                  className={cn(
                    'px-4 py-2.5 text-xs font-medium uppercase tracking-wide text-ink-faint',
                    col.align === 'right' ? 'text-right' : 'text-left',
                    col.sortable && 'cursor-pointer select-none hover:text-ink',
                  )}
                  onClick={() => col.sortable && handleSort(col.field)}
                >
                  <span className={cn('inline-flex items-center gap-1', col.align === 'right' && 'flex-row-reverse')}>
                    {col.label}
                    {col.sortable && (
                      sortField === col.field ? (
                        sortDir === 'asc'
                          ? <ChevronUp className="w-3.5 h-3.5 text-primary-600" />
                          : <ChevronDown className="w-3.5 h-3.5 text-primary-600" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5 text-line-strong" />
                      )
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="bg-surface divide-y divide-line">
            {loading ? (
              <TableSkeleton rows={10} cols={columns.length} />
            ) : paginated.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-12 text-center text-sm text-ink-faint"
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
                    onRowClick && 'cursor-pointer hover:bg-surface-2',
                  )}
                >
                  {columns.map(col => (
                    <td
                      key={col.field}
                      className={cn(
                        'px-4 py-2.5 text-ink',
                        col.align === 'right' && 'text-right tabular',
                        col.mono && 'font-mono text-[13px]',
                      )}
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
        <div className="flex items-center justify-between text-xs text-ink-muted">
          <span className="tabular">
            {`${(currentPage - 1) * pageSize + 1}–${Math.min(currentPage * pageSize, sorted.length)} of ${sorted.length}`}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              aria-label="Previous page"
              className="p-1.5 rounded-md hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed focus-ring"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const p = Math.max(1, Math.min(totalPages - 4, currentPage - 2)) + i
              return (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  aria-label={`Page ${p}`}
                  aria-current={p === currentPage ? 'page' : undefined}
                  className={cn(
                    'w-7 h-7 rounded-md text-xs font-medium transition-colors tabular focus-ring',
                    p === currentPage
                      ? 'bg-primary-600 text-white'
                      : 'hover:bg-surface-2 text-ink-muted',
                  )}
                >
                  {p}
                </button>
              )
            })}
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              aria-label="Next page"
              className="p-1.5 rounded-md hover:bg-surface-2 disabled:opacity-40 disabled:cursor-not-allowed focus-ring"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
