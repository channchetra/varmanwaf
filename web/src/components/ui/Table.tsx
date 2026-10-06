import { useMemo, useState, type ReactNode } from 'react'
import { CaretUp, CaretDown, CaretLeft, CaretRight } from '@phosphor-icons/react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import { Button } from './Button'

export interface Column<T> {
  key: string
  header: ReactNode
  /** Raw value used for sorting. */
  accessor?: (row: T) => string | number | null | undefined
  /** Custom cell renderer. */
  cell?: (row: T, index: number) => ReactNode
  sortable?: boolean
  align?: 'left' | 'right' | 'center'
  width?: string
  className?: string
}

export interface TableProps<T> {
  columns: Column<T>[]
  data: T[]
  rowKey: (row: T, index: number) => string
  loading?: boolean
  empty?: ReactNode
  onRowClick?: (row: T) => void
  /** Client-side pagination. Set to 0/undefined to disable. */
  pageSize?: number
  className?: string
  dense?: boolean
}

type SortDir = 'asc' | 'desc'

const alignClass = {
  left: 'text-left',
  right: 'text-right',
  center: 'text-center',
} as const

export function Table<T>({
  columns,
  data,
  rowKey,
  loading = false,
  empty,
  onRowClick,
  pageSize = 0,
  className,
  dense = false,
}: TableProps<T>) {
  const { t } = useTranslation()
  const [sort, setSort] = useState<{ key: string; dir: SortDir } | null>(null)
  const [page, setPage] = useState(0)

  const sorted = useMemo(() => {
    if (!sort) return data
    const col = columns.find((c) => c.key === sort.key)
    if (!col?.accessor) return data
    const copy = [...data]
    copy.sort((a, b) => {
      const av = col.accessor?.(a)
      const bv = col.accessor?.(b)
      if (av == null && bv == null) return 0
      if (av == null) return 1
      if (bv == null) return -1
      if (typeof av === 'number' && typeof bv === 'number') {
        return sort.dir === 'asc' ? av - bv : bv - av
      }
      const as = String(av)
      const bs = String(bv)
      return sort.dir === 'asc' ? as.localeCompare(bs) : bs.localeCompare(as)
    })
    return copy
  }, [data, sort, columns])

  const pageCount = pageSize > 0 ? Math.max(1, Math.ceil(sorted.length / pageSize)) : 1
  const safePage = Math.min(page, pageCount - 1)
  const pageData =
    pageSize > 0 ? sorted.slice(safePage * pageSize, safePage * pageSize + pageSize) : sorted

  const toggleSort = (col: Column<T>) => {
    if (!col.sortable) return
    setSort((prev) => {
      if (prev?.key !== col.key) return { key: col.key, dir: 'asc' }
      if (prev.dir === 'asc') return { key: col.key, dir: 'desc' }
      return null
    })
    setPage(0)
  }

  const cellPad = dense ? 'px-3 py-2' : 'px-4 py-3'

  return (
    <div className={cn('w-full', className)}>
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="bg-recessed">
              {columns.map((col) => {
                const active = sort?.key === col.key
                return (
                  <th
                    key={col.key}
                    style={col.width ? { width: col.width } : undefined}
                    scope="col"
                    className={cn(
                      cellPad,
                      'border-b border-line text-xs font-semibold tracking-wide text-fg-subtle uppercase',
                      alignClass[col.align ?? 'left'],
                      col.sortable && 'cursor-pointer select-none hover:text-fg',
                    )}
                    onClick={() => toggleSort(col)}
                  >
                    <span
                      className={cn(
                        'inline-flex items-center gap-1',
                        col.align === 'right' && 'flex-row-reverse',
                      )}
                    >
                      {col.header}
                      {col.sortable && (
                        <span className="inline-flex flex-col leading-none">
                          <CaretUp
                            weight="bold"
                            className={cn(
                              'h-2.5 w-2.5 -mb-0.5',
                              active && sort?.dir === 'asc' ? 'text-brand' : 'text-fg-subtle/40',
                            )}
                          />
                          <CaretDown
                            weight="bold"
                            className={cn(
                              'h-2.5 w-2.5',
                              active && sort?.dir === 'desc' ? 'text-brand' : 'text-fg-subtle/40',
                            )}
                          />
                        </span>
                      )}
                    </span>
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={columns.length} className={cn(cellPad, 'text-center')}>
                  <div className="flex items-center justify-center gap-2 py-8 text-fg-subtle">
                    <span className="h-4 w-4 animate-spin-slow rounded-full border-2 border-current border-t-transparent" />
                    <span className="text-sm">{t('common.loading')}</span>
                  </div>
                </td>
              </tr>
            ) : pageData.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className={cellPad}>
                  {empty ?? (
                    <div className="py-10 text-center text-sm text-fg-subtle">{t('common.noData')}</div>
                  )}
                </td>
              </tr>
            ) : (
              pageData.map((row, i) => (
                <tr
                  key={rowKey(row, i)}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={cn(
                    'border-b border-line last:border-0 transition-colors',
                    onRowClick && 'cursor-pointer hover:bg-recessed',
                  )}
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      className={cn(
                        cellPad,
                        'text-fg align-middle',
                        alignClass[col.align ?? 'left'],
                        col.className,
                      )}
                    >
                      {col.cell
                        ? col.cell(row, i)
                        : col.accessor
                          ? String(col.accessor(row) ?? '')
                          : null}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {pageSize > 0 && sorted.length > 0 && (
        <div className="mt-3 flex items-center justify-between text-[13px] text-fg-subtle">
          <span>
            {t('pagination.showing', {
              from: safePage * pageSize + 1,
              to: Math.min(sorted.length, (safePage + 1) * pageSize),
              total: sorted.length,
            })}
          </span>
          <div className="flex items-center gap-1">
            <Button
              size="icon"
              variant="ghost"
              aria-label={t('pagination.previous')}
              disabled={safePage === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              icon={<CaretLeft weight="bold" className="h-4 w-4" />}
            />
            <span className="px-2 tabular-nums">
              {safePage + 1} / {pageCount}
            </span>
            <Button
              size="icon"
              variant="ghost"
              aria-label={t('pagination.next')}
              disabled={safePage >= pageCount - 1}
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              icon={<CaretRight weight="bold" className="h-4 w-4" />}
            />
          </div>
        </div>
      )}
    </div>
  )
}
